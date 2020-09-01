package ipc

import (
	"errors"
	"fmt"
	linuxproc "github.com/c9s/goprocinfo/linux"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/olekukonko/tablewriter"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	image   = "syzkaller-image"
	timeout = 5 * time.Second
	//TODO change name and consider re-adding --rm when this is done
	dockerArgString = "run -a stdin -a stdout -a stderr -i --runtime=runsc --cap-add=ALL"
)

// make a command that invokes the executor directly without using the wrapper
func MakeExecutorCommand(bin []string) *exec.Cmd {
	dockerArgs := strings.Split(dockerArgString, " ")

	//change entrypoint to executor, append image, then remaining args
	dockerArgs = append(dockerArgs, "--entrypoint")
	dockerArgs = append(dockerArgs, bin[0], image)
	dockerArgs = append(dockerArgs, bin[1:]...)

	return osutil.Command("docker", dockerArgs...)
}

func MakeBootstrapCommand(bin []string, count int, stopTimestamp int64, cores string, usage float32) (*exec.Cmd, error) {
	dockerArgs := strings.Split(dockerArgString, " ")

	//add core restriction
	if cores != "" {
		dockerArgs = append(dockerArgs, fmt.Sprintf("--cpuset-cpus=%s", cores))
	}

	//add usage restriction
	if usage > 0 {
		dockerArgs = append(dockerArgs, fmt.Sprintf("--cpus=%f", usage))
	}

	//add image
	dockerArgs = append(dockerArgs, image)

	//bootstrap commands
	dockerArgs = append(dockerArgs, fmt.Sprintf("-executor=%s", bin[0]))

	if len(bin) > 1 {
		dockerArgs = append(dockerArgs, fmt.Sprintf("-executorArgs=%s", strings.Join(bin[1:], " ")))
	}

	if count > 0 {
		dockerArgs = append(dockerArgs, fmt.Sprintf("-count=%d", count))
	} else if stopTimestamp > 0 {
		dockerArgs = append(dockerArgs, fmt.Sprintf("-stop=%d", stopTimestamp))
	} else {
		return nil, errors.New("neither count nor stop given as nonzero!")
	}

	return osutil.Command("docker", dockerArgs...), nil
}

type ContainerRestrictions struct {
	Cores string
	Usage float32
}

// wraps the standard executor command in a docker command line
// this can only be called from a fuzzer that is _not_ running in a container, or at least has access to the docker CLI
func makeContainerCommand(pid int, bin []string, config *Config, inFile, outFile *os.File, outmem []byte,
	tmpDirPath string, r ContainerRestrictions) (*command, error) {

	if inFile != nil || outFile != nil {
		return nil, errors.New("containerized commands do not support passing additional file descriptors")
	}

	c := &command{
		pid:     pid,
		config:  config,
		timeout: sanitizeTimeout(config),
		dir:     "",
		outmem:  outmem,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	//TODO timeout should be passed from a higher level function and put into command struct
	stopTimestamp := time.Now().Add(c.timeout).Unix()

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wp.Close()

	// executor->ipc command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// ipc->executor command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)
	c.exited = make(chan struct{})

	cmd, err := MakeBootstrapCommand(bin, 0, stopTimestamp, r.Cores, r.Usage)
	if err != nil {
		return nil, fmt.Errorf("could not make bootstrap command: %v", err)
	}
	cmd.Stdin = outrp
	cmd.Stdout = inwp

	if config.Flags&FlagDebug != 0 {
		close(c.readDone)
		cmd.Stderr = os.Stdout
	} else {
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const bufSize = 128 << 10
			output := make([]byte, bufSize)
			var size uint64
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += uint64(n)
					if size >= bufSize*3/4 {
						copy(output, output[size-bufSize/2:size])
						size = bufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.cmd = cmd
	wp.Close()
	// Note: we explicitly close inwp before calling handshake even though we defer it above.
	// If we don't do it and executor exits before writing handshake reply,
	// reading from inrp will hang since we hold another end of the pipe open.
	inwp.Close()

	if c.config.UseForkServer {
		if err := c.handshake(); err != nil {
			log.Logf(1, "Handshake error on PID %d: %v", c.pid, err)
			return nil, err
		}
	}
	tmp := c
	c = nil // disable defer above
	return tmp, nil

}

type CPUReport struct {
	all  linuxproc.CPUStat
	cpus []linuxproc.CPUStat
}

func GetCPUReport() (*CPUReport, error) {
	stat, err := linuxproc.ReadStat("/proc/stat")
	if err != nil {
		return nil, fmt.Errorf("stat read failure")
	}
	report := &CPUReport{
		stat.CPUStatAll,
		stat.CPUStats,
	}
	return report, nil
}

func measureCore(b linuxproc.CPUStat, a linuxproc.CPUStat) (*linuxproc.CPUStat, uint64, error) {
	if b.Id != a.Id {
		return nil, 0, fmt.Errorf("tried to compare 2 different cores!")
	}
	beforeSum := b.User + b.Nice + b.System + b.Idle + b.IOWait + b.IRQ + b.SoftIRQ + b.Steal + b.Guest + b.GuestNice
	afterSum := a.User + a.Nice + a.System + a.Idle + a.IOWait + a.IRQ + a.SoftIRQ + a.Steal + a.Guest + a.GuestNice
	return &linuxproc.CPUStat{
		Id:        b.Id,
		User:      a.User - b.User,
		Nice:      a.Nice - b.Nice,
		System:    a.System - b.System,
		Idle:      a.Idle - b.Idle,
		IOWait:    a.IOWait - b.IOWait,
		IRQ:       a.IRQ - b.IRQ,
		SoftIRQ:   a.SoftIRQ - b.SoftIRQ,
		Steal:     a.Steal - b.Steal,
		Guest:     a.Guest - b.Guest,
		GuestNice: a.GuestNice - b.GuestNice,
	}, afterSum - beforeSum, nil
}

func convertToString(report linuxproc.CPUStat, total uint64) []string {
	return []string{
		report.Id,
		strconv.FormatUint(total-report.Idle, 10),
		strconv.FormatUint(total, 10),
		fmt.Sprintf("%0.2f", 100*float64(total-report.Idle)/float64(total)),
		strconv.FormatUint(report.User, 10),
		strconv.FormatUint(report.Nice, 10),
		strconv.FormatUint(report.System, 10),
		strconv.FormatUint(report.Idle, 10),
		strconv.FormatUint(report.IOWait, 10),
		strconv.FormatUint(report.IRQ, 10),
		strconv.FormatUint(report.SoftIRQ, 10),
		strconv.FormatUint(report.Steal, 10),
		strconv.FormatUint(report.Guest, 10),
		strconv.FormatUint(report.GuestNice, 10),
	}
}

func DisplayCPUUsage(before *CPUReport, after *CPUReport) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Core", "Busy", "Total", "Percent", "User", "Nice", "System", "Idle", "IO Wait", "IRQ", "SoftIRQ", "Steal", "Guest", "Guest Nice"})
	for i := range before.cpus {
		diff, total, err := measureCore(before.cpus[i], after.cpus[i])
		if err != nil {
			return err
		}
		table.Append(convertToString(*diff, total))
	}
	//footer will be total
	diff, total, err := measureCore(before.all, after.all)
	if err != nil {
		return err
	}
	table.SetFooter(convertToString(*diff, total))
	table.Render()
	return nil
}

func GetUsageOfCore(before *CPUReport, after *CPUReport, core int) (float64, error) {
	if core < 0 || core > len(before.cpus) {
		return 0, fmt.Errorf("core %d does not exist", core)
	}
	report, total, err := measureCore(before.cpus[core], after.cpus[core])
	if err != nil {
		return 0, err
	}
	return 100 * float64(total-report.Idle) / float64(total), nil
}
