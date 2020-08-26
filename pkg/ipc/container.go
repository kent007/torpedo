package ipc

import (
	"errors"
	"fmt"
	linuxproc "github.com/c9s/goprocinfo/linux"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"os"
	"os/exec"
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

func MakeBootstrapCommand(bin []string, count int, stopTimestamp int64) (*exec.Cmd, error) {
	dockerArgs := strings.Split(dockerArgString, " ")

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

// wraps the standard executor command in a docker command line
// this can only be called from a fuzzer that is _not_ running in a container, or at least has access to the docker CLI
func makeContainerCommand(pid int, bin []string, config *Config, inFile, outFile *os.File, outmem []byte,
	tmpDirPath string) (*command, error) {

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

	cmd, err := MakeBootstrapCommand(bin, 0, stopTimestamp)
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

func getCPUUsage() (uint64, uint64, error) {

	stat, err := linuxproc.ReadStat("/proc/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("stat read failure")
	}
	total := uint64(0)
	s := stat.CPUStatAll
	total = total + s.User + s.Nice + s.System + s.Idle + s.IOWait + s.IRQ + s.SoftIRQ + s.Steal + s.Guest + s.GuestNice
	return total, s.Idle, nil
}
