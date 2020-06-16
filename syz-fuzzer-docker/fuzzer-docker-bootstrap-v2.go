package main

import (
	"errors"
	"fmt"
	"github.com/google/syzkaller/pkg/osutil"
	"log"
	"os"
	"strconv"
	"strings"
)

//TODO security might disallow this
func checkDockerDaemon() error {
	command := osutil.Command("systemctl", "check", "docker")
	_ = command.Start()
	if err := command.Wait(); err != nil {
		return errors.New(fmt.Sprintf("systemctl check docker returned code %v", err))
	}
	return nil
}

//attach to all three streams and limit logs to 2 files of 5MB each
func main() {
	//sanitycheck log
	log.Printf("DOCKER MONITOR: starting...")

	dockerArgs := []string{"run", "-a", "stdin", "-a", "stdout", "-a", "stderr", "-i", "-v", "/sys/kernel/debug:/sys/kernel/debug:rw",
		"--network=host", "--log-opt", "max-size=5m", "--log-opt", "max-file=2", "syzkaller-image"}
	procs := 1
	//extract number of procs, set each fuzzer to one
	for i, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-procs") {
			procs, _ = strconv.Atoi(strings.Split(arg, "=")[1])
			os.Args[i] = "-procs=1"
		}
	}


	//append executor args
	dockerArgs = append(dockerArgs, os.Args[1:]...)
	ch := make(chan error)

	//start the container programs
	for i := 0; i < procs; i++ {
		go fuzzerRoutine(dockerArgs, ch, i)
	}
	err := <- ch
	if err != nil {
		if dockerErr := checkDockerDaemon(); dockerErr != nil {
			log.Printf("DOCKER MONITOR: docker daemon also crashed: %v", err)
		}
		log.Printf("DOCKER MONITOR: docker daemon was not affected by this crash.")
		os.Exit(1)
	}
	log.Printf("DOCKER MONITOR: exiting normally. This should only happen during testing mode")
}

func fuzzerRoutine(args []string, errorReport chan error, id int) {
	command := osutil.Command("docker", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		log.Fatalf("DOCKER MONITOR: Fuzzer %d: Could not start docker command: %v. Check container logs for more details", id, err)
	}
	if err := command.Wait(); err != nil {
		log.Printf("DOCKER MONITOR: Fuzzer %d crashed with error: %v", id, err)
		errorReport <- err
	}
	errorReport <- nil
}