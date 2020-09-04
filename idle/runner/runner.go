package main

import (
	"github.com/google/syzkaller/pkg/ipc"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	//do this some number of times
	args := []string{"run", "--cpuset-cpus=11", "idle-amd64", "-stop=" + strconv.FormatInt(time.Now().Add(10*time.Second).Unix(), 10)}
	cmd1 := exec.Command("docker", args...)

	args2 := []string{"run", "--cpuset-cpus=10", "idle-amd64", "-stop=" + strconv.FormatInt(time.Now().Add(10*time.Second).Unix(), 10)}
	cmd2 := exec.Command("docker", args2...)

	before, _ := ipc.GetCPUReport()
	log.Printf(strings.Join(cmd1.Args, " "))
	cmd1.Start()
	cmd2.Start()
	cmd1.Wait()
	cmd2.Wait()
	after, _ := ipc.GetCPUReport()
	ipc.DisplayCPUUsage(before, after, os.Stdout)

}
