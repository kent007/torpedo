package main

//
//import (
//	"context"
//	"errors"
//	"fmt"
//	"github.com/docker/docker/api/types"
//	"github.com/docker/docker/api/types/container"
//	"github.com/docker/docker/client"
//	"github.com/docker/docker/daemon/caps"
//	"github.com/docker/docker/pkg/stdcopy"
//	"log"
//	"os"
//	"strconv"
//	"strings"
//)
//
//const image = "syzkaller-image"
//
////old method, using the CLI
////"--runtime=runsc"
////on coverage-enabled containers, -v /sys/kernel/debug:/sys/kernel/debug:rw
////dockerArgs := []string{"run", "-a", "stdin", "-a", "stdout", "-a", "stderr", "-i", "-v", "/sys/kernel/debug:/sys/kernel/debug:rw",
////	"--log-opt", "max-size=5m", "--log-opt", "max-file=2", "--runtime=runsc", "--cap-add=ALL", "syzkaller-image"}
//
////I picked a simple GET api call that _has_ to hit the API, but it could be other things
//func checkDockerDaemon(cli *client.Client) error {
//	if _, err := cli.ContainerList(context.Background(), types.ContainerListOptions{}); err != nil {
//		return errors.New("docker API health check failed")
//	}
//	return nil
//}
//
////attach to all three streams and limit logs to 2 files of 5MB each
//func main() {
//	//sanitycheck log
//	log.Printf("DOCKER MONITOR: starting...")
//
//	cli, err := client.NewEnvClient()
//
//	log.Printf("DOCKER MONITOR: using runsc...")
//
//	procs := 1
//	//extract number of procs, set each fuzzer to one
//	for i, arg := range os.Args[1:] {
//		if strings.HasPrefix(arg, "-procs") {
//			procs, _ = strconv.Atoi(strings.Split(arg, "=")[1])
//			os.Args[i] = "-procs=1"
//		}
//	}
//
//	//append executor args
//	dockerArgs := os.Args[1:]
//	ch := make(chan error)
//
//	//start the container programs
//	for i := 0; i < procs; i++ {
//		go fuzzerRoutine(dockerArgs, cli, ch, i)
//	}
//	err = <-ch
//	if err != nil {
//		if dockerErr := checkDockerDaemon(cli); dockerErr != nil {
//			log.Printf("DOCKER MONITOR: docker daemon also crashed: %v", err)
//		}
//		log.Printf("DOCKER MONITOR: docker daemon was not affected by this crash.")
//		os.Exit(1)
//	}
//	log.Printf("DOCKER MONITOR: exiting normally. This should only happen during testing mode")
//}
//
//func fuzzerRoutine(args []string, cli *client.Client, errorReport chan error, id int) {
//	ctx := context.Background()
//	resp, err := cli.ContainerCreate(ctx, &container.Config{
//		Image:        image,
//		AttachStderr: true,
//		AttachStdout: true,
//		Cmd:          args,
//	}, &container.HostConfig{
//		LogConfig: container.LogConfig{
//			Type: "",
//			Config: map[string]string{
//				"max-size": "5m",
//				"max-file": "2",
//			},
//		},
//		CapAdd:  caps.GetAllCapabilities(),
//		Runtime: "runsc",
//	}, nil, fmt.Sprintf("executor-%d", id))
//	if err != nil {
//		log.Fatalf("DOCKER MONITOR: Fuzzer %d: Could not create container: %v", id, err)
//	}
//	if err = cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
//		log.Fatalf("DOCKER MONITOR: Fuzzer %d: Could not start container: %v", id, err)
//	}
//
//	reader, err := cli.ContainerAttach(ctx, resp.ID, types.ContainerAttachOptions{
//		Stream: true,
//		Stderr: true,
//		Stdout: true,
//		Logs:   false,
//	})
//
//	go func() {
//		_, err = stdcopy.StdCopy(os.Stdout, os.Stdout, reader.Reader)
//		log.Printf("DOCKER MONITOR: end of output from executor %d", id)
//		// don't care about errors, should be caught by outer function
//	}()
//
//	_, err = cli.ContainerWait(ctx, resp.ID)
//	if err != nil {
//		log.Printf("DOCKER MONITOR: Fuzzer %d crashed with error: %v", id, err)
//		errorReport <- err
//	}
//	errorReport <- nil
//}
