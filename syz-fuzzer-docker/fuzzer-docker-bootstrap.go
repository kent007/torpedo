package main

import (
	"bytes"
	"flag"
	"github.com/pkg/errors"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

type executeReq struct {
	magic     uint64
	envFlags  uint64 // env flags
	execFlags uint64 // exec flags
	pid       uint64
	faultCall uint64
	faultNth  uint64
	progSize  uint64
	// prog follows on pipe or in shmem
}

//use readall for consistency with IPC package
func readExecRequest() (*executeReq, error) {
	req := &executeReq{}
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := io.ReadFull(os.Stdin, reqData); err != nil {
		return nil, errors.Wrap(err, "Error reading executeRequest from stdin")
	}
	return req, nil
}

//use flags for 3 args:
// !! these all return pointers
func main() {
	var count = flag.Int("count", 0, "how many time to rerun the program")
	var stopTimestamp = flag.Int64("stop", 0, "loop the program until this unix timestamp")
	var executor = flag.String("executor", "/syz-executor", "the executor binary")
	var executorArgs = flag.String("executorArgs", "", "args for the executor")

	log.Printf("%v", os.Args)
	flag.Parse()
	log.Printf("count: %d; stopTimestamp: %d; executor: %s; executorArgs: %s", *count, *stopTimestamp, *executor, *executorArgs)

	log.SetPrefix("docker-bootstrap: ")

	//read exec request from stdin
	req, err := readExecRequest()
	if err != nil {
		log.Panicf("error determining length of program: %v", err)
	}
	log.Print("successfully read exec request")

	//read program data
	var progData = make([]byte, req.progSize)
	n, err := io.ReadFull(os.Stdin, progData)
	if err != nil || uint64(n) != req.progSize {
		log.Panicf("error reading program data: expected %d bytes, read %d with error %v", req.progSize, n, err)
	}
	log.Printf("successfully read program data")

	//run program and record output (overwriting on each successive run)
	var out []byte
	if *count != 0 {
		for i := 0; i < *count; i++ {
			out = execute(*executor, strings.Split(*executorArgs, " "), req, progData)
		}
	} else if *stopTimestamp != 0 {

		total := int64(0)
		ex := int64(0)
		stopTime := time.Unix(*stopTimestamp, 0)
		log.Printf("looping until %s", stopTime.String())
		if stopTime.Before(time.Now()) {
			log.Panicf("stop timestamp %d should be in the future!", *stopTimestamp)
		}
		/*
			When the runtime of the program relative to the total time is large, it's possible the timeout fires
			while the executor is running. To avoid this, we track the average execution time and check whether or not
			we have enough time left for another run before blindly executing again
			The effect is more pronounced when the CPU usage is limited, since the program can get BLOCKED while waiting
			for resources to become available
		*/
		stopNano := stopTime.UnixNano()
		for {
			now := time.Now().UnixNano()
			if ex != 0 && now >= stopNano-total/ex {
				break
			}
			before := time.Now().UnixNano()
			out = execute(*executor, strings.Split(*executorArgs, " "), req, progData)
			after := time.Now().UnixNano()
			ex++
			total += after - before
		}
		log.Printf("Total number of program executions: %d", ex)
		log.Printf("Average execution time: %d", total/ex)

	} else {
		log.Panicf("Neither -count nor -stop provided, exiting!")
	}

	_, err = os.Stdout.Write(out)
	if err != nil {
		log.Panicf("Could not write final program stdout to os.stdout")
	}
}

func execute(executor string, executorArgs []string, req *executeReq, progData []byte) []byte {

	//for now I'm using a pipe, could look into shmem in the future
	read, write, err := os.Pipe()
	if err != nil {
		log.Panicf("could not create pipe, %v", err)
	}

	var stdout = bytes.Buffer{}
	cmd := exec.Command(executor, executorArgs[:]...)
	cmd.Stdin = read
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Panicf("Could not start command: %v", err)
	}

	//the following is mostly cloned from ipc's exec
	//write request
	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
	if _, err := write.Write(reqData); err != nil {
		log.Panicf("failed to write request to control pipe: %v", err)
	}

	//write prog data
	if progData != nil {
		if _, err := write.Write(progData); err != nil {
			log.Panicf("failed to write program to control pipe: %v", err)
		}
	}

	//wait for command to finish
	_ = cmd.Wait()

	return stdout.Bytes()
}
