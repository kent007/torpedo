package main
// this is the shared memory version which caused some problems
//
//import (
//	"bytes"
//	"flag"
//	"github.com/google/syzkaller/pkg/osutil"
//	"github.com/google/syzkaller/prog"
//	"github.com/pkg/errors"
//	"io"
//	"log"
//	"os"
//	"os/exec"
//	"strings"
//	"time"
//	"unsafe"
//)
//
//const (
//	outputSize = 16 << 20
//)
//
//type executeReq struct {
//	magic     uint64
//	envFlags  uint64 // env flags
//	execFlags uint64 // exec flags
//	pid       uint64
//	faultCall uint64
//	faultNth  uint64
//	progSize  uint64
//	// prog follows on pipe or in shmem
//}
//
////use readall for consistency with IPC package
//func readExecRequest() (*executeReq, error) {
//	req := &executeReq{}
//	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
//	if _, err := io.ReadFull(os.Stdin, reqData); err != nil {
//		return nil, errors.Wrap(err, "Error reading executeRequest from stdin")
//	}
//	return req, nil
//}
//
////use flags for 3 args:
//// !! these all return pointers
////TODO eventually capture the signal and coverage from each program, then merge and write it all back as one blob
//func main() {
//	var count = flag.Int("count", 0, "how many time to rerun the program")
//	var stopTimestampNano = flag.Int64("stop", 0, "loop the program until this unix nano timestamp")
//	var executor = flag.String("executor", "/syz-executor", "the executor binary")
//	var executorArgs = flag.String("executorArgs", "", "args for the executor")
//
//	log.Printf("%v", os.Args)
//	flag.Parse()
//	log.Printf("count: %d; stopTimestampNano: %d; executor: %s; executorArgs: %s", *count, *stopTimestampNano, *executor, *executorArgs)
//
//	log.SetPrefix("docker-bootstrap: ")
//
//	//read exec request from stdin
//	req, err := readExecRequest()
//	if err != nil {
//		log.Panicf("error determining length of program: %v", err)
//	}
//	log.Print("successfully read exec request")
//
//	//read program data
//	var progData = make([]byte, req.progSize)
//	n, err := io.ReadFull(os.Stdin, progData)
//	if err != nil || uint64(n) != req.progSize {
//		log.Panicf("error reading program data: expected %d bytes, read %d with error %v", req.progSize, n, err)
//	}
//	log.Printf("successfully read program data")
//
//	//run program and record output (overwriting on each successive run)
//	var out []byte
//	var coverData []byte
//	if *count != 0 {
//		for i := 0; i < *count; i++ {
//			out, coverData = execute(*executor, strings.Split(*executorArgs, " "), req, progData)
//		}
//		log.Printf("Successfully completed %d runs", *count)
//	} else if *stopTimestampNano != 0 {
//
//		total := int64(0)
//		ex := int64(0)
//		stopTime := time.Unix(0, *stopTimestampNano)
//		log.Printf("looping until %s", stopTime.String())
//		if stopTime.Before(time.Now()) {
//			log.Panicf("stop timestamp %d should be in the future!", *stopTimestampNano)
//		}
//		/*
//			When the runtime of the program relative to the total time is large, it's possible the timeout fires
//			while the executor is running. To avoid this, we track the average execution time and check whether or not
//			we have enough time left for another run before blindly executing again
//			The effect is more pronounced when the CPU usage is limited, since the program can get BLOCKED while waiting
//			for resources to become available
//		*/
//		for {
//			before := time.Now().UnixNano()
//			if ex != 0 && before >= *stopTimestampNano-total/ex {
//				break
//			}
//			out, coverData = execute(*executor, strings.Split(*executorArgs, " "), req, progData)
//			after := time.Now().UnixNano()
//			ex++
//			total += after - before
//		}
//		log.Printf("Total number of program executions: %d", ex)
//		log.Printf("Average execution time: %s", time.Duration(total/ex).String())
//
//	} else {
//		log.Panicf("Neither -count nor -stop provided, exiting!")
//	}
//
//	_, err = os.Stdout.Write(out)
//	if err != nil {
//		log.Panicf("Could not write final program stdout to os.stdout, %v", err)
//	}
//
//	_, err = os.Stdout.Write(coverData)
//	if err != nil {
//		log.Panicf("Could not write coverage information to os.stdout, %v", err)
//	}
//}
//
//func execute(executor string, executorArgs []string, req *executeReq, progData []byte) ([]byte, []byte) {
//
//	//control pipe
//	read, write, err := os.Pipe()
//	if err != nil {
//		log.Panicf("could not create pipe, %v", err)
//	}
//
//	//input for shared memory
//	inFile, inmem, err := osutil.CreateMemMappedFile(prog.ExecBufferSize)
//	if err != nil {
//		log.Panicf("could not create mmapped input file, %v", err)
//	}
//	defer func() {
//		if inFile != nil {
//			osutil.CloseMemMappedFile(inFile, inmem)
//		}
//	}()
//	//output for shared memory
//	outFile, outmem, err := osutil.CreateMemMappedFile(outputSize)
//	if err != nil {
//		log.Panicf("could not create mmapped output file, %v", err)
//	}
//	defer func() {
//		if outFile != nil {
//			osutil.CloseMemMappedFile(outFile, outmem)
//		}
//	}()
//
//	//write prog data
//	numBytes := copy(inmem, progData)
//	log.Printf("wrote %d bytes of program into shared memory", numBytes)
//
//	var stdout = bytes.Buffer{}
//	cmd := exec.Command(executor, executorArgs[:]...)
//	cmd.Stdin = read
//	cmd.Stdout = &stdout
//	cmd.Stderr = os.Stderr
//	if inFile != nil && outFile != nil {
//		cmd.ExtraFiles = []*os.File{inFile, outFile}
//	}
//	if err := cmd.Start(); err != nil {
//		log.Panicf("Could not start command: %v", err)
//	}
//
//	//the following is mostly cloned from ipc's exec
//	//write request
//	// set the length of the program to 0 -- this hints executor it's coming
//	// via shared memory
//	req.progSize = 0
//	reqData := (*[unsafe.Sizeof(*req)]byte)(unsafe.Pointer(req))[:]
//	if _, err := write.Write(reqData); err != nil {
//		log.Panicf("failed to write request to control pipe: %v", err)
//	}
//
//	//wait for command to finish, on success the executor returns status 1
//	_ = cmd.Wait()
//	//if err != nil {
//	//	log.Printf("executor returned an error: %v", err)
//	//}
//
//	reader := bytes.NewReader(outmem)
//	coverData := make([]byte, outputSize)
//	_, err = reader.Read(coverData)
//	if err != nil {
//		log.Panicf("failed to read coverage data from shared memory: %v", err)
//	}
//
//	return stdout.Bytes(), coverData
//}
