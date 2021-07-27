package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"time"
)

func main() {
	var stopTimestamp = flag.Int64("stop", time.Now().Add(time.Second*5).UnixNano(), "loop the program until this unix timestamp")
	var program = flag.String("program", "", "a program inside this container to loop")

	log.Printf("%v", os.Args)
	flag.Parse()

	stopTime := time.Unix(0, *stopTimestamp)
	log.Printf("looping until %s", stopTime.String())
	if stopTime.Before(time.Now()) {
		log.Panicf("stop timestamp %d should be in the future!", *stopTimestamp)
	}

	ex := uint64(0)
	timeout := time.After(time.Until(stopTime))
	for {
		select {
		case <-timeout:
			log.Printf("%d loops", ex)
			return
		default:
			if *program != "" {
				cmd := exec.Command(*program)
				err := cmd.Run()
				if err != nil {
					log.Fatalf("command failed: %v", err)
					return
				}
			}
			ex++
		}
	}
}
