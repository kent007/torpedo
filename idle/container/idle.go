package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	var stopTimestamp = flag.Int64("stop", time.Now().Add(time.Second*5).Unix(), "loop the program until this unix timestamp")

	log.Printf("%v", os.Args)
	flag.Parse()

	stopTime := time.Unix(*stopTimestamp, 0)
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
			ex++
		}
	}
}
