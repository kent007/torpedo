package main

import (
	"encoding/csv"
	"fmt"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/kent007/linux-inspect/top"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type FuzzingState int

const (
	//we want the intersection of the proc/stat measurement and `top` to be as in-sync as possible
	//we also want to avoid any weird edge cases in resource util at the beginning or end
	//so we run the round for longer than we do for top, so that top can exit cleanly before the containers tear down
	//this is also important for capturing docker-related util, if the threads are torn down before TOP exits we won't
	//get any line output for them
	// FIXME changed this from 5/4 to 3/2
	ROUNDTIMESECONDS = 3
	ROUNDDURATION    = ROUNDTIMESECONDS * time.Second
	TOPDURATION      = ROUNDDURATION - 500*time.Millisecond
	TOPINTERVAL      = 2

	//kernel thread parent
	KTHREADD = 2

	//shuffletolerance is the percentage of tolerable variation when shuffling programs
	SHUFFLETOLERANCE = 2.5
	//number of rounds after which shuffle should stop trying to converge and assume program resource usage is flaky
	SHUFFLECAP = 3
	//tolerance for percent CPU utilization drop after program was removed
	DROPTOLERANCE = -10
	//number of rounds without improvement after which we assume mutate has reached a local maximum
	MUTATECAP = 15

	//the minimum amount positive score change we need to see before accepting the mutation
	MINIMPROVEMENT = 1

	ShufflePrograms FuzzingState = iota
	DropPrograms
	MutatePrograms
)

type FuzzingStatus struct {
	state                    FuzzingState  //whatever we were doing last round
	roundCounter             int           //the number of rounds we've been doing it
	roundsWithoutImprovement int           //the number of rounds since we had any improvement in the score
	best                     []interface{} //the programs that produced the best score
	bestScore                float64       //the highest score we've seen
	bestInfo                 []*ipc.ProgInfo // info associated with best
	last                     []interface{} //stores the last set of work items from the previous round
	lastScore                float64       //stores the score associated with last
	lastInfo                 []*ipc.ProgInfo // info associated with last
	totalImprovement         float64       //total improvement over lifetime of program set
}

//using this as a semaphore
var sem = make(chan int, 1)

//counter for above semaphore
var counter = int32(0)

//log file
var observerLog *os.File = nil

//seed programs
var seeds []string

//threshold CPU values based on running idle processes (1 or more procs doesn't make a difference in these categories)
//var thresholds = map[string]float64{
//	"kaudit":  0.0,
//	"auditd":  0.0,
//	"kworker": 5,
//	//"ksoftirq": 2.1,
//	"systemd-journal": 1.36,
//	"containerd":      3.2,
//}

//used to transmit information about the round between the TOP routine and the observer
type roundReport struct {
	before *ipc.CPUReport
	usages map[string]float64
	after  *ipc.CPUReport
}

//contains a goroutine for managing the TOP observations
func (fuzzer *Fuzzer) observerRoutine(numProcs int, idle bool, runtime string, capabilities string) {
	//create wait group and set to 1
	observer := sync.WaitGroup{}
	observer.Add(1)
	procGroup := sync.WaitGroup{}
	procGroup.Add(numProcs)

	dataCSV, _ := os.Create("round-data.csv")

	csvWriter := csv.NewWriter(dataCSV)

	//create all procs
	for pid := 0; pid < numProcs; pid++ {
		proc, err := newProc(fuzzer, pid, &observer, &procGroup)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
	}
	//start all procs
	for _, proc := range fuzzer.procs {
		go proc.loopSynchronized(runtime, capabilities)
	}

	//utilization := float64(0)
	categories := []string{"ksoftirq", "kworker", "dockerd", "containerd", "kaudit", "auditd", "systemd-journal", "runsc", "exe"}

	csvWriter.Write(append(categories, "other", "total"))

	results := make(chan *roundReport, 1)

	//IMPORTANT to set state to invalid value first
	status := &FuzzingStatus{}
	resetState(status, numProcs)
	var currentWork []interface{}
	if idle {
		currentWork = make([]interface{}, len(fuzzer.procs))
		observerLog, _ = os.Create("observer.idle.log")
	} else {
		currentWork = fuzzer.getNewPrograms(0)
	}
	//do this forever
	for roundCounter := 1; ; roundCounter++ {
		//all procs are waiting to select a program
		<-sem

		for i, proc := range fuzzer.procs {
			proc.programSelector <- currentWork[i]
		}

		//wait until all procs are primed
		procGroup.Wait()

		//done, beginning next round
		observerLog.WriteString(fmt.Sprintf("Beginning Round %d --------------------\n", roundCounter))
		writeProgramsToLog(currentWork)

		//calculate next stop timestamp, this is done here because the copy operation above could take some time
		stopTimestamp := time.Now().Add(ROUNDDURATION).UnixNano()
		topStopTimestamp := stopTimestamp - (500 * time.Millisecond).Nanoseconds()

		//save next timestamp into each proc
		for _, proc := range fuzzer.procs {
			proc.stopTimestamp = stopTimestamp
		}

		//observer signals all procs to execute
		start := time.Now()
		observer.Done()
		log.Logf(1, "Observer: staring round %d", roundCounter)
		log.Logf(4, "Observer: round %d will end at %d", roundCounter, stopTimestamp)

		//start measuring top
		go observeRound(topStopTimestamp, categories, results)

		//wait for ack that all processes have started (or at least completed their wait call)
		<-sem

		//observer increments by 1
		observer.Add(1)

		//wait for results
		report := <-results
		log.Logf(4, "Observer: round %d took %s seconds", roundCounter, time.Since(start))
		//utilization = report.usages["total"]
		observerLog.WriteString(fmt.Sprintf("usage during this period: (%+v)\n", report.usages))
		ipc.DisplayCPUUsage(report.before, report.after, observerLog)
		diff, total, _ := ipc.MeasureCore(report.before.All, report.after.All)
		percentUtil := 100 * float64(total-diff.Idle) / float64(total)

		//write to round CSV file
		var row []string
		for _, key := range categories {
			row = append(row, fmt.Sprintf("%f", report.usages[key]))
		}
		row = append(row, fmt.Sprintf("%f", report.usages["other"]))
		csvWriter.Write(row)
		csvWriter.Flush()

		//make decisions about how to conduct the next round, potentially resetting the status
		//this should only be done if we're not idling, in which case all will be null
		if !idle {
			currentWork = fuzzer.getPrograms(currentWork, status, percentUtil, roundCounter)
		}
	}

}

//observe one round until the stop timestamp and report the results
func observeRound(stopTimestamp int64, categories []string, results chan *roundReport) {

	before, _ := ipc.GetCPUReport()
	output, _ := top.GetTimed(top.DefaultExecPath, 0, stopTimestamp, TOPINTERVAL)
	after, _ := ipc.GetCPUReport()
	rows, iterations, _ := top.Parse(output)

	//round up some miscellaneous PIDs from children of kthreadd that aren't running as workers
	miscKernelPIDS, _ := ipc.GetChildrenOfPID(KTHREADD)
	usage := ipc.GetUsageOfProcs(rows, miscKernelPIDS, categories)

	//divide out the totals to get averages across the period
	for k, v := range usage {
		usage[k] = v / float64(iterations)
	}

	//currently for debug purposes
	//observerLog.WriteString(output)

	log.Logf(4, "Observer took %d top measurements", iterations)
	results <- &roundReport{
		before: before,
		usages: usage,
		after:  after,
	}
}

//measure CPU utilization for all children of pid until timestamp expires
//func measureTop(stopTimestamp int64, pid uint64, categories []string) (map[string]float64, int, error) {
//	//this runs until the command times out
//	rows, iterations, err := top.GetTimed(top.DefaultExecPath, 0, stopTimestamp, 4)
//	if err != nil {
//		return nil, -1, err
//	}
//
//	//round up some miscellaneous PIDs from children of kthreadd that aren't running as workers
//	miscPIDs, _ := ipc.GetChildrenOfPID(pid)
//	usage := ipc.GetUsageOfProcs(rows, miscPIDs, categories)
//	//divide out the totals to get averages across the period
//	for k, v := range usage {
//		usage[k] = v / float64(iterations)
//	}
//
//	return usage, iterations, nil
//}

//function that implements a state machine for the observer
//accepts the slice of current programs (with nil for each fuzzer not currently operating)
//returns a slice of work items to be completed by the corresponding indexed proc
/*
	the state machine currently has 3 states:
	shuffle -- check if the score has decreased since it was shuffled (tolerate % error)
				go to mutate or drop (mutate being more likely)
	drop -- drop a program and see whether or not it was significant
	mutate -- perform a mutation on a random program. If the score increases significantly,
				confirm it and log it as the best

this code is very complex
*/

func (fuzzer *Fuzzer) getPrograms(currentPrograms []interface{}, status *FuzzingStatus, currentScore float64,
	roundNumber int) []interface{} {
	status.roundCounter++
	percentChangeLast := (currentScore - status.lastScore) / status.lastScore * 100
	currentInfo := make([]*ipc.ProgInfo, len(currentPrograms))
	for i, work := range currentPrograms {
		currentInfo[i] = <-fuzzer.procs[i].lastInfo
		if work, ok := work.(*WorkTriage); ok {
			fuzzer.addProgramToCorpus(work, currentInfo[i])
		}
	}
	switch status.state {
	case ShufflePrograms:
		if math.Abs(percentChangeLast) > SHUFFLETOLERANCE {
			//measurements didn't match up
			log.Logf(1, "after shuffle, results changed by more than %f percent (%.2f vs %.2f, %2.2f percent "+
				"change)", SHUFFLETOLERANCE, currentScore, status.lastScore, percentChangeLast)
			if status.roundCounter > SHUFFLECAP {
				//failed to converge
				//TODO add a stat here to indicate that we failed to converge
				log.Logf(1, "observations did not converge during shuffling, resetting")
				observerLog.WriteString("observations did not converge during shuffling. ")
				if status.best[0] != nil {
					//revert to last known best
					observerLog.WriteString("reverting to last known good program set...\n")
					goto pickNextState
				} else {
					//just start over
					observerLog.WriteString("generating new programs...\n")
					resetState(status, len(currentPrograms))
					return fuzzer.getNewPrograms(roundNumber)
				}
			} else {
				//hope that current round was not an outlier, and compare against it instead
				saveLast(status, currentPrograms, currentScore, currentInfo)
				observerLog.WriteString(fmt.Sprintf("adjusting target score to %.2f and retrying...\n", currentScore))
				return shufflePrograms(currentPrograms)
			}
		}
		observerLog.WriteString(fmt.Sprintf("confirmed reproducible score of %.2f\n", currentScore))

		if status.bestScore+MINIMPROVEMENT <= currentScore {
			//the score we converged to is actually better by a significant amount!
			observerLog.WriteString(fmt.Sprintf("new best score %.2f!\n", currentScore))
			saveBest(status, currentPrograms, currentScore, currentInfo)
			status.roundsWithoutImprovement = 0
		} else {
			log.Logf(2, "score converged, but was not (significantly?) better than previously recorded best "+
				"(%.2f vs %.2f)", currentScore, status.bestScore)
			observerLog.WriteString(fmt.Sprintf("score converged, but was not (significantly?) better than previously"+
				" recorded best (%.2f vs %.2f)\n", currentScore, status.bestScore))
		}
	pickNextState:
		saveLast(status, status.best, status.bestScore, status.bestInfo)
		//this always operates on the best program, which has either just been set or needs to be reused
		//FIXME idling is actually better in some cases than the original program, we want to freeze the core entirely
		//if rand.Intn(4) == 0 {
		//	//drop
		//	changeState(status, DropPrograms)
		//	return dropProgram(status.best, 0)
		//} else {
		//mutate
		changeState(status, MutatePrograms)
		return fuzzer.mutateProgram(status.best)
		//}
	//case DropPrograms:
		//FIXME untested
		//if percentChangeLast < DROPTOLERANCE {
		//	//program should be put back
		//	log.Logf(2, "score dropped by %.2f, restoring program %d...\n", percentChangeLast, status.roundCounter-1)
		//	currentPrograms = status.last
		//} else {
		//	//save the last set and advance from there
		//	log.Logf(2, "score only dropped by %.2f, program %d likely insignificant",
		//		percentChangeLast, status.roundCounter-1)
		//	observerLog.WriteString(fmt.Sprintf("adjusting best score to %.2f...\n", currentScore))
		//	saveBest(status, currentPrograms, currentScore)
		//	saveLast(status, currentPrograms, currentScore)
		//}
		//if status.roundCounter == len(currentPrograms) {
		//	//done dropping, move to mutate
		//	changeState(status, MutatePrograms)
		//	return fuzzer.mutateProgram(currentPrograms)
		//} else {
		//	//drop the current program
		//	return dropProgram(currentPrograms, status.roundCounter)
		//}
	case MutatePrograms:
		if currentScore >= status.bestScore+MINIMPROVEMENT {
			//potentially a new best, save it and switch state to shuffle
			observerLog.WriteString(fmt.Sprintf("Potentially new best score %f\n", currentScore))
			saveLast(status, currentPrograms, currentScore, currentInfo)
			changeState(status, ShufflePrograms)
			return shufflePrograms(currentPrograms)
		} else {
			status.roundsWithoutImprovement++
			// reset to "best" programs
			currentPrograms = status.best
		}
		if status.roundsWithoutImprovement == MUTATECAP {
			//we've reached a local maximum, commit all programs into the corpus and get new programs
			log.Logf(1, "reached local maximum, generating new programs...")
			observerLog.WriteString("Local maximum reached. Restarting...\n")
			writeProgramsToLog(status.best)
			observerLog.WriteString(fmt.Sprintf("best score was %.2f\n", status.bestScore))
			observerLog.WriteString(fmt.Sprintf("total improvement was %.2f\n", status.totalImprovement))
			resetState(status, len(currentPrograms))
			return fuzzer.getNewPrograms(roundNumber)
		} else {
			//keep mutating
			saveLast(status, currentPrograms, currentScore, currentInfo)
			return fuzzer.mutateProgram(currentPrograms)
		}
	default:
		//save initial values, shuffle the programs and set the state to shuffle
		saveLast(status, currentPrograms, currentScore, currentInfo)
		observerLog.WriteString(fmt.Sprintf("initial score of %.2f\n", status.lastScore))
		changeState(status, ShufflePrograms)
		return shufflePrograms(currentPrograms)
	}
}

//change to the specified state and reset the round counter
func changeState(status *FuzzingStatus, newState FuzzingState) {
	status.state = newState
	status.roundCounter = 0
}

//reset the state of the `status` object
func resetState(status *FuzzingStatus, programs int) {
	status.state = -1
	status.best = make([]interface{}, programs)
	status.bestScore = 0
	status.bestInfo = make([]*ipc.ProgInfo, programs)
	status.roundsWithoutImprovement = 0
	status.roundCounter = 0
	status.last = make([]interface{}, programs)
	status.lastScore = 0
	status.lastInfo = make([]*ipc.ProgInfo, programs)
	status.totalImprovement = 0
}

//saves the information about the last round
func saveLast(status *FuzzingStatus, programs []interface{}, score float64, info []*ipc.ProgInfo) {
	copy(status.last, programs)
	status.lastScore = score
	copy(status.lastInfo, info)
}

//save information about the best round
func saveBest(status *FuzzingStatus, programs []interface{}, score float64, info []*ipc.ProgInfo) {
	if status.bestScore != 0 {
		status.totalImprovement += score - status.bestScore
	}
	copy(status.best, programs)
	status.bestScore = score
	copy(status.bestInfo, info)
}

//generate a new array of programs
//attempt to take items from the workqueue. If none are available,
//generate or mutate new programs
func (fuzzer *Fuzzer) getNewPrograms(roundCounter int) []interface{} {

	if observerLog != nil {
		observerLog.Close()
	}
	observerLog, _ = os.Create("../observer." + strconv.Itoa(roundCounter) + ".log")

	newPrograms := make([]interface{}, len(fuzzer.procs))

	generatePeriod := 100
	if fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i, proc := range fuzzer.procs {
		item := fuzzer.workQueue.dequeue()
		if item == nil {
			var p *prog.Prog
			ct := fuzzer.choiceTable
			fuzzerSnapshot := fuzzer.snapshot()
			if len(seeds) != 0 {
				// Choose a seed program
				p = getSeed(fuzzer.target).P
				log.Logf(1, "#%v: selected seed", i)
			} else if len(fuzzerSnapshot.corpus) == 0 || roundCounter%generatePeriod == 0 {
				// Generate a new prog.
				p = fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(1, "#%v: generated", i)
			} else {
				// Mutate an existing prog.
				p = fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(1, "#%v: mutated", i)
			}
			item = &WorkCandidate{
				p:     p,
				flags: ProgNormal,
			}
		}
		newPrograms[i] = item
	}
	observerLog.WriteString("new programs...")
	writeProgramsToLog(newPrograms)
	return newPrograms
}

//creates a copy of the passed slice, shuffles the contents, and returns the shuffled copy
func shufflePrograms(current []interface{}) []interface{} {
	observerLog.WriteString("shuffling programs...\n")
	shuffled := make([]interface{}, len(current))
	copy(shuffled, current)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

//drop one program from the array, but save the existing array into the status
func dropProgram(current []interface{}, dropIndex int) []interface{} {
	observerLog.WriteString(fmt.Sprintf("dropping program %d...\n", dropIndex))
	dropped := make([]interface{}, len(current))
	copy(dropped, current)
	dropped[dropIndex] = nil
	return dropped
}

//apply one mutations
//save the old array into the table
//this must perform a deep copy to avoid messing with the original array, in case we need to revert
func (fuzzer *Fuzzer) mutateProgram(current []interface{}) []interface{} {
	mutated := make([]interface{}, len(current))
	copy(mutated, current)
	for index, item := range current {
		observerLog.WriteString(fmt.Sprintf("mutating program %d...\n", index))
		fuzzerSnapshot := fuzzer.snapshot()
		switch item := item.(type) {
		case *WorkCandidate:
			clone := item.p.Clone()
			clone.Mutate(fuzzer.procs[index].rnd, prog.RecommendedCalls, fuzzer.choiceTable, fuzzerSnapshot.corpus)
			mutated[index] = &WorkCandidate{
				clone,
				item.flags,
			}
		case *WorkTriage:
			clone := item.p.Clone()
			clone.Mutate(fuzzer.procs[index].rnd, prog.RecommendedCalls, fuzzer.choiceTable, fuzzerSnapshot.corpus)

			if item.call > len(clone.Calls) - 1 {
				item.call = -1
			}

			mutated[index] = &WorkTriage{
				clone,
				item.call,
				item.info,
				item.flags,
			}
		}
	}
	return mutated
}


//func (fuzzer *Fuzzer) compareNewCoverage(item1, item2 interface{}, info1, info2 *ipc.ProgInfo) int {
//	//return > 0 if item 1 is bigger, 0 if same, -1 if item 1 is smaller
//
//	var program1, program2 *prog.Prog
//	switch item := item1.(type) {
//	case *WorkCandidate:
//		program1 = item.p
//		program2 = item2.(*WorkCandidate).p
//	case *WorkTriage:
//		program1 = item.p
//		program2 = item2.(*WorkTriage).p
//	}
//
//	if len(program1.Calls) != len(info1.Calls) || len(program2.Calls) != len(info2.Calls) {
//		log.Logf(1, "program and info are desynced")
//		log.Logf(1, "program was %s", program1.String())
//		log.Logf(1, "info was %+v", info1)
//		observerLog.WriteString("program and info are desynced\n")
//		return 0
//	}
//
//	calls1, _ := fuzzer.checkNewSignal(program1, info1)
//	calls2, _ := fuzzer.checkNewSignal(program2, info2)
//	return len(calls1) - len(calls2)
//}

func sendNewToManager(fuzzer *Fuzzer, item *WorkTriage, info *ipc.ProgInfo, callIndex int) {
	prio := signalPrio(item.p, &info.Calls[callIndex], callIndex)
	inputSignal := signal.FromRaw(info.Calls[callIndex].Signal, prio)
	newSignal := fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		//log.Logf(3, "call %d: no new signal")
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if callIndex != -1 {
		callName = item.p.Calls[callIndex].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", callIndex, callName)
	}

	var inputCover cover.Cover
	_, thisCover := getSignalAndCover(item.p, info, callIndex)
	inputCover.Merge(thisCover)

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "call %d: added new input for %v to corpus:\n%s", callIndex, logCallName, data)
	fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	fuzzer.addInputToCorpus(item.p, inputSignal, sig)
}

// send all new coverage at once
func (fuzzer *Fuzzer) addProgramToCorpus(item *WorkTriage, info *ipc.ProgInfo) {
	if item.call == -1 {
		sendNewToManager(fuzzer, item, info, item.call)
	} else {
		for i := 0; i < len(item.p.Calls); i++ {
			sendNewToManager(fuzzer, item, info, i)
		}
	}
}

func writeProgramsToLog(programs []interface{}) {
	for i, item := range programs {
		fmtString := "program %d\n%s\n"
		switch item := item.(type) {
		case *WorkTriage:
			observerLog.WriteString(fmt.Sprintf(fmtString, i, item.p.Serialize()))
		case *WorkCandidate:
			observerLog.WriteString(fmt.Sprintf(fmtString, i, item.p.Serialize()))
		case nil:
			observerLog.WriteString(fmt.Sprintf(fmtString, i, "no program"))
		default:
			observerLog.WriteString(fmt.Sprintf(fmtString, i, "unknown work type"))
		}
	}
}

//read seed programs from this directory
func (fuzzer *Fuzzer) readSeedPrograms(dir string) error {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	var paths []string
	for _, file := range files {
		if !file.IsDir() {
			paths = append(paths, filepath.Join(dir, file.Name()))
		}
	}
	if len(files) == 0 {
		log.Logf(1, "no seed files in %s", dir)
		return nil
	}
	seeds = paths
	return nil
}

func getSeed(target *prog.Target) *prog.LogEntry {
	// Choose a seed program
	var p *prog.LogEntry
	for {
		last := len(seeds) - 1
		file := seeds[last]
		seeds = seeds[:last]
		data, err := ioutil.ReadFile(file)
		if err != nil {
			log.Logf(1, "failed to read log file: %v", err)
			continue
		}
		log.Logf(1, "selected seed program %s", file)
		p = target.ParseLog(data)[0]
		break
	}
	return p
}

func (fuzzer *Fuzzer) signalObserver() {
	atomic.AddInt32(&counter, 1)
	if atomic.CompareAndSwapInt32(&counter, int32(len(fuzzer.procs)), 0) {
		sem <- 1
	}
}
