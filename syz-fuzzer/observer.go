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
	"math"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type FuzzingState int

const (
	//how long each round should be
	//the first top measurement takes approximately .2 seconds to complete
	//so 5.3 seconds gets us 6 top measurements
	DURATION = 5*time.Second + 300*time.Millisecond
	//kernel thread parent
	KTHREADD = 2

	//number of times a false-positive verification should be attempted
	VERIFYATTEMPTS = 3

	//shuffletolerance is the percentage of tolerable variation when shuffling programs
	SHUFFLETOLERANCE = 2.5
	//number of rounds after which shuffle should stop trying to converge and assume program resource usage is flaky
	SHUFFLECAP = 3
	//tolerance for percent CPU utilization drop after program was removed
	DROPTOLERANCE = -10
	//number of rounds without improvement after which we assume mutate has reached a local maximum
	MUTATECAP = 15

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
	last                     []interface{} //stores the last set of work items from the previous round
	lastScore                float64       //stores the score associated with last
}

//using this as a semaphore
var sem = make(chan int, 1)

//counter for above semaphore
var counter = int32(0)

//log file
//TODO have this roll over to a new log file each time the program set changes
var observerLog *os.File

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
func (fuzzer *Fuzzer) observerRoutine(numProcs int, idle bool) {
	//create wait group and set to 1
	observer := sync.WaitGroup{}
	observer.Add(1)
	procGroup := sync.WaitGroup{}
	procGroup.Add(numProcs)

	observerLog, _ = os.Create("observer.log")
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
		if idle {
			go proc.loopIdle()
		} else {
			go proc.loopSynchronized()
		}
	}

	utilization := float64(0)
	categories := []string{"ksoftirq", "kworker",
		"dockerd", "containerd",
		"kaudit", "auditd", "systemd-journal"}
	//FIXME dockerd temporarily removed due to known issue involving tty subsystem

	csvWriter.Write(append(categories, "other", "total"))

	results := make(chan *roundReport, 1)

	//IMPORTANT to set state to invalid value first
	status := &FuzzingStatus{
		state: -1,
	}
	currentWork := fuzzer.getNewPrograms(0)
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

		//calculate next stop timestamp, this is done here because the copy operation above could take some time
		stopTimestamp := time.Now().Add(DURATION).UnixNano()
		log.Logf(4, "Observer: next round will end at %d", stopTimestamp)

		//save next timestamp into each proc
		for _, proc := range fuzzer.procs {
			proc.stopTimestamp = stopTimestamp
		}

		//observer signals all procs to execute
		start := time.Now()
		observer.Done()

		//start measuring top
		go observeRound(stopTimestamp, categories, results)

		//wait for ack that all processes have started (or at least completed their wait call)
		<-sem

		//observer increments by 1
		observer.Add(1)

		//wait for results
		report := <-results
		log.Logf(4, "Observer: round took %s seconds", time.Since(start))
		utilization = report.usages["total"]
		observerLog.WriteString(fmt.Sprintf("usage during this period: %.2f (%+v)\n", utilization, report.usages))
		ipc.DisplayCPUUsage(report.before, report.after, observerLog)
		diff, total, _ := ipc.MeasureCore(report.before.All, report.after.All)
		utilization := 100 * float64(total-diff.Idle) / float64(total)

		//write to round CSV file
		var row []string
		for _, key := range categories {
			row = append(row, fmt.Sprintf("%f", report.usages[key]))
		}
		row = append(row, fmt.Sprintf("%f", report.usages["other"]),
			fmt.Sprintf("%f", report.usages["total"]))
		csvWriter.Write(row)
		csvWriter.Flush()

		//make decisions about how to conduct the next round, potentially resetting the status
		currentWork = fuzzer.getPrograms(currentWork, status, utilization)
	}

}

//observe one round until the stop timestamp and report the results
func observeRound(stopTimestamp int64, categories []string, results chan *roundReport) {
	before, _ := ipc.GetCPUReport()
	usages, iterations, _ := measureTop(stopTimestamp, KTHREADD, categories)
	after, _ := ipc.GetCPUReport()

	log.Logf(4, "Observer took %d top measurements", iterations)
	results <- &roundReport{
		before: before,
		usages: usages,
		after:  after,
	}
}

//measure CPU utilization for all children of pid until timestamp expires
func measureTop(stopTimestamp int64, pid uint64, categories []string) (map[string]float64, int, error) {
	//this runs until the command times out
	rows, iterations, err := top.GetTimed(top.DefaultExecPath, 0, stopTimestamp, 1)
	if err != nil {
		return nil, -1, err
	}

	//round up some miscellaneous PIDs from children of kthreadd that aren't running as workers
	miscPIDs, _ := ipc.GetChildrenOfPID(pid)
	usage := ipc.GetUsageOfProcs(rows, miscPIDs, categories)
	//divide out the totals to get averages across the period
	for k, v := range usage {
		usage[k] = v / float64(iterations)
	}

	return usage, iterations, nil
}

//checkAbnormal accepts a set of CPU utilizations and returns which ones are considered "abnormal" in context
//func checkAbnormal(usages map[string]float64, thresholds map[string]float64) map[string]bool {
//	abnormalProcs := map[string]bool{}
//	for k, v := range usages {
//		if t, ok := thresholds[k]; ok && v > t {
//			abnormalProcs[k] = true
//		}
//	}
//	return abnormalProcs
//}

//runs the program VERIFYATTEMPTS times and verifies abnormal behavior
//consumes a set of categories that triggered as abnormal in the initial run
//on each run, captures usage information and tracks which ones were abnormal
//removes all false-positive hits from the original set; if set becomes empty, returns nil
//else returns set of abnormal categories
//func verifyProgramAbnormality(prog *prog.Prog, f *Fuzzer, abnormal map[string]bool) map[string]bool {
//	log.Logf(4, "initial categories to check: %+v", abnormal)
//	env, _ := ipc.MakeEnv(f.config, 0)
//	results := make(chan *roundReport, 1)
//	for i := 0; i < VERIFYATTEMPTS; i++ {
//		var categories []string
//		for k := range abnormal {
//			categories = append(categories, k)
//		}
//		stopTimestamp := time.Now().Add(DURATION).UnixNano()
//		r := ipc.ContainerRestrictions{
//			Cores:         "0",
//			Usage:         0,
//			Count:         0,
//			StopTimestamp: stopTimestamp,
//		}
//
//		//observe the proc individually
//		go observeRound(stopTimestamp, categories, results)
//		env.ExecOnCore(f.execOpts, prog, &r)
//		report := <-results
//
//		latestAbnormal := checkAbnormal(report.usages, thresholds)
//		log.Logf(4, "latest run: %+v", latestAbnormal)
//		for k := range abnormal {
//			if _, ok := latestAbnormal[k]; !ok {
//				log.Logf(4, "no abnormal utilization detected on %s, eliminating", k)
//				delete(abnormal, k)
//			}
//		}
//		if len(abnormal) == 0 {
//			return nil
//		}
//	}
//	return abnormal
//}

//function that implements a state machine for the observer
//accepts the slice of current programs (with nil for each fuzzer not currently operating)
//returns a slice of work items to be completed by the corresponding indexed proc
/*
	the state machine currently has 3 states:
	shuffle -- check if the score has decreased since it was shuffled (tolerate 5% error?)
				go to mutate or drop (mutate being more likely)
	drop -- see if the current score is significantly worse than it was before (maybe half of what it
			would be if each program was contributing an equal amount of CPU usage
	mutate -- perform a mutation on a single, random program. If the score increases, keep it and go back to shuffle
*/

func (fuzzer *Fuzzer) getPrograms(currentPrograms []interface{}, status *FuzzingStatus, currentScore float64) []interface{} {
	status.roundCounter++
	percentChangeLast := (currentScore - status.lastScore) / status.lastScore * 100
	switch status.state {
	case ShufflePrograms:
		if math.Abs(percentChangeLast) > SHUFFLETOLERANCE {
			log.Logf(1, "after shuffle, results changed by more than %f percent (%.2f vs %.2f, %2.2f percent "+
				"change)", SHUFFLETOLERANCE, currentScore, status.bestScore, percentChangeLast)
			if status.roundCounter > SHUFFLECAP {
				//TODO add a stat here to indicate that we failed to converge
				log.Logf(1, "observations did not converge during shuffling, resetting")
				observerLog.WriteString("observations did not converge during shuffling. ")
				if status.best != nil {
					observerLog.WriteString("reverting to last known good program set...\n")
					changeState(status, MutatePrograms)
					return fuzzer.mutateProgram(status.best)
				} else {
					observerLog.WriteString("generating new programs...\n")
					resetState(status)
					return fuzzer.getNewPrograms(status.roundCounter)
				}
			} else {
				//hope that current round was not an outlier, and compare against it
				saveLast(status, currentPrograms, currentScore)
				observerLog.WriteString(fmt.Sprintf("adjusting target score to %.2f and retrying...\n", currentScore))
				return shufflePrograms(currentPrograms)
			}
		}
		observerLog.WriteString(fmt.Sprintf("confirmed reproducible score of %.2f\n", currentScore))

		if status.bestScore < currentScore {
			//the score we converged to is actually better!
			observerLog.WriteString(fmt.Sprintf("new best score %.2f!\n", currentScore))
			saveBest(status, currentPrograms, currentScore)
			status.roundsWithoutImprovement = 0
		} else {
			log.Logf(2, "score converged, but was not actually better than previously recorded best "+
				"(%.2f vs %.2f)", currentScore, status.bestScore)
			observerLog.WriteString(fmt.Sprintf("score converged, but was not actually better than previously recorded best "+
				"(%.2f vs %.2f)\n", currentScore, status.bestScore))
		}
		//TODO add drop back in later
		//if rand.Intn(4) == 0 {
		//	changeState(status, DropPrograms)
		//	//call drop program
		//} else {
		changeState(status, MutatePrograms)
		return fuzzer.mutateProgram(currentPrograms)
		//}
	case DropPrograms:
		//TODO double check this
		var newPrograms []interface{}
		if percentChangeLast < DROPTOLERANCE {
			//program should be put back
			log.Logf(2, "score dropped by %.2f, restoring program %d...", percentChangeLast, status.roundCounter-1)
			newPrograms = status.last
		} else {
			log.Logf(2, "score only dropped by %.2f, program %d likely insignificant",
				percentChangeLast, status.roundCounter-1)
			newPrograms = currentPrograms
			observerLog.WriteString(fmt.Sprintf("adjusting best score to %.2f...\n", currentScore))
			status.bestScore = currentScore
		}
		saveLast(status, currentPrograms, currentScore)
		if status.roundCounter == len(currentPrograms) {
			//done dropping, move to mutate
			changeState(status, MutatePrograms)
			newPrograms = fuzzer.mutateProgram(currentPrograms)
		} else {
			//drop the current program
			newPrograms = dropProgram(currentPrograms, status.roundCounter)
		}
		return newPrograms
	case MutatePrograms:
		if currentScore > status.bestScore {
			//potentially a new best, save it and switch state to shuffle
			observerLog.WriteString(fmt.Sprintf("Potentially new best score %f\n", currentScore))
			saveLast(status, currentPrograms, currentScore)
			changeState(status, ShufflePrograms)
			return shufflePrograms(currentPrograms)
		} else {
			//revert
			log.Logf(2, "reverting last mutation")
			status.roundsWithoutImprovement++
			currentPrograms = status.best
		}
		if status.roundsWithoutImprovement == MUTATECAP {
			//we've reached a local maximum, commit all programs into the corpus and get new programs
			log.Logf(1, "reached local maximum, generating new programs...")
			observerLog.WriteString("Local maximum reached: committing all programs to corpus and restarting\n")
			for i, work := range currentPrograms {
				if work, ok := work.(*WorkTriage); ok {
					fuzzer.addProgramToCorpus(work, fuzzer.procs[i].lastInfo)
				}
			}
			writeProgramsToLog(status.best)
			observerLog.WriteString(fmt.Sprintf("best score was %.2f\n", status.bestScore))
			resetState(status)
			return fuzzer.getNewPrograms(status.roundCounter)
		} else {
			//keep mutating
			saveLast(status, currentPrograms, currentScore)
			return fuzzer.mutateProgram(currentPrograms)
		}
	default:
		//save initial values, shuffle the programs and set the state to shuffle
		saveLast(status, currentPrograms, currentScore)
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
func resetState(status *FuzzingStatus) {
	status.state = -1
	status.best = nil
	status.bestScore = 0
	status.roundsWithoutImprovement = 0
	status.roundCounter = 0
	status.last = nil
	status.lastScore = 0
}

//saves the information about the last round
func saveLast(status *FuzzingStatus, programs []interface{}, score float64) {
	status.last = programs
	status.lastScore = score
}

//save information about the best round
func saveBest(status *FuzzingStatus, programs []interface{}, score float64) {
	status.best = programs
	status.bestScore = score
}

//generate a new array of programs
//attempt to take items from the workqueue. If none are available,
//generate or mutate new programs
func (fuzzer *Fuzzer) getNewPrograms(roundCounter int) []interface{} {
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
			if len(fuzzerSnapshot.corpus) == 0 || roundCounter%generatePeriod == 0 {
				// Generate a new prog.
				p = fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(1, "#%v: generated", i)
			} else {
				// Mutate an existing prog.
				p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
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
	log.Logf(3, "shuffling programs...")
	shuffled := make([]interface{}, len(current))
	copy(shuffled, current)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

//drop one program from the array, but save the existing array into the status
func dropProgram(current []interface{}, dropIndex int) []interface{} {
	log.Logf(1, "dropping program %d...", dropIndex)
	dropped := make([]interface{}, len(current))
	copy(dropped, current)
	dropped[dropIndex] = nil
	return dropped
}

//select a program at random and mutate it
//save the old array into the table
//this must perform a deep copy to avoid messing with the original array, in case we need to revert
func (fuzzer *Fuzzer) mutateProgram(current []interface{}) []interface{} {
	mutated := make([]interface{}, len(current))
	copy(mutated, current)
	var item interface{}
	var index int
	for {
		index = rand.Intn(len(fuzzer.procs))
		item = mutated[index]
		if item != nil {
			break
		}
	}
	log.Logf(2, "mutating program %d...", index)
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
		mutated[index] = &WorkTriage{
			clone,
			item.call,
			item.info,
			item.flags,
		}
	}
	return mutated
}

func (fuzzer *Fuzzer) addProgramToCorpus(item *WorkTriage, info *ipc.ProgInfo) {
	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}

	var inputCover cover.Cover
	_, thisCover := getSignalAndCover(item.p, info, item.call)
	inputCover.Merge(thisCover)

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	fuzzer.addInputToCorpus(item.p, inputSignal, sig)
}

func writeProgramsToLog(programs []interface{}) {
	for i, item := range programs {
		fmtString := "program %d\n%s\n\n"
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

func (fuzzer *Fuzzer) signalObserver() {
	atomic.AddInt32(&counter, 1)
	if atomic.CompareAndSwapInt32(&counter, int32(len(fuzzer.procs)), 0) {
		sem <- 1
	}
}
