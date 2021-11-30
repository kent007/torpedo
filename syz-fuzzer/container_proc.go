package main

import (
	"fmt"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"os"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	//eventually this should be decided using the number of available cores
	MAXPROGRAMS = 3
	//max usage for an individual core
	MAXUSAGE = 0.8
	//max amount of noise we want to tolerate from the system, as a percent
	NOISE = 0.02

	//for triaging, how many times to run the container
	RUNCOUNT = 50

	//minimization attempts
	MINATTEMPTS = 3

	//smash attempts
	SMASHATTEMPTS = 50
)

//when this function returns, we may execute our work for the round
func (proc *Proc) synchronizeWithObserver() {
	//inform observer proc is primed to execute
	proc.procGroup.Done()

	//wait for observer to release us
	proc.observer.Wait()
	log.Logf(4, "Proc %d: beginning round at %d", proc.pid, time.Now().UnixNano())

	//increment by 1 to synchronize with observer for start of next round
	proc.procGroup.Add(1)

	//we're released, inform observer we are running
	proc.fuzzer.signalObserver()
}

func (proc *Proc) loopSynchronized(runtime string, capabilities string) {
	r := &ipc.ContainerRestrictions{
		Cores:         strconv.Itoa(proc.pid),
		Usage:         1.0,
		Count:         0,
		StopTimestamp: 0,
		Runtime:       runtime,
		Capabilities:  capabilities,
	}
	for {
		proc.fuzzer.signalObserver()
		item := <-proc.programSelector
		//if nil, observer has instructed us to sit out this round
		if item == nil {
			log.Logf(1, "Proc %d: idling this round", proc.pid)
			proc.synchronizeWithObserver()
			cmd := ipc.MakeIdleCommand(proc.stopTimestamp, strconv.Itoa(proc.pid))
			_ = cmd.Run()
			continue
		}
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageContainerSynchronized(item, r)
			case *WorkCandidate:
				proc.executeSynchronized(proc.execOpts, item.p, item.flags, StatCandidate, r)
				//added a flag to prevent additional triage items from being created
				item.flags |= ProgTriaged
			//case *WorkSmash:
			//	//proc.smashInput(item)
			//	//proc.smashByKernelTime(item)
			//	proc.smashByKthreadD(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}
	}
}

func (proc *Proc) loopIdle() {
	for {
		proc.fuzzer.signalObserver()
		<-proc.programSelector

		proc.synchronizeWithObserver()

		cmd := ipc.MakeIdleCommand(proc.stopTimestamp, strconv.Itoa(proc.pid))
		_ = cmd.Run()
		log.Logf(4, "Proc %d: round ended at %d", proc.pid, time.Now().UnixNano())
	}
}

// this is essentially the same as ExecuteRaw, but without retry checking in the event of failure
func (proc *Proc) executeOnCoreSynchronized(opts *ipc.ExecOpts, p *prog.Prog, stat Stat, r *ipc.ContainerRestrictions) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.synchronizeWithObserver()

	//grab the latest timestamp
	r.StopTimestamp = proc.stopTimestamp

	//!!this is required for the manager to track execution
	proc.logProgram(opts, p)

	atomic.AddUint64(&proc.fuzzer.stats[stat], 1)

	output, info, hanged, err := proc.env.ExecOnCore(opts, p, r)
	log.Logf(4, "Proc %d: round ended at %d", proc.pid, time.Now().UnixNano())
	if err != nil {
		log.Logf(4, "fuzzer detected executor failure='%v'", err)
		debug.FreeOSMemory()
	}
	log.Logf(2, "result hanged=%v: %s", hanged, output)
	proc.lastInfo<-info

	return info
}

//lockstep triage operation
//record new coverage, observer will look for abnormal resource usage
//this basically does nothing now, since all the functionality was migrated to the observer
//FIXME does NOT create smash items, may want to experiment with this in the future
func (proc *Proc) triageContainerSynchronized(item *WorkTriage, r *ipc.ContainerRestrictions) {

	//execute in lockstep
	proc.executeOnCoreSynchronized(proc.execOptsCover, item.p, StatTriage, r)

	//do NOT enqueue a smash item
}

func (proc *Proc) smashContainerSynchronized(item *WorkSmash, r *ipc.ContainerRestrictions) {
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < SMASHATTEMPTS; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeOnCoreSynchronized(proc.execOpts, p, StatSmash, r)
	}
}

//normal candidate execution in lockstep
//creates triage items if the ProgTriaged flag is not set
func (proc *Proc) executeSynchronized(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat,
	r *ipc.ContainerRestrictions) *ipc.ProgInfo {
	info := proc.executeOnCoreSynchronized(execOpts, p, stat, r)
	if flags&ProgTriaged == 0 {
		//FIXME nil'd out this information here, will iterate through the calls on a single item instead
		proc.enqueueCallTriage(p, flags, -2, info.Calls[0])
		//calls, extra := proc.fuzzer.checkNewSignal(p, info)
		//for _, callIndex := range calls {
		//	proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
		//}
		//if extra {
		//	proc.enqueueCallTriage(p, flags, -1, info.Extra)
		//}
	}
	return info
}

type pidUsage struct {
	usage   map[string]float64
	samples int
	time    time.Duration
}

//execute a process and return the amount of CPU used by a process and all of its descendants
//during execution. This is especially useful for measuring the impact on kernel worker threads, the docker engine,
//and systemd
//func (proc *Proc) executeAndGetUsageOfProcs(opts *ipc.ExecOpts, p *prog.Prog, stat Stat,
//	r *ipc.ContainerRestrictions, pid uint64) (*pidUsage, *ipc.ProgInfo) {
//
//	stop := make(chan bool)
//	response := make(chan *pidUsage)
//	categories := []string{"[ksoftirq", "[kworker",
//		"/usr/bin/dockerd", "/usr/bin/containerd", "containerd-shim",
//		"[kaudit", "/sbin/auditd", "/lib/systemd/systemd-journald"}
//
//	//start an async function
//	go func (response chan *pidUsage, pid uint64) {
//		iterations := 0
//		start := time.Now()
//		totals := make(map[string]float64)
//
//		for {
//			select {
//			case <- stop:
//				// divide out the iterations to get an average
//				for k, v := range totals {
//					totals[k] = v / float64(iterations)
//				}
//				response <- &pidUsage{
//					usage:      totals,
//					samples:    iterations,
//					time:       time.Since(start),
//				}
//				return
//			default:
//				children, err := ipc.GetChildrenOfPID(pid)
//				if err != nil {
//					//TODO something
//				}
//				usage, err := ipc.GetUsageOfProcs(children, categories)
//				if err != nil {
//					//TODO something
//				}
//				// sum all new percentage data for this collection
//				for k, v := range usage {
//					totals[k] += v
//				}
//				iterations++
//			}
//		}
//	}(response, pid)
//	info := proc.executeOnCoreSynchronized(opts, p, stat, r)
//	stop <- true
//	usage := <-response
//	return usage, info
//}

func (proc *Proc) executeAndGetReport(opts *ipc.ExecOpts, p *prog.Prog, stat Stat,
	r *ipc.ContainerRestrictions) (*ipc.CPUReport, *ipc.CPUReport, *ipc.ProgInfo) {
	before, _ := ipc.GetCPUReport()
	info := proc.executeOnCoreSynchronized(opts, p, stat, r)
	after, _ := ipc.GetCPUReport()
	return before, after, info
}

// uses CPU utilization of kthreadd and children as a metric to drive fuzzing
//func (proc *Proc) smashByKthreadD(item *WorkSmash) {
//
//	fuzzerSnapshot := proc.fuzzer.snapshot()
//	f, _ := os.OpenFile("max_run_log_kthreadd_" +strconv.Itoa(proc.pid), os.O_CREATE | os.O_WRONLY | os.O_APPEND, 0666)
//
//
//	//run the program once to baseline the usage
//	r := &ipc.ContainerRestrictions{
//		Cores: strconv.Itoa(proc.pid),
//		Usage:   1.0,
//		Count:   RUNCOUNT,
//		StopTimestamp: 0,
//	}
//	maxBefore, _ := ipc.GetCPUReport()
//	maxResults, _ := proc.executeAndGetUsageOfProcs(proc.fuzzer.execOpts, item.p, StatSmash, r, KTHREADD)
//	maxAfter, _ := ipc.GetCPUReport()
//	maxPercentKthread := maxResults.usage["total"]
//	maxProg := item.p
//
//	f.Write([]byte("\n=============\n"))
//	f.Write([]byte(fmt.Sprintf("initial program utilization %.2f\n", maxPercentKthread)))
//	f.Write([]byte(fmt.Sprintf("%+v\n\n", maxResults)))
//	ipc.DisplayCPUUsage(maxBefore, maxAfter, f)
//	f.Write(maxProg.Serialize())
//
//	for i := 0; i < SMASHATTEMPTS; i++ {
//		p := item.p.Clone()
//		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
//		//the mutation has the same call in the same location
//		if p.ContainsCall(item.p.Calls[item.call], item.call) {
//			//do some tests on CPU usage and record a maximum
//			//save maximum to a separate queue
//
//			thisBefore, _ := ipc.GetCPUReport()
//			results, _ := proc.executeAndGetUsageOfProcs(proc.fuzzer.execOpts, item.p, StatSmash, r, KTHREADD)
//			thisAfter, _ := ipc.GetCPUReport()
//			thisPercentKthread := results.usage["total"]
//
//			if thisPercentKthread > maxPercentKthread {
//				maxProg = p
//				maxPercentKthread = thisPercentKthread
//				maxResults = results
//				maxBefore = thisBefore
//				maxAfter = thisAfter
//				//f.Write([]byte(fmt.Sprintf("new max: %+v\n", maxResults)))
//			}
//		}
//		proc.fuzzer.workQueue.enqueue(&WorkCandidate{
//			p:     p,
//			flags: ProgCandidate,
//		})
//	}
//
//	f.Write([]byte(fmt.Sprintf("\nobtained maximal program with utilization %.2f\n", maxPercentKthread)))
//	f.Write([]byte(fmt.Sprintf("%+v\n", maxResults)))
//	ipc.DisplayCPUUsage(maxBefore, maxAfter, f)
//	f.Write(maxProg.Serialize())
//}

/*
Want to drive CPU utilization as high as possible for program that contains the call we're interested in
Mutation has the chance to remove the call, so

Mutate some number of times
If the program contains the same call, run and keep track of CPU utilization. The highest
program can be put onto another queue for later OOB hunting

always re-enqueue the new programs as candidates to keep the fuzzer going
*/
func (proc *Proc) smashByKernelTime(item *WorkSmash) {

	fuzzerSnapshot := proc.fuzzer.snapshot()
	f, _ := os.OpenFile("max_run_log_kerneltime_"+strconv.Itoa(proc.pid), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	//run the program once to baseline the percentage
	r := &ipc.ContainerRestrictions{
		Cores:         strconv.Itoa(proc.pid),
		Usage:         1.0,
		Count:         RUNCOUNT,
		StopTimestamp: 0,
	}

	maxBefore, maxAfter, _ := proc.executeAndGetReport(proc.fuzzer.execOpts, item.p, StatSmash, r)

	//calc percentage spent in kernel time
	report, total, _ := ipc.MeasureCore(maxBefore.Cpus[proc.pid], maxAfter.Cpus[proc.pid])
	maxPercent := float64(report.System) / float64(total-report.Idle)
	maxProg := item.p

	f.Write([]byte("\n=============\n"))
	f.Write([]byte(fmt.Sprintf("initial program utilization %.2f\n", maxPercent)))
	ipc.DisplayCPUUsage(maxBefore, maxAfter, f)
	f.Write(maxProg.Serialize())

	for i := 0; i < SMASHATTEMPTS; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		//the mutation has the same call in the same location
		if p.ContainsCall(item.p.Calls[item.call], item.call) {
			//do some tests on CPU usage and record a maximum
			//save maximum to a separate queue

			before, after, _ := proc.executeAndGetReport(proc.fuzzer.execOpts, p, StatSmash, r)
			report, total, _ := ipc.MeasureCore(before.Cpus[proc.pid], after.Cpus[proc.pid])
			thisPercentKernel := float64(report.System) / float64(total-report.Idle)
			//f.Write([]byte(fmt.Sprintf("percent usage of mutation: %.2f\n", thisPercentKernel)))
			if thisPercentKernel > maxPercent {
				maxProg = p
				maxPercent = thisPercentKernel
				maxBefore = before
				maxAfter = after
			}
		}
		proc.fuzzer.workQueue.enqueue(&WorkCandidate{
			p:     p,
			flags: ProgCandidate,
		})
	}

	f.Write([]byte(fmt.Sprintf("\nobtained maximal program with utilization %.2f\n", maxPercent)))
	ipc.DisplayCPUUsage(maxBefore, maxAfter, f)
	f.Write(maxProg.Serialize())
}
