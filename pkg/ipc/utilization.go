package ipc

import (
	"fmt"
	"github.com/kent007/linux-inspect/top"
	"io/ioutil"
	"strconv"
	"strings"
)

//get all children for a particular process
//returns a map of bools, effectively implementing a set type
func GetChildrenOfPID(pid uint64) (map[int64]bool, error) {
	children := make(map[int64]bool)
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return children, fmt.Errorf("could not read file: %v", err)
	}
	pids := strings.Split(string(data), " ")
	for _, pid := range pids {
		p, err := strconv.ParseInt(pid, 10, 64)
		if err == nil {
			children[p] = true
		}
	}
	return children, nil
}

//return the summed current CPU utilization for all provided PIDs or categories
//first attempts to match the COMMAND to the category
//then falls back to using the PID map
func GetUsageOfProcs(rows []top.Row, pids map[int64]bool, categories []string) map[string]float64 {
	usages := map[string]float64{}
	for _, cat := range categories {
		// init all categories to 0
		usages[cat] = float64(0)
	}
	usages["other"] = float64(0)
	usages["total"] = float64(0)
	for _, row := range rows {
		//only interested in rows that are more than 0% CPU
		//log.Logf(4, "command: " + row.COMMAND)
		if row.CPUPercent > 0 {
			usages["total"] += row.CPUPercent
			//try to match it into a category based on COMMAND
			for _, cat := range categories {
				// found a category
				if strings.HasPrefix(row.COMMAND, cat) {
					usages[cat] += row.CPUPercent
					goto done
				}
			}
			if _, ok := pids[row.PID]; ok {
				// was a PID of interest, but not explicitly in a category
				usages["other"] += row.CPUPercent
			}
		}
	done:
	}
	return usages
}
