#!/usr/bin/env python3
import argparse


def extract_cpu_from_line(line):
    components = list(filter(None, line.split("|")))
    return float(components[3])


def parse(file, args):
    with open(file, "r") as f:
        lines = f.readlines()
        i = 0
        while i < len(lines):
            # find start of table
            if lines[i].startswith("+--"):
                cores = lines[i+3:i+15]
                total = lines[i+16]
                total = extract_cpu_from_line(total)
                cores = [extract_cpu_from_line(line) for line in cores]
                if flag_cpu_utilization(cores, total, args):
                    print(f"Violation(s) occurred at line {i} in file '{file}'\n")
                i = i + 17
            i = i + 1


# this oracle has 3 components to it
# 1: overall CPU utilization
# 2: too little utilization on a container core
# 3: too high utilization on an idle core
def flag_cpu_utilization(cores, total, args):
    flag = False
    if total >= args.thresh_total:
        print(f"Oracle thresh_total violated: utilization {total} is >= than configured threshold {args.thresh_total}")
        flag = True
    for i in range(len(cores)):
        if i < args.procs:
            # check for below active core threshold
            if cores[i] < args.thresh_active_core:
                print(f"Oracle thresh_active violated: active core {i} utilization {cores[i]} "
                      f"is less than expected minimum {args.thresh_active_core}")
                flag = True
        elif cores[i] > args.thresh_idle_core:
            if i == args.procs and cores[i] < 2.5 * args.thresh_idle_core:
                continue
            print(f"Oracle thresh_idle violated: idle core {i} utilization {cores[i]} "
                  f"is greater than expected maximum {args.thresh_idle_core}")
            flag = True
    return flag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--procs", type=int, required=True, help="number of procs")
    parser.add_argument("-tt", "--thresh-total", type=float, help="threshold for the total CPU")
    parser.add_argument("-tic", "--thresh-idle-core", type=float, default=10, help="upper threshold for an idle core")
    parser.add_argument("-tac", "--thresh-active-core", type=float, default=70, help="lower threshold for a core running a workload")
    parser.add_argument("files", nargs='+', help="file(s) to evaluate")

    args = parser.parse_args()

    print(f"Checking {len(args.files)} files...")
    for file in args.files:
        parse(file, args)

    print("Check completed.")


if __name__ == "__main__":
    main()
