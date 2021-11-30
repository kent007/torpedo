#!/usr/bin/env bash

docker container prune
sudo rm -Ir workdir
mkdir workdir
sudo taskset -c 9-11 bin/syz-manager -vv 100 -config config/gvisor.json 2>&1 | tee manager.log
# ADDING -debug locks the number of fuzzing procs to 1 always
