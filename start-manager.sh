#!/usr/bin/env bash

docker container prune
sudo rm -Ir workdir
mkdir workdir
taskset -c 9-11 bin/syz-manager -vv 1 -config config/crun.json  | tee manager.log
# ADDING -debug locks the number of fuzzing procs to 1 always
