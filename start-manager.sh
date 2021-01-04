#!/usr/bin/env bash

docker container prune
sudo rm -Ir workdir
mkdir workdir
taskset -c 5-11 bin/syz-manager -vv 100 -config config/docker.json 
# ADDING -debug locks the number of fuzzing procs to 1 always
