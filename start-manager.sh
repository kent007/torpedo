#!/usr/bin/env bash

docker container prune
sudo rm -Ir workdir
mkdir workdir
bin/syz-manager -vv 100 -config config/docker.json -debug
