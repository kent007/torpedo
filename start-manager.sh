#!/usr/bin/env bash

docker container prune
sudo rm -Ir workdir
mkdir workdir
bin/syz-manager -vv 100 -config bin/configs/docker-host-config.json -debug
