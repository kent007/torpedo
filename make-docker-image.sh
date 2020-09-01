#!/usr/bin/env bash

docker build --build-arg OS=$1 --build-arg ARCH=$2 -f Dockerfile -t syzkaller-image bin/
