#!/usr/bin/env bash

bin/linux_amd64/syz-fuzzer -executor=/docker_wrapper -name=vm-0 -arch=amd64 -manager=10.0.2.10:37839 -sandbox=none -procs=1 -cover=true -debug=true -test=true -vv=100
