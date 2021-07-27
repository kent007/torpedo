#!/usr/bin/env bash

taskset -c 5-11 bin/linux_amd64/syz-fuzzer -executor=/syz-executor \
  -os=linux \
  -name=vm-0 \
  -arch=amd64 \
  -manager=10.0.2.10:37839 \
  -sandbox=none \
  -procs=2 \
  -cover=false \
  -debug=false \
  -test=true \
  -vv=100
