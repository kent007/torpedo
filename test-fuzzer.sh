#!/usr/bin/env bash

bin/linux_amd64/syz-fuzzer -executor=/syz-executor \
  -name=vm-0 \
  -arch=amd64 \
  -manager=10.0.2.10:37839 \
  -sandbox=none \
  -procs=1 \
  -cover=false \
  -debug=true \
  -test=true \
  -vv=100
