#!/usr/bin/env bash
bin/test_64/syz-fuzzer -executor=/syz-executor -name=vm-0 -os=test -arch=64 -manager=10.0.22.10:37839 -sandbox=none -procs=1 -cover=false -debug=true -test=true -vv=100
