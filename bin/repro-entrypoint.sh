#!/usr/bin/env bash

echo "running program $1 $2 times"

for i in $(seq 1 $2)
do
	dir="/tmp/syzkaller.$i"
	mkdir $dir
	cd $dir
	$1
done
