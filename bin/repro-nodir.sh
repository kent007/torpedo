#!/usr/bin/env bash

echo "running program $1 $2 times"

for i in $(seq 1 $2)
do
	$1
done
