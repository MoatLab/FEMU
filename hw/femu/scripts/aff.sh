#!/bin/bash

spid=$1

for ((i = spid, j = 5; i <= spid + 19; i++, j++)); do
    taskset -cp $j $i
    echo "----------"
done
