#!/bin/bash

spid=$1

for ((i = $spid, j = 4; i <= 3, j <= 7; i++, j++)); do
    taskset -cp $j $i
    echo "----------"
done
