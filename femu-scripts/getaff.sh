#!/bin/bash

pname="qemu"  # for example
for pid in $(pgrep "${pname}")
do 
    [ "${pid}" != "" ] || exit
    echo "PID: ${pid}"
    for tid in \
      $(ps --no-headers -ww -p "${pid}" -L -olwp | sed 's/$/ /' | tr  -d '\n')
    do
    taskset -cp "${tid}"   # substitute thread id in place of a process id
    done
done
