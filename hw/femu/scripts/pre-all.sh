#!/bin/bash

# Turn on eth1
ssh m  "sudo ifconfig eth1 192.168.8.30/24 up"
ssh s1 "sudo ifconfig eth1 192.168.8.31/24 up"
ssh s2 "sudo ifconfig eth1 192.168.8.32/24 up"

# ready the FS on NVMe
ssh m  "bash -s" < ./pre.sh
ssh s1 "bash -s" < ./pre.sh
ssh s2 "bash -s" < ./pre.sh
echo "----------m"
ssh m  "df -h"
echo "----------s1"
ssh s1 "df -h"
echo "----------s2"
ssh s2 "df -h"


