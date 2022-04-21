#!/bin/sh

set -e

DATA=$(mktemp)

cleanup() {
	rm -f $DATA
}

trap cleanup EXIT

dd if=/dev/zero of=$DATA bs=$((0x1000)) count=5 2>/dev/null

run_binary "./opal-gard" "-p -e -f $DATA clear all"
run_binary "./opal-gard" "-p -e -f $DATA create /sys0/node0/proc1"
run_binary "./opal-gard" "-p -e -f $DATA list"
run_binary "./opal-gard" "-p -e -f $DATA clear 00000001"
run_binary "./opal-gard" "-p -e -f $DATA list"

diff_with_result

pass_test
