#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
#
# Pin a running FEMU VM's threads to host CPUs, one thread per CPU: the vCPUs
# first, then FEMU's pollers and FTL threads, starting at FIRST_CPU. The other
# QEMU threads (main loop, I/O, CXL workers) go to the CPUs after those.
#
# Threads are found by name, which Linux shows only when QEMU runs with
# -name NAME,debug-threads=on (the run-*.sh launchers pass it). The pollers
# start when the guest enables the controller, so run this after the guest has
# booted.
#
# Usage: ./pin.sh [FIRST_CPU]
#   QEMU_PID   process to pin (default: the only qemu-system-x86 process)

set -euo pipefail

die() {
    echo "pin.sh: $*" >&2
    exit 1
}

first=${1:-0}
[[ $first =~ ^[0-9]+$ ]] || die "FIRST_CPU must be a CPU number, not '$first'"
nrcpus=$(getconf _NPROCESSORS_ONLN)
sudo=()
(( EUID == 0 )) || sudo=(sudo)

if [[ -n ${QEMU_PID:-} ]]; then
    pid=$QEMU_PID
else
    mapfile -t pids < <(pgrep -x qemu-system-x86 || true)
    (( ${#pids[@]} == 1 )) ||
        die "found ${#pids[@]} qemu-system-x86 processes; set QEMU_PID"
    pid=${pids[0]}
fi
[[ -d /proc/$pid/task ]] || die "no process $pid"

# Each list holds "tid name" lines; vCPUs are sorted by vCPU index.
vcpus=$(ps -T -p "$pid" -o tid=,comm= |
        awk '$2 == "CPU" && $3 ~ /^[0-9]+\// {split($3, a, "/"); print a[1], $1}' |
        sort -n | awk '{print $2}')
femu=$(ps -T -p "$pid" -o tid=,comm= |
       awk '$2 == "femu-poller" || $2 == "FEMU-FTL-Thread" {print $1}')

[[ -n $vcpus ]] ||
    die "no 'CPU N/...' threads in $pid; start QEMU with -name NAME,debug-threads=on"
mapfile -t vcpu_tids <<< "$vcpus"
femu_tids=()
[[ -z $femu ]] || mapfile -t femu_tids <<< "$femu"
if ! ps -T -p "$pid" -o comm= | awk '$1 == "femu-poller" {f = 1} END {exit !f}'; then
    echo "pin.sh: no femu-poller thread yet; the guest has not enabled the controller" >&2
fi

need=$(( ${#vcpu_tids[@]} + ${#femu_tids[@]} ))
(( first + need <= nrcpus )) ||
    die "need CPUs $first to $(( first + need - 1 )), the host has 0 to $(( nrcpus - 1 ))"

# Move every thread first, so the per-thread pins below are not overwritten.
rest=$(( first + need ))
if (( rest < nrcpus )); then
    "${sudo[@]}" taskset -apc "$rest-$(( nrcpus - 1 ))" "$pid" > /dev/null
    echo "other QEMU threads -> CPUs $rest-$(( nrcpus - 1 ))"
else
    echo "no CPUs left for the other QEMU threads; they stay where they are"
fi

cpu=$first
for tid in "${vcpu_tids[@]}" "${femu_tids[@]}"; do
    "${sudo[@]}" taskset -pc "$cpu" "$tid" > /dev/null
    echo "$(cat "/proc/$pid/task/$tid/comm") (tid $tid) -> CPU $cpu"
    cpu=$(( cpu + 1 ))
done
