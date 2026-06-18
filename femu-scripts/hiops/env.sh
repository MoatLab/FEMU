#!/bin/bash
# Shared config + helpers for the FEMU high-IOPS socket-isolation benchmark.
# Sourced by every step script (00..04). Edit the knobs here, not in the steps.
#
# Topology (2-socket host): node0 = guest VM (vCPUs + RAM); node1 = FEMU poller
# threads + the emulated-SSD backend (mbe). Only the per-I/O emulation copy
# crosses the inter-socket link, and the two DRAM-bandwidth domains do not
# contend. This is the configuration measured in HIOPS.md.
set -u

# --- paths (EDIT THESE for your machine) -------------------------------------
FEMU_BUILD=${FEMU_BUILD:-$HOME/FEMU/build}        # dir holding qemu-system-x86_64
QEMU=$FEMU_BUILD/qemu-system-x86_64
BASE_IMG=${BASE_IMG:-$HOME/images/femu-vm.qcow2}  # a cloud guest with SPDK + fio
SEED=${SEED:-$HOME/images/seed.iso}               # cloud-init seed (user/pass femu/femu)
IMG=${IMG:-/tmp/femu-hiops-overlay.qcow2}         # COW overlay (created per run)
LOG=${LOG:-/tmp/femu-hiops.log}                   # QEMU stdout/stderr
RESULT_GUEST=/tmp/hiops-result.txt                # bench output, inside the guest

# --- VM / device knobs -------------------------------------------------------
VM_NAME=FEMU-HIOPS
SMP=${SMP:-48}                # vCPUs == IO queues == SPDK reactors; set to the
                              # guest socket's logical-CPU budget (see HIOPS.md)
MEM=${MEM:-40G}              # guest RAM (node0-bound, 1G hugepages)
DEVSZ_MB=${DEVSZ_MB:-16384}   # emulated NVMe size (the mbe backend, -> node1)
GUEST_NODE=${GUEST_NODE:-0}   # 0 = isolated (guest on node0); 1 = baseline (all node1)
SSH_PORT=${SSH_PORT:-8232}

# --- bench knobs -------------------------------------------------------------
QD=${QD:-128}
IOSIZE=${IOSIZE:-512}         # bytes (512 or 4096)
RW=${RW:-randread}
RUNSEC=${RUNSEC:-20}
# CPU mask for SPDK reactors: one bit per reactor, SMP bits set.
CPUMASK=${CPUMASK:-0x$(printf '%x' $(( (1 << SMP) - 1 )))}

# --- guest ssh ---------------------------------------------------------------
GSSH="sshpass -p femu ssh -p $SSH_PORT \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=10 femu@localhost"

# Resolve the live QEMU main process (the one with the full thread tree).
qemu_pid() {
  pgrep -f "qemu-system-x86_64 -name $VM_NAME" | while read -r p; do
    [ "$(sudo ls /proc/"$p"/task 2>/dev/null | wc -l)" -gt 10 ] && echo "$p"
  done | head -1
}
# Kill any stale VM WITHOUT matching our own shell (never `pkill -f qemu-system`).
kill_vm() { for p in $(pgrep -f "name $VM_NAME"); do sudo kill -9 "$p" 2>/dev/null; done; }
hp1g_free() { cat /sys/devices/system/node/node"$1"/hugepages/hugepages-1048576kB/free_hugepages; }
