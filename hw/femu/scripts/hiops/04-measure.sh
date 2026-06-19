#!/bin/bash
# Step 4: run the measured benchmark inside the guest and print the result.
#   ENGINE=bdevperf bash 04-measure.sh   # SPDK bdevperf -C (default)
#   ENGINE=fio      bash 04-measure.sh   # fio with the SPDK nvme plugin
# Override IOSIZE/RW/QD/RUNSEC via env (see env.sh). slirp can wedge under load,
# so the bench writes to a guest file that we read back after it finishes.
cd "$(dirname "$0")" && . ./env.sh
ENGINE=${ENGINE:-bdevperf}

if [ "$ENGINE" = fio ]; then
  # One fio job (= one SPDK qpair) per reactor core; batch submit/complete so
  # fio's per-I/O accounting does not become the bottleneck (without batching
  # fio+SPDK tops out well below the device's capability).
  $GSSH "DEV=\$(lspci -d 1d1d: | awk '{print \$1}'); sudo pkill -9 fio bdevperf 2>/dev/null; sleep 2
cat > /tmp/hiops.fio <<EOF
[global]
ioengine=spdk
thread=1
group_reporting=1
direct=1
norandommap=1
randrepeat=0
time_based=1
runtime=$RUNSEC
rw=$RW
bs=$IOSIZE
iodepth=256
iodepth_batch_submit=64
iodepth_batch_complete_min=64
iodepth_batch_complete_max=256
numjobs=$SMP
cpus_allowed=0-$((SMP-1))
[test]
filename=trtype=PCIe traddr=0000.\${DEV//:/.} ns=1
EOF
sudo LD_PRELOAD=\$HOME/spdk/build/fio/spdk_nvme fio /tmp/hiops.fio > $RESULT_GUEST 2>&1
echo fio-done"
  echo "=== RESULT (fio + SPDK plugin, $IOSIZE B $RW) ==="
  $GSSH "grep -aiE 'read: IOPS|write: IOPS|err= ' $RESULT_GUEST | head -2"
else
  $GSSH "sudo pkill -9 fio bdevperf 2>/dev/null; sleep 2
nohup sudo ~/spdk/build/examples/bdevperf -m $CPUMASK -q $QD -o $IOSIZE -w $RW -t $RUNSEC -C --json /tmp/bj > $RESULT_GUEST 2>&1 </dev/null & echo measure-launched"
  WAIT=$((RUNSEC + 20)); echo "bench running ${RUNSEC}s; waiting ${WAIT}s ..."; sleep $WAIT
  echo "=== RESULT (SPDK bdevperf -C, $IOSIZE B $RW; column 2 of Total = IOPS) ==="
  $GSSH "grep -aE 'Total +:' $RESULT_GUEST | tail -1"
  echo "--- errors (should be empty) ---"
  $GSSH "grep -aiE 'error|claimed|failed' $RESULT_GUEST | head -3"
fi
