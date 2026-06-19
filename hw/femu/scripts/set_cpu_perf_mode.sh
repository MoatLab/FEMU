#!/usr/bin/env bash

echo -n "Placing all CPUs in performance mode..."
for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
	echo -n performance > $governor
done
echo "Done"
