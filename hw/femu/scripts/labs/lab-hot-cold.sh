#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# FEMU lab 2, hot and cold data (hw/femu/docs/labs/lab2-hot-and-cold.md).
# Run in the guest, as root, on a fresh device:
#
#   sudo bash lab-hot-cold.sh uniform|zipf|hot80
#
#   uniform  every 4 KiB page has the same chance of a write
#   zipf     fio --random_distribution=zipf:1.2
#   hot80    80% of the writes go to the first 20% of the namespace
#            (fio --random_distribution=zoned:80/20:20/80)
#
# The method is the one of lab 1: fill, age with 4 GiB of the workload,
# then measure one more 4 GiB run. The last line is
#   LAB2 workload=... host=... gc=... nand=... waf=... check=ok

set -euo pipefail
here=$(dirname "$0")

case ${1:-} in
uniform) dist=() ;;
zipf) dist=(--random_distribution=zipf:1.2) ;;
hot80) dist=(--random_distribution=zoned:80/20:20/80) ;;
*)
    echo "usage: sudo bash $0 uniform|zipf|hot80" >&2
    exit 2
    ;;
esac

LAB_DIR=${LAB_DIR:-./lab-out}/$1
export LAB_DIR
out=$(bash "$here/lab-gc-waf.sh" "${dist[@]}")
echo "LAB2 workload=$1 ${out#LAB1 }"
