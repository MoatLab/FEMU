#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Shared functions of the workload recipe runners (recipe-*-guest.sh).
# A runner sources this file from its own directory. Do not run it.
#
# A runner sets RECIPE (the prefix of its summary lines) before the first
# call. The last line of a runner is always
#
#   <RECIPE>_RESULT=PASS|FAIL|SETUP-ERROR key=value ...
#
# and the exit status is 0, 1 or 2 in that order. A runner that ends
# also writes that line to the file DONE in its scratch directory. An
# exit that no function of this file made gives SETUP-ERROR, through the
# EXIT handler below.

recipe_failed=0
recipe_done=0
recipe_workdir=
recipe_mnt=

# Run a command with a time limit of $1 seconds. A command that ignores
# the first signal gets SIGKILL after 30 more seconds.
bounded() {
    local limit=$1
    shift

    timeout -k 30 "$limit" "$@"
}

# Clean up, write the completion marker, print the result line and exit.
# A cleanup or a marker that fails does not stop the result line.
recipe_end() {
    local verdict=$1 status=$2
    shift 2
    local line="${RECIPE}_RESULT=$verdict${*:+ $*}"

    recipe_done=1
    if [[ -n $recipe_mnt ]] && mountpoint -q "$recipe_mnt"; then
        bounded 120 umount "$recipe_mnt" 2>/dev/null ||
            echo "${RECIPE}_CLEANUP=umount-failed"
    fi
    if [[ -n $recipe_workdir && -d $recipe_workdir ]]; then
        echo "$line" 2>/dev/null >"$recipe_workdir/DONE" ||
            echo "${RECIPE}_CLEANUP=no-done-file"
    fi
    echo "$line"
    exit "$status"
}

# An exit with no result line: a command failed outside of a check.
recipe_on_exit() {
    local rc=$?

    ((recipe_done)) && return
    recipe_end SETUP-ERROR 2 "reason=unexpected-exit-$rc"
}
trap recipe_on_exit EXIT

# The setup is wrong: no workload result exists.
setup_fail() {
    recipe_end SETUP-ERROR 2 "reason=$1"
}

# A check failed: record it and go on, so that one run shows each failure.
check_fail() {
    echo "${RECIPE}_FAIL=$1"
    recipe_failed=1
}

# End the run with the verdict of the checks.
recipe_finish() {
    if ((recipe_failed)); then
        recipe_end FAIL 1 "$@"
    fi
    recipe_end PASS 0 "$@"
}

# Fail the setup when the value of variable $1 is not a positive integer.
need_number() {
    local name
    for name in "$@"; do
        [[ ${!name} =~ ^[1-9][0-9]*$ ]] || setup_fail "bad-$name-${!name}"
    done
}

# Set ns_dev, ns_name, ctrl_dev and gen_dev from a namespace block device
# such as /dev/nvme0n1 or nvme0n1. RECIPE_CTRL replaces the controller.
resolve_namespace() {
    local dev=${1#/dev/}

    [[ $dev =~ ^nvme([0-9]+)n([0-9]+)$ ]] || setup_fail "bad-namespace-$dev"
    ns_name=$dev
    ns_dev=/dev/$dev
    ctrl_dev=${RECIPE_CTRL:-/dev/nvme${BASH_REMATCH[1]}}
    # shellcheck disable=SC2034  # the runners use it
    gen_dev=/dev/ng${BASH_REMATCH[1]}n${BASH_REMATCH[2]}
    [[ -b $ns_dev ]] || setup_fail "no-namespace-$dev"
    [[ -c $ctrl_dev ]] || setup_fail "no-controller-${ctrl_dev#/dev/}"
    if lsblk -nro MOUNTPOINT "$ns_dev" | grep -q .; then
        setup_fail "mounted-$dev"
    fi
}

# The FEMU counters of log page C0h, as six numbers on one line: host
# pages, GC pages, programmed pages, plane reads, reads of the most-read
# block and lines rewritten for read stress. The status is 1 when the
# device has no such log page: the recipe needs a BlackBox namespace.
c0_read() {
    local out

    out=$(bounded 60 nvme get-log "$ctrl_dev" --log-id=0xc0 --log-len=512 \
        -b 2>/dev/null |
        od -An -v -t u8 -w8 |
        awk 'NR == 2 { h = $1 } NR == 3 { g = $1 } NR == 4 { n = $1 }
             NR == 5 { m = $1 } NR == 6 { r = $1 } NR == 21 { p = $1 }
             END { if (NR == 64) print h, g, n, p, m, r }') || true
    [[ -n $out ]] || return 1
    echo "$out"
}

# Sectors of 512 bytes that the block layer read from and wrote to the
# namespace: fields 3 and 7 of its stat file.
blk_read() {
    awk '{ print $3, $7 }' "/sys/block/$ns_name/stat"
}

# Take a sample of both counter sets into the array named $1. The local
# names start with "_" so that they do not hide the array of the caller.
sample() {
    local -n _into=$1
    local _c0 _blk

    _c0=$(c0_read) || setup_fail no-c0-log
    _blk=$(blk_read) || setup_fail no-block-stat
    # shellcheck disable=SC2034  # a name reference to the caller's array
    read -r -a _into <<<"$_c0 $_blk"
}

# Print the change from the sample named $2 to the sample named $3, and
# set the d_* variables: d_host, d_gc, d_nand, d_planes (pages), d_rd,
# d_wr (bytes) and d_waf.
counter_change() {
    local name=$1
    local -n _from=$2 _to=$3

    d_host=$((_to[0] - _from[0]))
    d_gc=$((_to[1] - _from[1]))
    d_nand=$((_to[2] - _from[2]))
    d_planes=$((_to[3] - _from[3]))
    d_rd=$(((_to[6] - _from[6]) * 512))
    d_wr=$(((_to[7] - _from[7]) * 512))
    d_waf=$(awk -v h="$d_host" -v g="$d_gc" -v n="$d_nand" \
        'BEGIN { if (h > 0) printf "%.3f", (n + g) / h; else print "-" }')
    echo "${RECIPE}_COUNTERS=$name host_pages=$d_host gc_pages=$d_gc" \
        "nand_pages=$d_nand waf=$d_waf plane_reads=$d_planes" \
        "blk_read_bytes=$d_rd blk_write_bytes=$d_wr" \
        "max_block_reads=${_to[4]} read_reclaim_lines=${_to[5]}"
}

# True when $1 is at least 90% of $2.
at_least_90() {
    (($1 * 10 >= $2 * 9))
}

# Make an ext4 file system on the namespace and mount it at $1.
mount_fresh() {
    recipe_mnt=$1
    mkdir -p "$recipe_mnt" || setup_fail mkdir-mount
    bounded 600 mkfs.ext4 -q -F -E lazy_itable_init=0,lazy_journal_init=0 \
        "$ns_dev" >/dev/null 2>&1 || setup_fail mkfs
    bounded 120 mount -o noatime "$ns_dev" "$recipe_mnt" ||
        setup_fail mount
}

# Write the guest page cache to the device, with a time limit.
flush_device() {
    bounded 900 sync || setup_fail sync-status-$?
}

# Write the guest page cache to the device and drop it.
drop_caches() {
    flush_device
    bounded 300 sh -c 'echo 3 >/proc/sys/vm/drop_caches' ||
        setup_fail drop-caches
}
