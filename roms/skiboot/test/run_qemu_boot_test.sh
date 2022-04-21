#!/bin/bash

QEMU_ARGS="-M powernv -nodefaults -device ipmi-bmc-sim,id=bmc0 -serial none"
QEMU_ARGS+=" -device isa-serial,chardev=s1 -chardev stdio,id=s1,signal=off"

if [ -z "$QEMU_BIN" ]; then
    QEMU_BIN="qemu-system-ppc64"
fi

if [ ! $(command -v $QEMU_BIN) ]; then
    echo "Could not find executable QEMU_BIN ($QEMU_BIN). Skipping hello_world test";
    exit 0;
fi

if [ -n "$KERNEL" ]; then
    echo 'Please rebuild skiboot without KERNEL set. Skipping hello_world test';
    exit 0;
fi

if [ ! $(command -v expect) ]; then
    echo 'Could not find expect binary. Skipping hello_world test';
    exit 0;
fi

if [ -z "$SKIBOOT_ZIMAGE" ]; then
    export SKIBOOT_ZIMAGE=$(pwd)/zImage.epapr
fi

if [ ! -f "$SKIBOOT_ZIMAGE" ]; then
    echo "No $SKIBOOT_ZIMAGE, skipping boot test";
    exit 0;
fi

T=$(mktemp  --tmpdir skiboot_qemu_boot_test.XXXXXXXXXX)

( cat <<EOF | expect
set timeout 600
spawn $QEMU_BIN $QEMU_ARGS -bios skiboot.lid -kernel $SKIBOOT_ZIMAGE
expect {
timeout { send_user "\nTimeout waiting for petitboot\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Could not load OPAL firmware" { send_user "\nSkiboot is too large for this Qemu, skipping\n"; exit 4; }
"Machine Check Stop" { exit 1; }
"Trying to write privileged spr 338" { send_user "\nUpgrade Qemu: needs PCR register\n"; exit 3 }
"Welcome to Petitboot"
}
close
wait
exit 0
EOF
) 2>&1 > $T
E=$?

if [ $E -eq 4 ]; then
    echo "Qemu is too old and can't load a skiboot.lid this big"
    rm $T
    exit 0
fi

if [ $E -eq 3 ]; then
    echo "WARNING: Qemu test not run; upgrade QEMU to one that supports PCR register";
    rm $T
    exit 0;
fi

if [ -n "$V" ] ; then cat "$t" ; fi
if [ $E -eq 0 ]; then
    rm $T
else
    echo "Boot Test FAILED. Results in $T";
fi

echo
exit $E;
