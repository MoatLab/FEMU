#!/bin/bash

QEMU_ARGS="-M powernv"
QEMU_ARGS+=" -device pcie-pci-bridge,id=bridge1,bus=pcie.1,addr=0x0"
QEMU_ARGS+=" -device ich9-ahci,id=sata0,bus=pcie.0,addr=0x0"
QEMU_ARGS+=" -device e1000e,netdev=net0,bus=bridge1,addr=0x3 -netdev user,id=net0"
QEMU_ARGS+=" -device nec-usb-xhci,bus=bridge1,addr=0x2"
QEMU_ARGS+=" -nographic"

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

if [ -z "$DISK_IMAGE" ]; then
    export DISK_IMAGE="$(pwd)/debian-11-generic-ppc64el.qcow2"
fi

WAIT_FOR="Welcome to Petitboot"

if [ -f "$DISK_IMAGE" ]; then
    QEMU_ARGS+=" -drive file=$DISK_IMAGE,if=none,id=drive0,format=qcow2,cache=none"
    QEMU_ARGS+=" -device ide-hd,bus=sata0.0,unit=0,drive=drive0,id=ide,bootindex=1"

    # TODO: Find a generic way to check that disk was read
    WAIT_FOR="(*) Debian GNU/Linux"
fi

T=$(mktemp  --tmpdir skiboot_qemu_boot_test.XXXXXXXXXX)

( cat <<EOF | expect
set timeout 600
spawn $QEMU_BIN $QEMU_ARGS -bios skiboot.lid -kernel $SKIBOOT_ZIMAGE
expect {
timeout { send_user "\nTimeout waiting for petitboot\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n"; exit 1 }
"Could not load OPAL firmware" { send_user "\nSkiboot is too large for this Qemu, skipping\n"; exit 4; }
"Machine Check Stop" { exit 1; }
"Trying to write privileged spr 338" { send_user "\nUpgrade Qemu: needs PCR register\n"; exit 3 }
"$WAIT_FOR"
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

if [ -n "$V" ] ; then cat "$T" ; fi
if [ $E -eq 0 ]; then
    rm $T
else
    echo "Boot Test FAILED. Results in $T";
fi

echo
exit $E;
