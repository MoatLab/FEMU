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


export SKIBOOT_ZIMAGE=$(pwd)/test/hello_world/hello_kernel/hello_kernel

t=$(mktemp) || exit 1

trap "rm -f -- '$t'" EXIT

(
cat <<EOF | expect
set timeout 30
spawn $QEMU_BIN -bios skiboot.lid $QEMU_ARGS -kernel $SKIBOOT_ZIMAGE -nographic
expect {
timeout { send_user "\nTimeout waiting for hello world\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Could not load OPAL firmware" { send_user "\nSkiboot is too large for this Qemu, skipping\n"; exit 4; }
"Machine Check Stop" { exit 1;}
"Hello World!"
}
close
wait
exit 0
EOF
) 2>&1 > $t

r=$?
if [ $r -eq 4 ]; then
    echo "Qemu is too old and can't load a skiboot.lid this big"
    rm $T
    exit 0
fi

if [ $r != 0 ]; then
    cat $t
    exit $r
fi

if [ -n "$V" ] ; then cat "$t" ; fi
rm -f -- "$t"
trap - EXIT

exit 0;
