#!/bin/bash

if [ -z "$P10MAMBO_PATH" ]; then
    P10MAMBO_PATH=/opt/ibm/systemsim-p10-1.1-0
fi

if [ -z "$P10MAMBO_BINARY" ]; then
    P10MAMBO_BINARY="run/p10/power10"
fi

if [ ! -x "$P10MAMBO_PATH/$P10MAMBO_BINARY" ]; then
    echo "Could not find executable P10MAMBO_BINARY ($P10MAMBO_PATH/$P10MAMBO_BINARY). Skipping hello_world test";
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

if [ -n "$SKIBOOT_ENABLE_MAMBO_STB" ]; then
    export SKIBOOT_ZIMAGE=$(pwd)/test/hello_world/hello_kernel/hello_kernel.stb
    export SKIBOOT_CVC_CODE=$(pwd)/external/mambo/cvc.bin
else
    export SKIBOOT_ZIMAGE=$(pwd)/test/hello_world/hello_kernel/hello_kernel
fi

# Currently getting some core dumps from mambo, so disable them!
ulimit -c 0

t=$(mktemp) || exit 1

trap "rm -f -- '$t'" EXIT

( cd external/mambo;
cat <<EOF | expect
set timeout 30
spawn $P10MAMBO_PATH/$P10MAMBO_BINARY -n -f ../../test/hello_world/run_hello_world.tcl
expect {
timeout { send_user "\nTimeout waiting for hello world\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n;" exit 1 }
"Machine Check Stop" { exit 1;}
"Execution stopped: Sim Support exit requested stop"
}
wait
exit 0
EOF
) 2>&1 > $t

r=$?
if [ $r != 0 ]; then
    cat $t
    exit $r
fi

if [ -n "$V" ] ; then cat "$t" ; fi
rm -f -- "$t"
trap - EXIT
exit 0;
