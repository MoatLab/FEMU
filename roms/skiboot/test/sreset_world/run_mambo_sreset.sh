#!/bin/bash


if [ -z "$MAMBO_PATH" ]; then
    MAMBO_PATH=/opt/ibm/systemsim-p8/
fi

if [ -z "$MAMBO_BINARY" ]; then
    MAMBO_BINARY="/run/pegasus/power8"
fi

if [ ! -x "$MAMBO_PATH/$MAMBO_BINARY" ]; then
    echo "Could not find executable MAMBO_BINARY ($MAMBO_PATH/$MAMBO_BINARY). Skipping sreset_world test";
    exit 0;
fi

if [ -n "$KERNEL" ]; then
    echo 'Please rebuild skiboot without KERNEL set. Skipping sreset_world test';
    exit 0;
fi

if [ ! $(command -v expect) ]; then
    echo 'Could not find expect binary. Skipping sreset_world test';
    exit 0;
fi

if [ -n "$SKIBOOT_ENABLE_MAMBO_STB" ]; then
    export SKIBOOT_ZIMAGE=$(pwd)/test/sreset_world/sreset_kernel/sreset_kernel.stb
else
    export SKIBOOT_ZIMAGE=$(pwd)/test/sreset_world/sreset_kernel/sreset_kernel
fi

# Currently getting some core dumps from mambo, so disable them!
ulimit -c 0

t=$(mktemp) || exit 1

trap "rm -f -- '$t'" EXIT

( cd external/mambo; 
cat <<EOF | expect
set timeout 30
spawn $MAMBO_PATH/$MAMBO_BINARY -n -f ../../test/sreset_world/run_sreset_world.tcl
expect {
timeout { send_user "\nTimeout waiting for hello world\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n"; exit 1 }
"Machine Check Stop" { exit 1;}
"Hello World!"
}
expect {
timeout { send_user "\nTimeout waiting for Hello SRESET\n"; exit 1 }
eof { send_user "\nUnexpected EOF\n"; exit 1 }
"Machine Check Stop" { exit 1;}
"Hello SRESET!"
}
expect {
timeout { send_user "\nTimeout waiting for shutdown\n"; exit 1}
eof { send_user "\nUnexpected EOF\n"; exit 1}
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
