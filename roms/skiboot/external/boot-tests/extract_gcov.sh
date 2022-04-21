#!/bin/bash

if [ "$SKIBOOT_GCOV" != 1 ]; then
    echo "Skipping GCOV test on physical hardware. Enable with SKIBOOT_GCOV=1"
    exit 0;
fi

if [ ! -f ~/.skiboot_boot_tests ]; then
    if [ -z $FSPSSHUSER ] || [ -z $FSPSSHPASS ] ; then
	echo "Skipping extract gcov due to missing ~/.skiboot_boot_tests"
	echo "Set FSPSSHUSER and FSPSSHPASS in ~/.skiboot_boot_tests"
	exit 0;
    fi
fi

source ~/.skiboot_boot_tests

target=$1
SSHUSER=$FSPSSHUSER
SSHPASS=$FSPSSHPASS

export SSHUSER SSHPASS

SSHCMD="sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $target";
REMOTECPCMD="sshpass -e scp -o User=$SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ";

$SSHCMD rm -f skiboot-$target.dump
echo "Dumping skiboot memory from host: $target... (takes time)"
$SSHCMD sh --login -c \"getmemproc 30000000 3145728 -fb skiboot-$target.dump\"
$REMOTECPCMD $target:skiboot-$target.dump skiboot-$target.dump
