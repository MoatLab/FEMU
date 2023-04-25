#!/bin/bash

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"

make clean
# --disable-werror --extra-cflags=-w --disable-git-update
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp
make -j $NRCPUS

echo ""
echo "===> FEMU compilation done ..."
echo ""
exit
