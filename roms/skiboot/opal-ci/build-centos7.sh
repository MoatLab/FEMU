#!/bin/bash

set -uo pipefail
set -e
set -vx

# We're limited as to what we want to bother to run on CentOS7
# It's fairly old and some of the things (e.g. build+run qemu) we don't
# want to bother doing.
if [ $(arch) == "x86_64" ]; then
    export CROSS=/opt/cross/gcc-8.1.0-nolibc/powerpc64-linux/bin/powerpc64-linux-
fi
# Note that this doesn't work on centos7 because "/lib64/ld64.so.2: version `GLIBC_2.22' not found"
if [ $(arch) == "ppc64le" ]; then
    export CROSS=/opt/cross/gcc-8.1.0-nolibc/powerpc64-linux/bin/powerpc64-linux-
fi

MAKE_J=$(grep -c processor /proc/cpuinfo)

make -j${MAKE_J} all
make -j${MAKE_J} check
(make clean; cd external/gard && CROSS= make -j${MAKE_J})
(cd external/pflash; make -j${MAKE_J})
make clean
SKIBOOT_GCOV=1 make -j${MAKE_J}
SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC=$(pwd) -f ../Makefile -C builddir -j${MAKE_J}
make clean
