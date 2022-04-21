#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(grep -c processor /proc/cpuinfo)
export CROSS="ccache powerpc64-linux-gnu-"

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
