#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(grep -c processor /proc/cpuinfo)

export CROSS="ccache powerpc64le-linux-gnu-"

make -j${MAKE_J} all
make -j${MAKE_J} check
(make clean; cd external/gard && CROSS= make -j${MAKE_J})
# because some ppc64le versions don't have arm cross compiler
if which arm-linux-gnueabi-gcc; then
    ( cd external/pflash;
      echo "Building for ARM..."
      make clean && make distclean
      CROSS_COMPILE=arm-linux-gnueabi-  make || { echo "ARM build failed"; exit 1; }
    )
fi
(cd external/pflash; make clean && make distclean && make)
make clean
SKIBOOT_GCOV=1 make -j${MAKE_J}
SKIBOOT_GCOV=1 make -j${MAKE_J} check

make clean
rm -rf builddir
mkdir builddir
make SRC=$(pwd) -f ../Makefile -C builddir -j${MAKE_J}
make clean
