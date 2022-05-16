#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Script to build all pflash backends
#
# Copyright 2015 IBM Corp.
#
# pflash has three different backends that are used on powerpc, arm (BMC) and
# x86 (file-backed). In order to test for regressions when touching shared code
# such as libflash.
#
# Defaults to the cross compilers available under Ubuntu. You can set the
# environment variables arm_cc, amd64_cc, ppc64le_cc for other distributions.
#
# installing on x86:
#   apt-get install gcc-arm-linux-gnueabi gcc-powerpc64le-linux-gnu gcc
#

arm_cc=${arm_cc:-arm-linux-gnueabi-}
amd64_cc=${amd64_cc:-x86_64-linux-gnu-}
ppc64le_cc=${ppc64le_cc:-powerpc64le-linux-gnu-}

echo "Building for ARM..."
make clean && make distclean
CROSS_COMPILE=${arm_cc}  make || { echo "ARM build failed"; exit 1; }

echo "Building for x86..."
make clean && make distclean
CROSS_COMPILE=${amd64_cc} make || { echo "x86 build failed"; exit 1; }

echo "Building for ppc64le..."
make clean && make distclean
CROSS_COMPILE=${ppc64le_cc} make || { echo "ppc64le build failed"; exit 1; }

make clean && make distclean
