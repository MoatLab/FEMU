#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Takes /dev/stdin as dtb, saves to file, does dtdiff
# Also runs parameter through a dts->dtb->dts conversion
# in order to work around dtc bugs.
#
# Copyright 2018 IBM Corp.

T=$(mktemp)
cp /dev/stdin $T.dtb
dtc -I dts -O dtb $1 > $T.orig.dtb
dtdiff $T.orig.dtb $T.dtb
R=$?
if [ $R == 0 ]; then rm -f $T $T.orig.dtb $T.dtb; fi
exit $R
