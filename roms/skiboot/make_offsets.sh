#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2012-2019 IBM Corp

cat <<EOF
#ifndef ASM_OFFSETS_H
#define ASM_OFFSETS_H
/* Derived from $1 by make_offsets.sh */

$(grep '#define' $1)
#endif /* ASM_OFFSETS_H */
EOF
