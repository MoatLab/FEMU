#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(nproc)

make -j${MAKE_J} CC=clang
make -j${MAKE_J} CC=clang check
