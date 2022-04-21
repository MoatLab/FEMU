#!/bin/bash

set -uo pipefail
set -e
set -vx

MAKE_J=$(grep -c processor /proc/cpuinfo)
export CROSS="ccache powerpc64-linux-gnu-"

make -j${MAKE_J} SKIBOOT_GCOV=1 coverage-report

pip install -r doc/requirements.txt
(cd doc; make html)

cp -r doc/ghpages-skeleton doc/_build/ghpages
mv coverage-report doc/_build/ghpages/
mv doc/_build/html doc/_build/ghpages/doc
