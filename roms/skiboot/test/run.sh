#!/bin/bash

t=$(mktemp) || exit 1

trap "rm -f -- '$t'" EXIT

$* 2>&1 > $t
r=$?
if [ $r != 0 ]; then
    cat $t
    exit $r
fi

rm -f -- "$t"
trap - EXIT
exit 0
