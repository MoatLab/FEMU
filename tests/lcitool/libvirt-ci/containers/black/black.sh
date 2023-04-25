#!/bin/sh

black --diff . > black.txt

if test -s black.txt
then
    echo
    echo "❌ ERROR: some files failed black code formatting check"
    echo
    echo "See the black.txt artifact for full details of mistakes."
    echo
    exit 1
fi

echo "✔ OK: all files passed black code formatting check"
