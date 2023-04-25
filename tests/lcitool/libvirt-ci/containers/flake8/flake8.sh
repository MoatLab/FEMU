#!/bin/sh

flake8

if test "$?" != "0"
then
    echo
    echo "❌ ERROR: some files failed flake8 code style check"
    echo
    echo "See the flake8.txt artifact for full details of mistakes."
    echo

    flake8 --show-source > flake8.txt
    exit 1
fi

echo "✔ OK: all files passed flake8 code style check"
