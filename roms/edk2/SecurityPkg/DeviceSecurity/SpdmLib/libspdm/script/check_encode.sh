#!/bin/bash

# Checks if source code files (.h, .c) are encoded as ASCII and
# use the Unix-style end-of-lines character (LF).

set -e

# Change directory to top of repository.
cd `dirname $0`
cd ../

file_list="./library ./include ./script"

for files in $(find $file_list -name '*.c' -or -name '*.h*' -or -name '*.sh' -or -name "*.txt");
do
    file_output=$(file "$files")
    echo $file_output

    if [[ $file_output != *"ASCII"* ]]; then
        echo "ERROR: File is not encoded as ASCII."
        exit 1
    fi

    if [[ $file_output == *"CRLF"* ]]; then
        echo "ERROR: File contains DOS / Windows EOL characters."
        exit 1
    fi

    if [[ $file_output == *"CR"* ]]; then
        echo "ERROR: File contains Apple / Macintosh EOL characters."
        exit 1
    fi
done
