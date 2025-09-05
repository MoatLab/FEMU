#!/bin/bash

# Check if the modified files' copyright dates are current.

set -e

# Change directory to top of repository.
cd `dirname $0`
cd ../

# Get list of changed files.
git fetch origin main
modified_files=$(git diff --name-only --diff-filter=AM origin/main..HEAD)

current_year=$(date +%Y)
exit_code=0

echo

for file in $modified_files
do
    # Only examine C files for now.
    if [[ $file == "include/"* ]] || [[ $file == "library/"* ]]; then
        if [[ $file == *".h" ]] || [[ $file == *".c" ]]; then
            # Assume that the copyright is located at the third line of the file.
            if [[ $(sed -n '3p' $file) != *$current_year* ]]; then
                echo $file needs to be updated with $current_year copyright.
                exit_code=1
            fi
        fi
    fi
done

exit $exit_code
