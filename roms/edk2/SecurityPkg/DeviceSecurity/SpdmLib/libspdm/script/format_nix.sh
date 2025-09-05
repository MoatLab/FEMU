#!/bin/bash

# Executes the Uncrustify code beautifier.
# Beautification is needed to pass the CI/CD checks for a pull request.
# This script can be run from any directory within the libspdm repository.

set -e

# Check if uncrustify is present.
if ! command -v uncrustify &> /dev/null
then
    echo "ERROR: Unable to execute uncrustify."
    exit 1
fi

# Change directory to top of repository.
cd `dirname $0`
cd ../

# Exclude non-libspdm submodules.
EXCLUDE_PATH1="./unit_test/test_size/intrinsiclib/ia32/*"
EXCLUDE_PATH2="./os_stub/mbedtlslib/mbedtls/*"
EXCLUDE_PATH3="./os_stub/openssllib/*"
EXCLUDE_PATH4="./unit_test/cmockalib/cmocka/*"

# Run uncrustify.
if [ $# -eq 0 ];
then
    find -not -path "$EXCLUDE_PATH1" -not -path "$EXCLUDE_PATH2" -not -path "$EXCLUDE_PATH3" -not -path "$EXCLUDE_PATH4" \
    \( -name "*.c" -o -name "*.h" \) -exec uncrustify -q -c ./.uncrustify.cfg --replace --no-backup {} +
    exit $?
elif [ $1 = "--check" ];
then
    find -not -path "$EXCLUDE_PATH1" -not -path "$EXCLUDE_PATH2" -not -path "$EXCLUDE_PATH3" -not -path "$EXCLUDE_PATH4" \
    \( -name "*.c" -o -name "*.h" \) -exec uncrustify -q -c ./.uncrustify.cfg --check {} +
    exit $?
else
    echo "ERROR: Unknown argument."
    exit 1
fi
