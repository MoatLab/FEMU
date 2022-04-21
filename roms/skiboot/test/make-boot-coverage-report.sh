#!/bin/bash

# We cheat and do this in a shell script so I don't go Makefile crazy.

SKIBOOT_GCOV_ADDR=$(perl -e "printf '0x%x', 0x30000000 + 0x$(grep gcov_info_list skiboot.map|cut -f 1 -d ' ')")

LCOV_INFO_FILES=""

function process_dump {
    ./extract-gcov $1 $SKIBOOT_GCOV_ADDR
    lcov -q -b . -d . -c -o $2 --gcov-tool ${CROSS}gcov
    LCOV_INFO_FILES="$LCOV_INFO_FILES -a $2"
    find .|grep '\.gcda$'|xargs rm -f
}
    

find .|grep '\.gcda$'|xargs rm -f

for i in $BOOT_TESTS; do
    if [ -f ./external/mambo/skiboot-$i.dump ]; then
	process_dump ./external/mambo/skiboot-$i.dump skiboot-$i.info
    fi
    if [ -f ./skiboot-$i.dump ]; then
	process_dump ./skiboot-$i.dump skiboot-$i.info
    fi
done

if [ -z "$LCOV_INFO_FILES" ]; then
    echo "ERROR: no lcov files found"
    exit 1;
fi

lcov -q -b . -d . --gcov-tool ${CROSS}gcov -o skiboot-boot.info $LCOV_INFO_FILES

genhtml -o boot-coverage-report skiboot-boot.info
