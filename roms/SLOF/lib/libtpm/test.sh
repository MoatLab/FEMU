#!/usr/bin/env bash
cd $(dirname "$0")

CC=${HOSTCC:-gcc}
CFLAGS="-Wall -Wextra -Werror -I../../include -I../../slof -I../../lib/libc/include -DMAIN"
LDFLAGS="-lcrypto"

function fail() {
	rm -f ${EXEC}
	echo "Test failed"
	exit 1
}

function run_test() {
	local msg="$1"
	local src="$2"

	EXEC="./${src%%.c}-test"

	echo ${msg}
	${CC} ${CFLAGS} ${src} -o ${EXEC} ${LDFLAGS} || exit 1
	${EXEC} || fail
	rm -f ${EXEC}
}

run_test "SHA-1 test:" sha.c
run_test "SHA-256 test:" sha256.c
run_test "SHA-384 & SHA-512 test:" sha512.c

echo "All tests passed"
exit 0
