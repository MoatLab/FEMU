#!/bin/bash -uex
#
# this is a really dumb script for auto-generating test cases from known good-data
#
# usage: ./add_test <pass|fail> <inputfile> <testname> [opal-gard subcommand]
#
# e.g.
#      ./add_test.sh fail blank.bin create-bad-instance create /sys256
#      ./add_test.sh pass blank.bin create-normal create /sys0/node0/proc0
#
# this will generate a test script file and writes the stdout/stderr of the command
# to the respective files.
#

cd $(dirname $(realpath $0))/../
echo $PWD

if [ "$1" = "pass" ]; then
	check='if [ "$?" -ne 0 ]; then'
	test_type="pass"
else
	check='if [ "$?" -eq 0 ]; then'
	test_type="fails"
fi
shift

file="test/files/$1"
if [ ! -f "$file" ]; then
	echo "test file not found!"
	exit 1;
fi
shift

name="$1"
shift

max="$(ls test/tests/ -1|sort -n | sed 's@\(..\).*@\1@' | tail -1 | sed s@^0*@@)"
num="$(printf %02d $((max + 1)))"

echo "Adding: $num-$name"

# where we will write the script file
script_file="test/tests/$num-$name"

echo "making $num-$name: f=$script_file, normally $test_type, cmd='$*'"

cat > $script_file <<EOF
#! /bin/sh

run_binary "./opal-gard" "-9 -p -e -f $file $*"
$check
	fail_test
fi

diff_with_result

pass_test
EOF

# generate the .out and .err files
stdout_file="test/results/$num-$name.out"
stderr_file="test/results/$num-$name.err"

test_input="$name-$num-input"
cp $file $test_input
./opal-gard -f $test_input -p -e $* 2>$stderr_file >$stdout_file
rm -f $test_input
