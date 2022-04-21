#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Run an NPU Hardware procedure
#
# Copyright 2016 IBM Corp.


function usage() {
	echo -e "$0: run a NPU hardware procedure (requires root)\n"
	echo -e "Usage: $0 <PCI bdfn> <procedure number>\n"
	echo -e "Example: $0 0008:00:01.1 1"
	echo -e "Procedures are documented in skiboot/doc/nvlink.rst"
}

function check_root() {
	if [ "$(id -u)" != "0" ]; then
		echo -e "Error: $0 must be run as root\n" 1>&2
		exit 1
	fi
}

function check_args() {
	if [ "$#" -eq 0 ]; then
		usage
		exit 1
	fi

	if [ "$#" -gt 2 ]; then
		echo -e "Error: too many arguments\n" 1>&2
		usage
		exit 1
	fi

	if [[ "$1" == "-h" || "$1" == "--help" ]]; then
		usage
		exit 0
	fi

	if ! [ "$2" -eq "$2" ] 2>/dev/null; then
		echo -e "Procedure must be a decimal number\n" 1>&2
		usage
		exit 1
	fi

	if [[ "$2" -lt "0" || "$2" -gt "12" ]]; then
		echo -e "Invalid procedure number\n" 1>&2
		usage
		exit 2
	fi

	pci_check=$(lspci -s $1)
	if [[ $? -ne 0 || $pci_check == "" ]]; then
		echo -e "Invalid PCI device\n" 1>&2
		usage
		exit 2
	fi
}

function run_procedure() {
	# Convert procedure number into hex
	procedure=$(echo "obase=16; $2" | bc)

	# Check the status register to make sure we can run a procedure
	status=$(setpci -s $1 0x84.L)
	if [[ $status == 8000000* ]]; then
		echo "Procedure in progress, try again." 1>&2
		echo "If that doesn't work, use procedure 0 to abort." 1>&2
		exit 3
	fi

	# Start the procedure
	setpci -s $1 0x88.L=0x0000000$procedure >/dev/null
	if [ $? -ne 0 ]; then
		echo "Control register write failed!" 1>&2
		exit 3
	fi

	iterations=1
	while [[ $(setpci -s $1 0x84.L) == 8000000* ]]; do
		((iterations++))
	done

	# Check again, procedure should be finished
	status=$(setpci -s $1 0x84.L)

	echo "Done in $iterations iteration(s)!"

	if [[ $status == 40000000 ]]; then
		echo "Procedure completed successfully."
		exit 0
	elif [[ $status == 40000001 ]]; then
		echo "Transient failure, try again." 1>&2
		exit 4
	elif [[ $status == 40000002 ]]; then
		echo "Permanent failure, reboot required?" 1>&2
		exit 5
	elif [[ $status == 40000003 ]]; then
		echo "Procedure aborted." 1>&2
		exit 6
	elif [[ $status == 40000004 ]]; then
		echo "Unsupported procedure." 1>&2
		exit 7
	fi
}

check_args "$@"
check_root
run_procedure "$1" "$2"
