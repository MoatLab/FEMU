#!/bin/bash

usage() {
	echo "$0 [ prefix ]"
	echo -e "\t Optionally specify a prefix other than 'skiboot'"
	echo
}

if [ "$1" = "-h" -o "$1" = "--help" ] ;
then
	usage
	exit 1;
fi

if test -e .git || git rev-parse --is-inside-work-tree > /dev/null 2>&1;
then
	version=$(git describe --exact-match 2>/dev/null)
	if [ -z "$version" ];
	then
		version=$(git describe 2>/dev/null)
	fi
	if [ -z "$version" ];
	then
		version=$(git rev-parse --verify --short HEAD 2>/dev/null)
	fi
	if [ ! -z "$EXTRA_VERSION" ];
	then
		version="$version-$EXTRA_VERSION"
	fi
	if git diff-index --name-only HEAD |grep -qv '.git';
	then
		if [ ! -z "$USER" ];
		then
			version="$version-$USER"
		fi
		version="$version-dirty"
		diffsha=$(git diff|sha1sum)
		diffsha=$(cut -c-7 <<< "$diffsha")
		version="$version-$diffsha"
	fi

	if [ $# -eq 1 ];
	then
		version=$(echo $version | sed s/skiboot/$1/)
	fi

	echo $version
else
	if [ ! -z "$SKIBOOT_VERSION" ];
	then
		echo $SKIBOOT_VERSION
	else
		if [ -f ".version" -a -s ".version" ];
		then
			cat .version
		else
			exit 1;
		fi
	fi
fi
