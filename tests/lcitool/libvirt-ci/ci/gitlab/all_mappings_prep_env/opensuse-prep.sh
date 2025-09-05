#!/bin/sh

zypper dist-upgrade -y
zypper install -y \
    perl-App-cpanminus \
    python311-base \
    python311-pip
test -f /usr/bin/python3 || ln -s /usr/bin/python3.11 /usr/bin/python3
