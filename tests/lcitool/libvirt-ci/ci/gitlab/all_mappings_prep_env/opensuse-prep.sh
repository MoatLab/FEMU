#!/bin/sh

zypper dist-upgrade -y
zypper install -y \
    perl-App-cpanminus \
    python311-base \
    python311-pip

# OpenSUSE doesn't create/refresh the python3 symlink to always point to the
# newest python3 install available, it always points to 3.6 - FAIL
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
