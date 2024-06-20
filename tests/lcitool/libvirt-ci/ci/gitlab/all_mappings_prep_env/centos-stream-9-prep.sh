#!/bin/sh
dnf distro-sync -y
dnf install 'dnf-command(config-manager)' -y
dnf config-manager --set-enabled -y crb

dnf install -y epel-release
dnf install -y \
    perl-App-cpanminus \
    python3 \
    python3-pip
