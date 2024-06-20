#!/bin/sh

dnf distro-sync -y
dnf install 'dnf-command(config-manager)' -y
dnf config-manager --set-enabled -y powertools
dnf install -y centos-release-advanced-virtualization epel-release

dnf install -y \
    perl-App-cpanminus \
    python38 \
    python38-pip
