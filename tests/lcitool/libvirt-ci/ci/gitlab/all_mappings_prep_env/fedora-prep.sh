#!/bin/sh

dnf update -y
dnf install -y \
    perl-App-cpanminus \
    python3 \
    python3-pip
