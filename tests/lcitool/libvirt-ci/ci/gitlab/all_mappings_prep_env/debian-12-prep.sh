#!/bin/sh

apt-get update -y
apt-get dist-upgrade -y
apt-get install --no-install-recommends -y \
    cpanminus \
    python3 \
    python3-pip \
    python3-venv
