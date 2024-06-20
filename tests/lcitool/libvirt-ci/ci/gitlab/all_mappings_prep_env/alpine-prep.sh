#!/bin/sh

apk update
apk upgrade
apk add \
    perl-app-cpanminus \
    python3 \
    py3-pip
