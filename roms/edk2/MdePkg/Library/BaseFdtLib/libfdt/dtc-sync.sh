#!/bin/sh -e

DTC_PATH=../dtc/

cp ${DTC_PATH}/libfdt/*.c libfdt/
cp ${DTC_PATH}/libfdt/*.h libfdt/
cp ${DTC_PATH}/pylibfdt/libfdt.i libfdt/
