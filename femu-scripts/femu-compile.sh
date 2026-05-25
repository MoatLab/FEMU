#!/bin/bash

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"
FEMU_CONFIGURE_OPTS=""

for arg in "$@"; do
    case "$arg" in
        --enable-csd-ubpf)
            FEMU_CONFIGURE_OPTS="${FEMU_CONFIGURE_OPTS} --enable-femu-csd-ubpf"
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--enable-csd-ubpf]"
            exit 1
            ;;
    esac
done

make clean
# --disable-werror --extra-cflags=-w --disable-git-update
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp ${FEMU_CONFIGURE_OPTS}
make -j $NRCPUS

echo ""
echo "===> FEMU compilation done ..."
echo ""
exit
