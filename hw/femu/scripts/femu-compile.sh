#!/bin/bash

NRCPUS="$(cat /proc/cpuinfo | grep "vendor_id" | wc -l)"
FEMU_CONFIGURE_OPTS=""

for arg in "$@"; do
    case "$arg" in
        --enable-csd-ubpf)
            FEMU_CONFIGURE_OPTS="${FEMU_CONFIGURE_OPTS} --enable-femu-csd-ubpf"
            ;;
        --enable-csd-ubpf=*)
            UBPF_PATH="${arg#*=}"
            FEMU_CONFIGURE_OPTS="${FEMU_CONFIGURE_OPTS} --enable-femu-csd-ubpf -Dfemu_csd_ubpf_path=${UBPF_PATH}"
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Usage: $0 [--enable-csd-ubpf[=/path/to/ubpf-cemu]]"
            exit 1
            ;;
    esac
done

make clean
# --disable-werror --extra-cflags=-w --disable-git-update
# FEMU emulates an SSD; none of QEMU's network block drivers are used, and their
# headers move under us -- libnfs 6 changed nfs_pread_async and broke the build
# on newer distributions. Leave them out.
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
             --disable-libnfs --disable-libiscsi --disable-curl \
             ${FEMU_CONFIGURE_OPTS} || {
    echo "===> FEMU configure failed"
    exit 1
}
make -j $NRCPUS || {
    echo "===> FEMU compilation failed"
    exit 1
}

echo ""
echo "===> FEMU compilation done ..."
echo ""
exit
