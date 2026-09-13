#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run FEMU as a black-box SSD (FTL managed by the device)
#
# Every setting below can be overridden from the environment, and each default
# is the value this script used when they were constants. Set nothing and the
# command line is what it always was.
#
# The reason for the change: the layout was written into the file, so running
# two devices, or running one under a harness, meant editing the script or
# keeping a forked copy per configuration. The names match the ones the
# container path uses, so a run is described the same way whichever way it is
# started.

# image directory
IMGDIR=${FEMU_GUEST_DIR:-$HOME/images}
# Virtual machine disk image
OSIMGF=${FEMU_IMAGE:-$IMGDIR/${FEMU_IMAGE_NAME:-u20s.qcow2}}

# Configurable SSD Controller layout parameters (must be power of 2)
secsz=${FEMU_SECTOR_SIZE:-512} # sector size in bytes
secs_per_pg=${FEMU_SECTORS_PER_PAGE:-8} # number of sectors in a flash page
pgs_per_blk=${FEMU_PAGES_PER_BLOCK:-256} # number of pages per flash block
blks_per_pl=${FEMU_BLOCKS_PER_PLANE:-256} # number of blocks per plane
pls_per_lun=${FEMU_PLANES_PER_LUN:-1} # planes per LUN
luns_per_ch=${FEMU_LUNS_PER_CHANNEL:-8} # number of chips per channel
nchs=${FEMU_CHANNELS:-8} # number of channels
ssd_size=${FEMU_SSD_SIZE_MB:-12288} # in megabytes, if you change the above layout parameters, make sure you manually recalculate the ssd size and modify it here, please consider a default 25% overprovisioning ratio.

# Latency in nanoseconds
pg_rd_lat=${FEMU_PAGE_READ_LATENCY:-40000} # page read latency
pg_wr_lat=${FEMU_PAGE_WRITE_LATENCY:-200000} # page write latency
blk_er_lat=${FEMU_BLOCK_ERASE_LATENCY:-2000000} # block erase latency
ch_xfer_lat=${FEMU_CHANNEL_TRANSFER_LATENCY:-0} # channel transfer time, ignored for now

# GC Threshold (1-100)
gc_thres_pcent=${FEMU_GC_THRESHOLD:-75}
gc_thres_pcent_high=${FEMU_GC_THRESHOLD_HIGH:-95}

# Guest resources and the port forwarded to its sshd
vm_cpus=${FEMU_CPUS:-4}
vm_memory=${FEMU_MEMORY:-4G}
ssh_port=${FEMU_GUEST_SSH_PORT:-8080}

#-----------------------------------------------------------------------

#Compose the entire FEMU BBSSD command line options
FEMU_OPTIONS="-device femu"
FEMU_OPTIONS=${FEMU_OPTIONS}",devsz_mb=${ssd_size}"
FEMU_OPTIONS=${FEMU_OPTIONS}",namespaces=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",femu_mode=1"
FEMU_OPTIONS=${FEMU_OPTIONS}",secsz=${secsz}"
FEMU_OPTIONS=${FEMU_OPTIONS}",secs_per_pg=${secs_per_pg}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pgs_per_blk=${pgs_per_blk}"
FEMU_OPTIONS=${FEMU_OPTIONS}",blks_per_pl=${blks_per_pl}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pls_per_lun=${pls_per_lun}"
FEMU_OPTIONS=${FEMU_OPTIONS}",luns_per_ch=${luns_per_ch}"
FEMU_OPTIONS=${FEMU_OPTIONS}",nchs=${nchs}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_rd_lat=${pg_rd_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",pg_wr_lat=${pg_wr_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",blk_er_lat=${blk_er_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",ch_xfer_lat=${ch_xfer_lat}"
FEMU_OPTIONS=${FEMU_OPTIONS}",gc_thres_pcent=${gc_thres_pcent}"
FEMU_OPTIONS=${FEMU_OPTIONS}",gc_thres_pcent_high=${gc_thres_pcent_high}"

# Appended only when asked for, so an unset environment reproduces the command
# line this script produced before any of this was configurable. The flat
# pg_rd_lat above is what a cell type replaces: set FEMU_NAND_CELL_TYPE and the
# device reads its per-page-class table instead.
[ -n "${FEMU_NAND_CELL_TYPE:-}" ] &&
    FEMU_OPTIONS=${FEMU_OPTIONS}",nand_cell_type=${FEMU_NAND_CELL_TYPE}"
for c in 0 1 2 3; do
    v=FEMU_E_READ_C$c
    [ -n "${!v:-}" ] && FEMU_OPTIONS=${FEMU_OPTIONS}",e_read_c${c}_mpj=${!v}"
    v=FEMU_E_ARRAY_C$c
    [ -n "${!v:-}" ] && FEMU_OPTIONS=${FEMU_OPTIONS}",e_array_c${c}_mpj=${!v}"
done
[ -n "${FEMU_E_XFER:-}" ] && FEMU_OPTIONS=${FEMU_OPTIONS}",e_xfer_mpj=${FEMU_E_XFER}"
[ -n "${FEMU_STATS_FLUSH_MS:-}" ] &&
    FEMU_OPTIONS=${FEMU_OPTIONS}",stats_flush_ms=${FEMU_STATS_FLUSH_MS}"
# Anything else the device takes, comma separated: op_pcent=7, buffer_size=...
[ -n "${FEMU_EXTRA_DEVICE_OPTS:-}" ] &&
    FEMU_OPTIONS=${FEMU_OPTIONS}",${FEMU_EXTRA_DEVICE_OPTS}"

echo ${FEMU_OPTIONS}

# Extra read-only guest disks, ';' separated -drive specs. A replay payload is
# far too large for a cloud-init seed, so it arrives as a disk the guest copies
# onto the emulated SSD from inside.
EXTRA_DRIVES=()
if [ -n "${FEMU_EXTRA_DRIVES:-}" ]; then
    IFS=';' read -r -a specs <<< "${FEMU_EXTRA_DRIVES}"
    for spec in "${specs[@]}"; do
        [ -n "$spec" ] && EXTRA_DRIVES+=(-drive "$spec")
    done
fi

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

# sudo is how an ordinary user reaches KVM and raises RLIMIT_MEMLOCK for the
# pinned memory backend. In a container the process is already root and sudo is
# often not installed, so asking for it there fails for want of a binary.
SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=
# Built in build-femu/ by femu-compile.sh, which is where this script is run
# from; a packaged build puts it on PATH instead.
QEMU=${FEMU_QEMU_BIN:-./qemu-system-x86_64}
[ -x "$QEMU" ] || QEMU=$(command -v qemu-system-x86_64) || {
    echo "qemu-system-x86_64 not found; build it or set FEMU_QEMU_BIN"; exit 1; }

$SUDO FEMU_EXP_LOG=${FEMU_EXP_LOG} \
     FEMU_SECRET=${FEMU_SECRET} \
     FEMU_DUMP_LPN=${FEMU_DUMP_LPN} \
     FEMU_QLC_STATS_PATH=${FEMU_QLC_STATS_PATH} \
     FEMU_ALLOW_UNPINNED=${FEMU_ALLOW_UNPINNED} \
     "$QEMU" \
    -name "FEMU-BBSSD-VM" \
    -enable-kvm \
    -cpu host \
    -smp ${vm_cpus} \
    -m ${vm_memory} \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    "${EXTRA_DRIVES[@]}" \
    ${FEMU_OPTIONS} \
    -net user,hostfwd=tcp::${ssh_port}-:22 \
    -net nic,model=virtio \
    -nographic \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log
