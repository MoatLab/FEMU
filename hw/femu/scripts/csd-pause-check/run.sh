#!/bin/bash
#
# Check csd_pause in a real KVM guest: the guest must see the modelled run
# time of a CSD program, and its clocks must never step back.
#
# Usage: run.sh QEMU KERNEL MODDIR OUTDIR [VCPUS]
#   QEMU    a FEMU qemu-system-x86_64
#   KERNEL  a guest bzImage with KVM guest support
#   MODDIR  /lib/modules/<version> of that kernel (for nvme.ko), or "none"
#           when NVMe is built in
#   OUTDIR  where the guest image and the logs go
#
# It boots the guest twice, with csd_pause off (the control) and on. Each
# boot runs clockcheck on every vCPU while csdlat times Execute commands.
# Needs gcc with static glibc, a static busybox, cpio and gzip.
set -euo pipefail

qemu=$1
kernel=$2
moddir=$3
mkdir -p "$4"
out=$(cd "$4" && pwd)
vcpus=${5:-4}
here=$(cd "$(dirname "$0")" && pwd)
root="$out/initramfs"

build_guest() {
    local m
    local mods=(common/nvme-auth common/nvme-keyring host/nvme-core host/nvme)

    rm -rf "$root"
    mkdir -p "$root/bin" "$root/proc" "$root/sys" "$root/dev" "$root/mod"
    cp "$(command -v busybox)" "$root/bin/"
    gcc -O2 -static -o "$root/csdlat" "$here/csdlat.c"
    gcc -O2 -static -pthread -o "$root/clockcheck" "$here/clockcheck.c"
    if [[ $moddir != none ]]; then
        for m in "${mods[@]}"; do
            if [[ -f $moddir/kernel/drivers/nvme/$m.ko ]]; then
                cp "$moddir/kernel/drivers/nvme/$m.ko" "$root/mod/"
            fi
        done
    fi
    cat > "$root/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
for m in nvme-auth nvme-keyring nvme-core nvme; do
    [ -f /mod/$m.ko ] && insmod /mod/$m.ko
done
i=0
while [ ! -e /dev/nvme0n1 ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
echo "CLOCKSOURCE $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)"
echo "TIMER $(awk '/^Clock Event Device: /{d=$4} / mode:/{if (d ~ /lapic/) {print d, $0; exit}}' /proc/timer_list)"
# vCPU 0 stays idle, so it halts and keeps an old pvclock page
last=$(( $(nproc) - 1 ))
# a hex mask, because older busybox taskset has no -c
mask=$(printf %x $(( 1 << last )))
/clockcheck 20 &
sleep 1
taskset $mask /csdlat /dev/nvme0 /dev/nvme0n1 50 500 100
taskset $mask /csdlat /dev/nvme0 /dev/nvme0n1 5 2000 100
wait
echo GUEST-DONE
poweroff -f
EOF
    chmod +x "$root/init"
    (cd "$root" && find . | cpio -o -H newc 2>/dev/null | gzip > "$out/initramfs.gz")
}

build_prog() {
    cat > "$out/prog/slow.c" <<'EOF'
#include <time.h>
struct args { int numr; void **a; long long *l; long long p1, p2;
              void *d; long long dl; } __attribute__((packed));
long long run(struct args *a)
{
    struct timespec t = { a->p1 / 1000, (a->p1 % 1000) * 1000000L };
    nanosleep(&t, 0);
    return 7;
}
EOF
    gcc -shared -fPIC -o "$out/prog/slow.so" "$out/prog/slow.c"
}

boot() {
    local pause=$1
    local log="$out/guest-pause-$pause.log"
    local dev="femu,devsz_mb=1024,femu_mode=4,fdm_size=64"

    dev+=",csd_program_dir=$out/prog,csd_pause=$pause"
    timeout 300 "$qemu" -enable-kvm -cpu host -smp "$vcpus" -m 2G \
        -nographic -no-reboot -kernel "$kernel" -initrd "$out/initramfs.gz" \
        -append "console=ttyS0 quiet panic=-1" -device "$dev" \
        > "$log" 2>&1 || true
    echo "== csd_pause=$pause"
    grep -E "CLOCKSOURCE|TIMER|CSDLAT|CLOCKCHECK|GUEST-DONE|femu" "$log" | \
        grep -v "^femu_log" || true
    local n
    n=$(grep -c "CSDLAT host_ms" "$log" || true)
    if (( n < 2 )) || ! grep -q GUEST-DONE "$log"; then
        echo "FAIL: no csdlat result in $log"
        return 1
    fi
}

mkdir -p "$out/prog"
build_guest
build_prog
boot off
boot on
