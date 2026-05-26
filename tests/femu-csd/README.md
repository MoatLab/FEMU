# FEMU CSD Passthrough Tests

This directory contains lightweight guest-side tools for validating FEMU CSD
vendor commands without `linux-cemu`, FDMFS, or a fixed VM image.

Build inside a normal Linux guest:

```bash
make
```

Run a basic AFDM smoke test against a namespace device:

```bash
sudo ./csd-passthru /dev/nvme0n1 smoke
```

The smoke test sends AFDM commands through `NVME_IOCTL_IO_CMD` and uses the
original CEMU-style admin lifecycle commands through `NVME_IOCTL_ADMIN_CMD`:

- allocate AFDM
- write AFDM
- read AFDM
- load and activate a phantom CSF
- execute the phantom CSF
- deactivate and unload the phantom CSF
- deallocate AFDM

Build also produces `csd-vadd.so`, a minimal shared-library CSF used by the
shared-library smoke path. The program load payload follows the original CEMU
descriptor format: a PRP data buffer containing `path\0symbol\0`. Because the
shared library is loaded by the QEMU process on the host, the `path` string
inside that descriptor must be visible to the host QEMU process:

```bash
sudo ./csd-passthru /dev/nvme0n1 smoke-so /home/<user>/FEMU/tests/femu-csd/csd-vadd.so
```

The shared-library CSF ABI is:

```c
int64_t kernel(struct femu_csd_args *args);
```

For the direct AFDM execution path, `args->mr_addr[0]` is the output AFDM and
`args->mr_addr[1]` is the input AFDM.

Other useful command-level checks:

```bash
sudo ./csd-passthru /dev/nvme0n1 alloc 4096
sudo ./csd-passthru /dev/nvme0n1 create-group 5 0 0
sudo ./csd-passthru /dev/nvme0n1 set-qos <group-id> 6 0 0
sudo ./csd-passthru /dev/nvme0n1 exec <csf-id> <in-afdm-id> <out-afdm-id> 0 <group-id> <cparam1>
sudo ./csd-passthru /dev/nvme0n1 delete-group <group-id>
sudo ./csd-passthru /dev/nvme0n1 nvm-to-afdm <afdm-id> 0 0 0
```

FEMU CSD also accepts the original CEMU program lifecycle admin command
layouts for load/unload (`0x22`) and activate/deactivate (`0x23`). The
lightweight passthrough helper sends those commands to the controller device
without the CEMU kernel driver:

```bash
sudo ./csd-passthru /dev/nvme0 admin-load-phantom 1 1000
sudo ./csd-passthru /dev/nvme0 admin-load-so 1 /host/path/csd-vadd.so csd_vadd
sudo ./csd-passthru /dev/nvme0 admin-load-ubpf 1 /host/path/csf.bpf.o csf_symbol 0
sudo ./csd-passthru /dev/nvme0 admin-activate 1
sudo ./csd-passthru /dev/nvme0 admin-deactivate 1
sudo ./csd-passthru /dev/nvme0 admin-unload 1
```

The tool assumes FEMU was started with CSD mode enabled, for example:

```bash
-device femu,femu_mode=4,fdm_size=64
```

It intentionally does not depend on CEMU's modified kernel driver or FDMFS. CSD
mode still uses FEMU's device-side BBSSD FTL path for normal NVM read/write
requests; the passthrough commands validate the additional computational
storage interface.

Shared-library CSF support is enabled in the default FEMU build. uBPF support
is optional because it depends on an external `ubpf` library. Build FEMU with:

```bash
./femu-compile.sh --enable-csd-ubpf
```
