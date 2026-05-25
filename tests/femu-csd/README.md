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

The smoke test sends these CSD commands through `NVME_IOCTL_IO_CMD`:

- allocate AFDM
- write AFDM
- read AFDM
- download a phantom CSF
- execute the phantom CSF
- deallocate AFDM

Build also produces `csd-vadd.so`, a minimal shared-library CSF used by the
shared-library smoke path. Because the shared library is loaded by the QEMU
process on the host, pass a host-visible path to the guest tool:

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
sudo ./csd-passthru /dev/nvme0n1 download-phantom 1000
sudo ./csd-passthru /dev/nvme0n1 download-so /host/path/csd-vadd.so csd_vadd
sudo ./csd-passthru /dev/nvme0n1 download-ubpf /host/path/csf.bpf.o csf_symbol 0
sudo ./csd-passthru /dev/nvme0n1 create-group 5 0 0
sudo ./csd-passthru /dev/nvme0n1 set-qos <group-id> 6 0 0
sudo ./csd-passthru /dev/nvme0n1 exec <csf-id> <in-afdm-id> <out-afdm-id> 0 <group-id> <cparam1>
sudo ./csd-passthru /dev/nvme0n1 delete-group <group-id>
sudo ./csd-passthru /dev/nvme0n1 nvm-to-afdm <afdm-id> 0 0 0
```

The tool assumes FEMU was started with CSD mode enabled, for example:

```bash
-device femu,femu_mode=4,fdm_size=64
```

It intentionally does not depend on CEMU's modified kernel driver or FDMFS.

Shared-library CSF support is enabled in the default FEMU build. uBPF support
is optional because it depends on an external `ubpf` library. Build FEMU with:

```bash
./femu-compile.sh --enable-csd-ubpf
```
