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

Other useful command-level checks:

```bash
sudo ./csd-passthru /dev/nvme0n1 alloc 4096
sudo ./csd-passthru /dev/nvme0n1 download-phantom 1000
sudo ./csd-passthru /dev/nvme0n1 create-group 5 0 0
sudo ./csd-passthru /dev/nvme0n1 set-qos <group-id> 6 0 0
sudo ./csd-passthru /dev/nvme0n1 exec <csf-id> <in-afdm-id> <out-afdm-id> 0 <group-id>
sudo ./csd-passthru /dev/nvme0n1 delete-group <group-id>
sudo ./csd-passthru /dev/nvme0n1 nvm-to-afdm <afdm-id> 0 0 0
```

The tool assumes FEMU was started with CSD mode enabled, for example:

```bash
-device femu,femu_mode=4,fdm_size=64
```

It intentionally does not depend on CEMU's modified kernel driver or FDMFS.
