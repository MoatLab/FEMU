# SPDX-License-Identifier: GPL-2.0-or-later
"""Per-mode facts for FEMU, kept in one place.

hw/femu/scripts/gen-mode-table.py renders this list into every Markdown file
under README.md and hw/femu/docs/ that holds the markers

  <!-- modes-table:start -->
  <!-- modes-table:end -->

and hw/femu/scripts/check-doc-examples.py realizes each entry's `example`
under qtest, so the selection and required properties below are tested on
every CI run. Edit this file, then run

  python3 hw/femu/scripts/gen-mode-table.py

Fields:
  key          short identifier, used to name the tested example
  name         what the table calls the mode or feature
  use          what it is for, in a few words
  device       the -device type that provides it
  symbol       the femu_mode enum symbol in hw/femu/nvme.h (None for a
               feature that is not a mode); gen-mode-table.py checks that the
               symbol has the value in `femu_mode`
  femu_mode    the femu_mode value, or None
  select       how to turn it on
  example      a minimal command line fragment that turns it on; tested
  io           what the example test does after realize: "rw" (Identify, then
               write and read back one block on namespace 1), "kv" (Identify,
               then store and retrieve one value), "identify" (Identify only),
               "none" (realize only, for a device that is not an NVMe
               controller)
  allow_warning  text of a warning the example is expected to print
  guest_kernel minimum guest kernel and configuration
  guest_tools  guest tools and versions
  host         host requirements beyond the common ones (KVM, RAM for
               devsz_mb plus guest RAM)
  launcher     the script in hw/femu/scripts that starts it, or None
  guide        repository path (with an optional #anchor) of the page that
               documents it
  guest_check  (what, repository path) of the documented run that checked it
               inside a booted guest, or None when no documented run covers it
"""

MODES = [
    {
        "key": "nossd",
        "name": "NoSSD",
        "use": "fast NVMe device in DRAM, no flash timing",
        "device": "femu",
        "symbol": "FEMU_NOSSD_MODE",
        "femu_mode": 2,
        "select": "`femu_mode=2` (the default)",
        "example": "-device femu,devsz_mb=1024,femu_mode=2",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver",
        "guest_tools": "nvme-cli, fio",
        "host": "none beyond the common ones",
        "launcher": "run-nossd.sh",
        "guide": "README.md#nossd-mode",
        "guest_check": None,
    },
    {
        "key": "bbssd",
        "name": "BlackBox SSD (BBSSD)",
        "use": "a commercial SSD: device FTL, GC, NAND timing",
        "device": "femu",
        "symbol": "FEMU_BBSSD_MODE",
        "femu_mode": 1,
        "select": "`femu_mode=1`",
        "example": "-device femu,devsz_mb=1024,femu_mode=1",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver",
        "guest_tools": "nvme-cli, fio",
        "host": "about 17 GiB free RAM for the launcher's 12 GiB device",
        "launcher": "run-blackbox.sh",
        "guide": "README.md#blackbox-ssd-mode-bbssd",
        "guest_check": ("quick start, run end to end",
                        "hw/femu/docs/getting-started/quick-start.md"),
    },
    {
        "key": "zns",
        "name": "Zoned Namespace (ZNS)",
        "use": "zoned storage research",
        "device": "femu",
        "symbol": "FEMU_ZNSSD_MODE",
        "femu_mode": 3,
        "select": "`femu_mode=3`",
        "example": "-device femu,devsz_mb=1024,femu_mode=3",
        "io": "rw",
        "guest_kernel": "5.9 or newer with `CONFIG_BLK_DEV_ZONED=y`; "
                        "4 KiB guest pages",
        "guest_tools": "nvme-cli 1.12 or newer for `nvme zns`",
        "host": "none beyond the common ones",
        "launcher": "run-zns.sh",
        "guide": "README.md#zoned-namespace-ssd-mode-znssd",
        "guest_check": None,
    },
    {
        "key": "ocssd12",
        "name": "Open-Channel SSD 1.2",
        "use": "host-managed FTL research",
        "device": "femu",
        "symbol": "FEMU_OCSSD_MODE",
        "femu_mode": 0,
        "select": "`femu_mode=0,lver=1`",
        "example": "-device femu,devsz_mb=1024,femu_mode=0,lver=1",
        "io": "identify",
        "guest_kernel": "4.16 to 5.14 (LightNVM was removed in 5.15)",
        "guest_tools": "LightNVM tools, or SPDK on newer kernels",
        "host": "none beyond the common ones",
        "launcher": "run-whitebox.sh",
        "guide": "README.md#whitebox-ssd-mode-ocssd",
        "guest_check": None,
    },
    {
        "key": "ocssd20",
        "name": "Open-Channel SSD 2.0",
        "use": "host-managed FTL research",
        "device": "femu",
        "symbol": "FEMU_OCSSD_MODE",
        "femu_mode": 0,
        "select": "`femu_mode=0` (`lver=2` is the default)",
        "example": "-device femu,devsz_mb=1024,femu_mode=0,lver=2",
        "io": "identify",
        "guest_kernel": "4.17 to 5.14 (LightNVM was removed in 5.15)",
        "guest_tools": "LightNVM tools, or SPDK on newer kernels",
        "host": "none beyond the common ones",
        "launcher": "run-whitebox.sh",
        "guide": "README.md#whitebox-ssd-mode-ocssd",
        "guest_check": None,
    },
    {
        "key": "kv",
        "name": "Key-value SSD (KV)",
        "use": "key-value store research",
        "device": "femu",
        "symbol": "FEMU_KVSSD_MODE",
        "femu_mode": 5,
        "select": "`femu_mode=5`",
        "example": "-device femu,devsz_mb=1024,femu_mode=5",
        "io": "kv",
        "guest_kernel": "5.13 or newer; no block device, the namespace is "
                        "`/dev/ngXnY`",
        "guest_tools": "nvme-cli `io-passthru`, `hw/femu/scripts/kv-probe.c`",
        "host": "none beyond the common ones",
        "launcher": None,
        "guide": "README.md#key-value-ssd-mode-kvssd",
        "guest_check": None,
    },
    {
        "key": "csd",
        "name": "Computational storage (CSD)",
        "use": "running programs next to the data",
        "device": "femu",
        "symbol": "FEMU_CSD_MODE",
        "femu_mode": 4,
        "select": "`femu_mode=4,fdm_size=<MiB>`",
        "example": "-device femu,devsz_mb=1024,femu_mode=4,fdm_size=64",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver",
        "guest_tools": "`hw/femu/tests/csd` tools",
        "host": "`csd_program_dir` for shared-library programs; "
                "`--enable-csd-ubpf` build for eBPF programs",
        "launcher": "run-csd.sh",
        "guide": "README.md#computational-storage-mode-csd",
        "guest_check": None,
    },
    {
        "key": "fdp",
        "name": "Flexible Data Placement (FDP)",
        "use": "placement hints on a BBSSD",
        "device": "femu-subsys",
        "symbol": None,
        "femu_mode": 1,
        "select": "`femu-subsys,fdp=on,fdp.nruh=<n>` and "
                  "`femu,femu_mode=1,subsys=<id>`",
        "example": "-device femu-subsys,id=fdp0,nqn=fdp0,fdp=on,fdp.nruh=4 "
                   "-device femu,devsz_mb=1024,femu_mode=1,subsys=fdp0",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver; placement hints need "
                        "passthrough or io_uring commands",
        "guest_tools": "nvme-cli with `nvme fdp`",
        "host": "none beyond the common ones",
        "launcher": "run-blackbox-fdp.sh",
        "guide": "README.md#features",
        "guest_check": None,
    },
    {
        "key": "multi-ns",
        "name": "Multiple namespaces",
        "use": "several namespaces, each with its own mode",
        "device": "femu",
        "symbol": None,
        "femu_mode": None,
        "select": "`namespaces=<n>`, optionally `namespace_sizes` and "
                  "`namespace_modes`",
        "example": "-device femu,devsz_mb=1024,femu_mode=1,namespaces=2,"
                   "namespace_modes=bbssd,,znssd",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver (ZNS namespaces need what "
                        "ZNS needs)",
        "guest_tools": "nvme-cli",
        "host": "none beyond the common ones",
        "launcher": None,
        "guide": "README.md#multiple-namespaces",
        "guest_check": None,
    },
    {
        "key": "ns-mgmt",
        "name": "Namespace management",
        "use": "create, delete and attach namespaces at run time",
        "device": "femu",
        "symbol": None,
        "femu_mode": None,
        "select": "`ns_mgmt=on` on a NoSSD or BBSSD controller; "
                  "`femu-subsys,ns_mgmt=on` to share namespaces",
        "example": "-device femu,devsz_mb=1024,femu_mode=1,ns_mgmt=on",
        "io": "rw",
        "guest_kernel": "any with the NVMe driver",
        "guest_tools": "nvme-cli `create-ns`, `attach-ns`",
        "host": "none beyond the common ones",
        "launcher": None,
        "guide": "hw/femu/docs/CONFIGURATION-CHANGES.md",
        "guest_check": None,
    },
    {
        "key": "pi",
        "name": "Metadata and protection information",
        "use": "per-block metadata, PI types 1 to 3",
        "device": "femu",
        "symbol": None,
        "femu_mode": None,
        "select": "`meta=<bytes>,mc=<mask>`, plus `pi=on` with `meta` of 8 "
                  "or more",
        "example": "-device femu,devsz_mb=1024,femu_mode=1,meta=8,mc=2,pi=on",
        "io": "rw",
        "guest_kernel": "`CONFIG_BLK_DEV_INTEGRITY=y` to use metadata "
                        "formats through the block layer",
        "guest_tools": "nvme-cli `format`",
        "host": "none beyond the common ones",
        "launcher": None,
        "guide": "hw/femu/docs/reference/properties.md",
        "guest_check": None,
    },
    {
        "key": "cxl-off",
        "name": "CXL SSD, `der=off`",
        "use": "CXL memory backed by flash, all accesses trapped",
        "device": "femu-cxl-ssd",
        "symbol": None,
        "femu_mode": None,
        "select": "`femu-cxl-ssd` below `pxb-cxl` and `cxl-rp` on "
                  "`-machine q35,cxl=on`",
        "example": "-machine q35,cxl=on "
                   "-object memory-backend-ram,id=cxlmem,size=256M "
                   "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
                   "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
                   "-device femu-cxl-ssd,id=cxlssd,bus=rp0,"
                   "volatile-memdev=cxlmem,der=off "
                   "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M",
        "io": "none",
        "guest_kernel": "`CONFIG_CXL_BUS`, `CXL_PCI`, `CXL_ACPI`, "
                        "`CXL_MEM`, `CXL_PORT`, `CXL_REGION`, `DEV_DAX`, "
                        "`DEV_DAX_KMEM`",
        "guest_tools": "`cxl-cli`, `daxctl`, `ndctl`",
        "host": "a build with `CONFIG_CXL_MEM_DEVICE`",
        "launcher": "run-cxlssd.sh",
        "guide": "hw/femu/docs/cxlssd.md",
        "guest_check": None,
    },
    {
        "key": "cxl-memslot",
        "name": "CXL SSD, `der=memslot`",
        "use": "cached pages mapped into the guest as KVM memory slots",
        "device": "femu-cxl-ssd",
        "symbol": None,
        "femu_mode": None,
        "select": "`der=memslot` on `femu-cxl-ssd`",
        "example": "-machine q35,cxl=on "
                   "-object memory-backend-ram,id=cxlmem,size=256M "
                   "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
                   "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
                   "-device femu-cxl-ssd,id=cxlssd,bus=rp0,"
                   "volatile-memdev=cxlmem,der=memslot "
                   "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M",
        "io": "none",
        "guest_kernel": "as for `der=off`",
        "guest_tools": "as for `der=off`",
        "host": "KVM (TCG is refused)",
        "launcher": "run-cxlssd.sh",
        "guide": "hw/femu/docs/cxlssd.md",
        "guest_check": None,
    },
    {
        "key": "cxl-cylon",
        "name": "CXL SSD, `der=cylon`",
        "use": "cached pages mapped by a Cylon host kernel",
        "device": "femu-cxl-ssd",
        "symbol": None,
        "femu_mode": None,
        "select": "`der=cylon,cylon-kernel-ack=on` on `femu-cxl-ssd`",
        # Under qtest there is no KVM, so the device falls back to MMIO and
        # says so; the example checks that the properties are accepted.
        "example": "-machine q35,cxl=on "
                   "-object memory-backend-ram,id=cxlmem,size=256M "
                   "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
                   "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
                   "-device femu-cxl-ssd,id=cxlssd,bus=rp0,"
                   "volatile-memdev=cxlmem,der=cylon,cylon-kernel-ack=on "
                   "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M",
        "allow_warning": "FEMU CXL DER unavailable",
        "io": "none",
        "guest_kernel": "as for `der=off`",
        "guest_tools": "as for `der=off`",
        "host": "Cylon host kernel; KVM with EPT A/D bits and the TDP MMU; "
                "4 KiB host pages; a shared, preallocated hugetlb backend. "
                "Without them the device warns and uses MMIO",
        "launcher": "run-cxlssd.sh",
        "guide": "hw/femu/docs/cxlssd.md",
        "guest_check": None,
    },
    {
        "key": "cca",
        "name": "CXL caching API (CCA)",
        "use": "guest pins, unpins and invalidates cached pages",
        "device": "femu-cxl-ssd",
        "symbol": None,
        "femu_mode": None,
        "select": "`cca=on` on `femu-cxl-ssd`",
        "example": "-machine q35,cxl=on "
                   "-object memory-backend-ram,id=cxlmem,size=256M "
                   "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
                   "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
                   "-device femu-cxl-ssd,id=cxlssd,bus=rp0,"
                   "volatile-memdev=cxlmem,cca=on "
                   "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M",
        "io": "none",
        "guest_kernel": "as for `der=off`; a devdax region",
        "guest_tools": "`hw/femu/tools/cca` (`ccactl`, `cca-test`), run as "
                       "root",
        "host": "as for `der=off`",
        "launcher": "run-cxlssd.sh",
        "guide": "hw/femu/tools/cca/README.md",
        "guest_check": None,
    },
    {
        "key": "cxl-nvme",
        "name": "NVMe front end on a CXL SSD",
        "use": "the same media as CXL memory and as an NVMe namespace",
        "device": "femu",
        "symbol": None,
        "femu_mode": 1,
        "select": "`femu,bus=pcie.0,femu_mode=1,cxl_ssd=<id>` after the "
                  "`femu-cxl-ssd`",
        "example": "-machine q35,cxl=on "
                   "-object memory-backend-ram,id=cxlmem,size=256M "
                   "-device pxb-cxl,id=cxl.0,bus=pcie.0,bus_nr=52 "
                   "-device cxl-rp,id=rp0,bus=cxl.0,chassis=0,slot=0 "
                   "-device femu-cxl-ssd,id=cxlssd,bus=rp0,"
                   "volatile-memdev=cxlmem "
                   "-device femu,bus=pcie.0,femu_mode=1,cxl_ssd=cxlssd "
                   "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=256M",
        "io": "rw",
        "guest_kernel": "as for `der=off`, plus the NVMe driver",
        "guest_tools": "as for `der=off`, plus nvme-cli",
        "host": "as for `der=off`",
        "launcher": None,
        "guide": "hw/femu/docs/cxlssd.md",
        "guest_check": None,
    },
]
