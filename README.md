[![FEMU Version](https://img.shields.io/badge/FEMU-v9.0-brightgreen)](https://img.shields.io/badge/FEMU-v9.0-brightgreen)
[![Build Status](https://travis-ci.com/vtess/FEMU.svg?branch=master)](https://travis-ci.com/vtess/FEMU)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Platform](https://img.shields.io/badge/Platform-x86--64-brightgreen)](https://shields.io/)

```
  ______ ______ __  __ _    _ 
 |  ____|  ____|  \/  | |  | |
 | |__  | |__  | \  / | |  | |
 |  __| |  __| | |\/| | |  | |
 | |    | |____| |  | | |__| |
 |_|    |______|_|  |_|\____/  -- A QEMU-based and DRAM-backed NVMe SSD Emulator

```
                              
Contact Information
--------------------

**Maintainer**: [Huaicheng Li](https://huaicheng.github.io), Email: ``huaicheng@cs.vt.edu``

> **Research opportunities:** Huaicheng Li is hiring Ph.D. students to join his group, feel free to contact him for details!

Feel free to contact Huaicheng for any suggestions/feedback, bug
reports, or general discussions.

Please consider citing our FEMU paper at FAST 2018 if you use FEMU. The bib
entry is

```
@InProceedings{Li+18-FEMU, 
Author = {Huaicheng Li and Mingzhe Hao and Michael Hao Tong 
and Swaminathan Sundararaman and Matias Bj{\o}rling and Haryadi S. Gunawi},
Title = "The CASE of FEMU: Cheap, Accurate, Scalable and Extensible Flash Emulator",
Booktitle =  {Proceedings of 16th USENIX Conference on File and Storage Technologies (FAST)},
Address = {Oakland, CA},
Month =  {February},
Year =  {2018}
}
```


Research Papers using FEMU
--------------------------

**Please Check the growing list of research papers using FEMU [here](https://github.com/vtess/FEMU/wiki/Research-Papers-using-FEMU), including papers at ASPLOS, OSDI, SOSP and FAST, etc.**



Project Description (What is FEMU?)
-----------------------------------


                            +--------------------+
                            |    VM / Guest OS   |
                            |                    |
                            |                    |
                            |  NVMe Block Device |
                            +--------^^----------+
                                     ||
                                  PCIe/NVMe
                                     ||
      +------------------------------vv----------------------------+
      |  +---------+ +---------+ +---------+ +---------+ +------+  |
      |  | Blackbox| |  OCSSD  | | ZNS-SSD | |  NoSSD  | | ...  |  |
      |  +---------+ +---------+ +---------+ +---------+ +------+  |
      |                    FEMU NVMe SSD Controller                |
      +------------------------------------------------------------+


Briefly speaking, FEMU is a **fast**, **accurate**, **scalable**, and
**extensible** NVMe SSD Emulator. Based upon QEMU/KVM, FEMU is exposed to Guest
OS (Linux) as an NVMe block device (e.g. /dev/nvme0nX). It supports emulating different types of SSDs:

- ``Whitebox mode`` (``OCSSD``) (a.k.a. Software-Defined Flash (SDF), or
  OpenChannel-SSD) with host side FTL (e.g. LightNVM or SPDK FTL), both
  OpenChannel Spec 1.2 and 2.0 are supported.

- ``Blackbox mode`` (``BBSSD``) with FTL managed by the device (like most of
  current commercial SSDs). A page-level mapping based FTL is included.

- ``ZNS mode`` (``ZNSSD``), exposing NVMe Zone interface for the host to
  directly read/write/append to the device following certain rules.

- ``NoSSD mode``, emulating a as-fast-as-possible NVMe device with sub-10
  microsecond latency. This is to emualte SCM-class block devices such as
  Optane or Z-NAND SSDs.


FEMU design aims to achieve the benefits of both SSD Hardware platforms (e.g.
CNEX OpenChannel SSD, OpenSSD, etc.) and SSD simulators (e.g. DiskSim+SSD,
FlashSim, SSDSim, etc.). Like hardware platforms, FEMU can support running full
system stack (Applications + OS + NVMe interface) on top, thus enabling
Software-Defined Flash (SDF) alike research with modifications at application,
OS, interface or SSD controller architecture level. Like SSD simulators, FEMU
can also support internal-SSD/FTL related research. Users can feel free to
experiment with new FTL algorithms or SSD performance models to explore new SSD
architecture innovations as well as benchmark the new arch changes with real
applications, instead of using decade-old disk trace files.


Installation
------------

1. Make sure you have installed necessary libraries for building QEMU. The
   dependencies can be installed by following instructions below:

```bash
  git clone https://github.com/vtess/femu.git
  cd femu
  mkdir build-femu
  # Switch to the FEMU building directory
  cd build-femu
  # Copy femu script
  cp ../femu-scripts/femu-copy-scripts.sh .
  ./femu-copy-scripts.sh .
  # only Debian/Ubuntu based distributions supported
  sudo ./pkgdep.sh
```

2. Compile & Install FEMU:

```bash
  ./femu-compile.sh
```
  FEMU binary will appear as ``x86_64-softmmu/qemu-system-x86_64``

  **Tested host environment** (For successful FEMU compilation):
  
  | Linux Distribution | Kernel | Gcc    | Ninja  | Python |
  | :---               | :---:  | ---    | ---    | ---    |
  | Gentoo             | 5.10   | 9.3.0  | 1.10.1 | 3.7.9  |
  | Ubuntu 16.04.5     | 4.15.0 | 5.4.0  | 1.8.2  | 3.6.0  |
  | Ubuntu 20.04.1     | 5.4.0  | 9.3.0  | 1.10.0 | 3.8.2  |
  | Ubutnu 22.04.2     | 5.15.0 | 11.3.0 | 1.10.1 | 3.10.6 |

  **Tested VM environment** (Whether a certain FEMU mode works under a certain
  guest kernel version): 

  | Mode \ Guest Kernel       | 4.16    | 4.20    | 5.4     | 5.10    | 6.1     | 6.9
  | :---                      | :---:   | --      | --      | --      | --      | --
  | NoSSD                     | &check; | &check; | &check; | &check; | &check; | &check;
  | BlackBox SSD              | &check; | &check; | &check; | &check; | &check; | &check;
  | OpenChannel-SSD v1.2      | &check; | &check; | &check; | &check; | &cross; | &cross;
  | OpenChannel-SSD v2.0      | &cross; | &check; | &check; | &check; | &cross; | &cross;
  | Zoned-Namespace (ZNS) SSD | &cross; | &cross; | &cross; | &check; | &check; | &check;


3. Prepare the VM image (For performance reasons, we suggest to use a server
   version guest OS [e.g. Ubuntu Server 22.04, 20.04, 18.04, 16.04])

  You can either build your own VM image, or use the VM image provided by us

  **Option 1**: This is the **recommended** way to get FEMU running quickly -
  Use our VM image file. You can download it from our
  [FEMU-VM-image-site](https://forms.gle/nEZaEe2fkj5B1bxt9). After you fill in
  the form, VM image downloading instructions will be sent to your email address
  shortly.

  **Option 2**: Build your own VM image by following instructions:
  After the guest OS is installed, make following changes to redirect VM output
  to the console, instead of using a separate GUI window. (**Desktop version
  guest OS is not tested**)

> Note: Please ask for help from Google if any of the steps doesn't work. In general, it
> gives you a basic idea to build your own VM image and make it run in text console.

```
    # Download a Ubuntu server ISO file
    $ mkdir -p ~/images/
    $ cd ~/images
    $ wget http://releases.ubuntu.com/20.04/ubuntu-20.04.3-live-server-amd64.iso
    $ sudo apt-get install qemu-system-x86
    # Create a QCOW2 disk image
    $ qemu-img create -f qcow2 femu.qcow2 80G

    # install guest OS to femu.qcow2 (You need a GUI environment to prepare the VM image)
    $ qemu-system-x86_64 -cdrom ubuntu-20.04.3-live-server-amd64.iso -hda femu.qcow2 -boot d -net nic -net user -m 8192 -localtime -smp 8 -cpu host -enable-kvm

```

  - After guest OS is installed, boot it with

```
    $ qemu-system-x86_64 -hda femu.qcow2 -net nic -net user -m 8192 -localtime -smp 8 -cpu host -enable-kvm
```

If the OS is installed into ``femu.qcow2``, you should be able to enter the
guest OS. Inside the VM, edit ``/etc/default/grub``, make sure the following
options are set.


```
GRUB_CMDLINE_LINUX="ip=dhcp console=ttyS0,115200 console=tty console=ttyS0"
GRUB_TERMINAL=serial
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
```

Still in the VM, update the grub
   
```
$ sudo update-grub
$ sudo shutdown -h now
```
  
  Now you're ready to `Run FEMU`. If you stick to a Desktop version guest OS,
  please remove "-nographics" command option from the running script before
  running FEMU.

 
 4. Login to FEMU VM

  - If you correctly setup the aforementioned configurations, you should be
    able to see **text-based** VM login in the same terminal where you issue
    the running scripts.
  - Or, more conveniently, FEMU running script has mapped host port `8080` to
    guest VM port `22`, thus, after you install and run `openssh-server` inside
    the VM, you can also ssh into the VM via below command line. (Please run it
    from your host machine)
  
  ```
  $ ssh -p8080 $user@localhost
  ```

Run FEMU
--------


### 0. Minimum Requirement

- Run FEMU on a physical machine, not inside a VM (if the VM has nested
  virtualization enabled, you can also give it a try, but FEMU performance will
  suffer, this is **not** recommended.)

- At least 8 cores and 12GB DRAM in the physical machine to enable seamless run
  of the following default FEMU scripts emulating a 4GB SSD in a VM with 4
  vCPUs and 4GB DRAM.

- If you intend to emulate a larger VM (more vCPUs and DRAM) and an SSD with
  larger capacity, make sure refer to the resource provisioning tips
  [here](https://github.com/vtess/FEMU/wiki/Before-running-FEMU).

### 1. Run FEMU as blackbox SSDs (``Device-managed FTL`` or ``BBSSD`` mode) ###

**TODO:** currently blackbox SSD parameters are hard-coded in
`hw/femu/ftl/ftl.c`, please change them accordingly and re-compile FEMU.

Boot the VM using the following
script:

```Bash
./run-blackbox.sh
```

### 2. Run FEMU as whitebox SSDs (ak.a. ``OpenChannel-SSD`` or ``OCSSD`` mode) ###

Both OCSSD [Specification
1.2](http://lightnvm.io/docs/Open-ChannelSSDInterfaceSpecification12-final.pdf)
and [Specification 2.0](http://lightnvm.io/docs/OCSSD-2_0-20180129.pdf) are
supported, to run FEMU OCSSD mode:

```Bash
./run-whitebox.sh
```

By default, FEMU will run OCSSD in 2.0 mode. To run OCSSD in 1.2, make sure
``OCVER=1`` is set in the ``run-whitebox.sh``



Inside the VM, you can play with LightNVM.


### 3. Run FEMU without SSD logic emulation (``NoSSD`` mode) ###

```Bash
./run-nossd.sh
```

In this ``nossd`` mode, no SSD emulation logic (either blackbox or whitebox
emulation) will be executed.  Base NVMe specification is supported, and FEMU in
this case handles IOs as fast as possible. It can be used for basic performance
benchmarking, as well as fast storage-class memory (SCM, or Intel Optane SSD)
emulation. 

### 4. Run FEMU as NVMe ZNS (Zoned-Namespace) SSDs (``ZNSSD`` mode) ###

```Bash
./run-zns.sh
```

### 5. Run FEMU as Computational Storage, a.k.a, SmartSSD (``SmartSSD`` mode) ###

Stay tuned.

### 6. Run FEMU as CXL-SSD (``CXLSSD`` mode) ###

Stay tuned.


### Contributing ###

Github [``issue``](https://github.com/vtess/FEMU/issues) and [``pull
request``](https://github.com/vtess/FEMU/pulls) are preferred. Do let
us know if you have any thoughts!

### Acknowledgement ###

FEMU is inspired by many prior SSD simulators/emulators (SSDSim, FlashSim,
VSSIM) as well as hardware development platforms (OpenSSD, DFC), but FEMU has
gone far beyond what prior platforms can achieve in terms of ``performance``,
``extensibility``, and ``usability``.

FEMU's NVMe controller logic is based on QEMU/NVMe, LightNVM/QEMU and ZNS/QEMU.


### For more detail, please checkout the [Wiki](https://github.com/vtess/femu/wiki)!

