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

**Maintainer**: [Huaicheng Li](https://people.cs.uchicago.edu/~huaicheng/) (huaicheng@cs.uchicago.edu)

Please do not hesitate to contact Huaicheng for any suggestions/feedback, bug
reports, or general discussions.

Please consider citing our FEMU paper if you use FEMU. The bib entry is

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

Project Description
-------------------

Briefly speaking, FEMU is an NVMe SSD Emulator. Based upon QEMU/KVM, FEMU is
exposed to Guest OS (Linux) as an NVMe block device (e.g. /dev/nvme0nX). It can
be used as an emulated whitebox or blackbox SSD: (1). whitebox mode (a.k.a.
Software-Defined Flash (SDF), or OpenChannel-SSD) with FTL residing in the host
side (e.g. LightNVM) (2). blackbox mode with FTL managed by the device
(like most of current commercial SSDs).

FEMU tries to achieve benefits of both SSD Hardware platforms (e.g. CNEX
OpenChannel SSD, OpenSSD, etc.) and SSD simulators (e.g. DiskSim+SSD, FlashSim,
SSDSim, etc.). Like hardware platforms, FEMU can support running full system
stack (Applications + OS + NVMe interface) on top, thus enabling
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
  git clone https://github.com/ucare-uchicago/femu.git
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

  Tested host environment: 

  ```
  OS: Ubuntu 16.04.5 LTS
  gcc: 5.4.0
  Ninja: 1.8.2
  Python: 3.6 
  ```
  
> Notes: FEMU is now re-based on QEMU-5.2.0, which requires >=Python-3.6 and >=Ninjia-1.7 to build, 
> check [here](https://wiki.qemu.org/ChangeLog/5.2#Build_Dependencies) for installing
> these dependencies if ``pkgdep.sh`` doesn't solve all the requirements.)


3. Prepare the VM image (For performance reasons, we suggest to use a server
   version guest OS [e.g. Ubuntu Server 16.04, 14.04])

  You can either build your own VM image, or use the VM image provided by us

  **Option 1**: Use our VM image, please download it from our
  [FEMU-VM-image-site](https://goo.gl/forms/NptPVEOy9EnwN70Y2) and save it as
  `$HOME/images/u14s.qcow2`. After you fill in the query, VM image downloading
  link will be sent to your email address shortly. ***Please make sure to provide
  a correct email address when filling the above form. Contact
  [Huaicheng Li](mailto:huaicheng@cs.uchicago.edu) upon any problems.***

  **Option 2**: Build your own VM image by following guides (e.g.
  [here](https://help.ubuntu.com/community/Installation/QemuEmulator#Installation_of_an_operating_system_from_ISO_to_the_QEMU_environment)).
  After the guest OS is installed, make following changes to redirect VM output
  to the console, instead of using a separate GUI window. (**Desktop version
  guest OS is not tested**)

   - Inside your guest Ubuntu server, edit `/etc/default/grub`, make sure the
     following options are set.

```
GRUB_CMDLINE_LINUX="ip=dhcp console=ttyS0,115200 console=tty console=ttyS0"
GRUB_TERMINAL=serial
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
```

   - Still in the VM, update the grub
   
```
$ sudo update-grub
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

### 1. Run FEMU as blackbox SSDs (``Device-managed FTL`` mode) ###

**TODO:** currently blackbox SSD parameters are hard-coded in
`hw/block/femu/ftl/ftl.c`, please change them accordingly and re-compile FEMU.

Boot the VM using the following
script:

```Bash
./run-blackbox.sh
```

### 2. Run FEMU as whitebox SSDs (``OpenChannel-SSDs`` mode) ###

```Bash
./run-whitebox.sh
```

Inside the VM, you can play with LightNVM.

Currently FEMU only supports [OpenChannel Specification
1.2](http://lightnvm.io/docs/Open-ChannelSSDInterfaceSpecification12-final.pdf),
the newer 2.0 spec support in work-in-progress and will be added soon.

### 3. Run FEMU without SSD logic emulation (``NoSSD`` mode) ###

```Bash
./run-nossd.sh
```

In this ``nossd`` mode, no SSD emulation logic (either blackbox or whitebox
emulation) will be executed.  Base NVMe specification is supported, and FEMU in
this case handles IOs as fast as possible. It can be used for basic performance
benchmarking, as well as fast storage-class memory (SCM) emulation. 

### 4. Run FEMU as ZNS (Zoned-Namespace) SSDs (``ZNS-SSDs`` mode) ###

To be released!


## For more details, please checkout the [Wiki](https://github.com/ucare-uchicago/femu/wiki)!

