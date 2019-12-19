```
  ______ ______ __  __ _    _ 
 |  ____|  ____|  \/  | |  | |
 | |__  | |__  | \  / | |  | |
 |  __| |  __| | |\/| | |  | |
 | |    | |____| |  | | |__| |
 |_|    |______|_|  |_|\____/ 

```
                              
Contact Information
--------------------

**Maintainer**: [Huaicheng Li](people.cs.uchicago.edu/~huaicheng/) (huaicheng@cs.uchicago.edu)

If you have any suggestions, general discussions about FEMU or bug reports, please do not hesistate to contact Huaicheng. We would like to hear your thoughts!

Please cite our FEMU paper if you use FEMU. The bib entry is

```
@InProceedings{Li+18-FEMU, 
Author = {Huaicheng Li and Mingzhe Hao and Michael Hao Tong 
and Swaminathan Sundararaman and Matias Bjørling and Haryadi S. Gunawi},
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
  ```

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
  - Or, more conviniently, FEMU running script has mapped host port `8080` to
    guest VM port `22`, thus, after you install and run `openssh-server` inside
    the VM, you can also ssh into the VM via below command line. (Please run it
    from your host machine)
  
  ```
  $ ssh -p8080 $user@localhost
  ```

Run FEMU
--------

### 1. Before running ###

- FEMU currently uses its own malloc'ed space for data storage, instead of
  using image-files. However, FEMU still requires a image-file in QEMU command
  line so as to cheat QEMU to probe correct internal numbers about the backend
  storage.  Thus, if you want to emulate an SSD of 32GB, you need to create an
  image file of 32GB on your local file system and attach it to QEMU. (This
  limitation will be remove in near future)

- FEMU relies on DRAM to provide accurate delay emulation, so make sure you
  have enough DRAM free space for the emulated SSD.

- Only **Guest Linux version >= 4.14** are supported as FEMU requires the
  shadow doorbell buffer support in Linux NVMe driver implementation. (Linux
  4.12, 4.13 are abandoned due to their wrong implementation in doorbell buffer
  config support.)

- To achieve best performance, users need to disable the
  doorbell write operations in guest Linux NVMe driver since FEMU uses polling.
  Please see [here](#ddb) on how to do this.

### 2. Run FEMU as an emulated blackbox SSD (device-managed FTL) ###

**TODO:** currently blackbox SSD parameters are hard-coded in
`hw/block/femu/ftl/ftl.c`, please change them accordingly and re-compile FEMU.

Boot the VM using the following
script:

```Bash
./run-blackbox.sh
```

### 3. Run FEMU as an emulated whitebox SSD (OpenChannel-SSD) ###

```Bash
./run-whitebox.sh
```

Inside the VM, you can play with LightNVM.

Currently FEMU only supports [OpenChannel Specification
1.2](http://lightnvm.io/docs/Open-ChannelSSDInterfaceSpecification12-final.pdf),
the newer 2.0 spec support in work-in-progress and will be added soon.

### 4. Run FEMU without SSD logic emulation ###

```Bash
./run-nossd.sh
```

In this ``nossd`` mode, no SSD emulation logic (either blackbox or whitebox
emulation) will be executed.  Base NVMe specification is supported, and FEMU in
this case handles IOs as fast as possible. It can be used for basic performance
benchmarking.

Tuning
------


Debugging
---------

FEMU Design
-----------
Please refer to our FAST paper and design document (to come) ...


Additonal Tweaks
----------------

1. <a name="ddb"></a>Disable doorbell writes in your guest Linux NVMe driver:

**Note: Linux kernel version less than 4.14 has a wrong implementation over the
doorbell buffer config support bit. (Fixed in this commit:
223694b9ae8bfba99f3528d49d07a740af6ff95a). FEMU has been updated to fix this
problem accordingly. Thus, in order for FEMU polling to work properly out of
box, please use guest Linux >= 4.14.

Otherwise, if you want to stick to 4.12/4.13, please make sure
``NVME_OACS_DBBUF = 1 << 7`` in ``hw/block/nvme.h`` as this is what was wrongly
implemented in 4.12/4.13**

In Linux 4.14 source code, file ``drivers/nvme/host/pcie.c``, around ``line
293``, you will find below function which is used to indicate whether to
perform doorbell write operations.

What we need to do is to add one sentence (``return false;``) after ``*dbbuf_db
= value;``, as shown in the code block below.

After this, recompile your guest Linux kernel.

```C
/* Update dbbuf and return true if an MMIO is required */
static bool nvme_dbbuf_update_and_check_event(u16 value, u32 *dbbuf_db,
					      volatile u32 *dbbuf_ei)
{
	if (dbbuf_db) {
		u16 old_value;

		/*
		 * Ensure that the queue is written before updating
		 * the doorbell in memory
		 */
		wmb();

		old_value = *dbbuf_db;
		*dbbuf_db = value;

		/* Disable Doorbell Writes for FEMU: We only need to 
		 * add the following statement */
		return false;
		/* End FEMU modification for NVMe driver */

		if (!nvme_dbbuf_need_event(*dbbuf_ei, value, old_value))
			return false;
	}

	return true;
}
```

