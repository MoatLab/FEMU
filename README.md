FEMU README
===========
-------------------

Project Description
-------------------

Briefly speaking, FEMU is an NVMe SSD Emulator. Based upon QEMU/KVM, FEMU is exposed to Guest OS (Linux) as an NVMe block device (e.g. /dev/nvme0nX). It can be used as an emulated whitebox or blackbox SSD: (1). whitebox mode (a.k.a. Software-Defined Flash (SDF), or OpenChannel-SSD) with FTL residing in the host side (e.g. LightNVM) (2). blackbox mode with FTL residing inside the device (most of current commercial SSDs).

FEMU tries to achieve benefits of both SSD Hardware platforms (e.g. CNEX OpenChannel SSD, OpenSSD, etc.) and SSD simulators (e.g. DiskSim+SSD, FlashSim, SSDSim, etc.). Like hardware platforms, FEMU can support running full system stack (Applications + OS + NVMe interface) on top, thus enabling Software-Defined Flash (SDF) alike research with modifications at application, OS, interface or SSD controller architecture level. Like SSD simulators, FEMU can also support internal-SSD/FTL related research. Users can feel free to experiment with new FTL algorithms or SSD performance models to explore new SSD architecture innovations as well as benchmark the new arch changes with real applications, instead of using decade-old disk trace files.

Installation
------------


1. Make sure you have installed necessary libraries for building QEMU. The dependencies can be installed automatically by

	```bash
	# Switch to the FEMU building directory
	cd femu/build-femu
	# Copy femu script
	cp -r ../femu-scripts/[pkgdep,femu-compile,lnvm-run,wcc-run,pin].sh ../femu-scripts/ftk ../femu-scripts/vssd1.conf . 
	# only Debian based distributions supported
	sudo ./pkgdep.sh 
	```
		
2. Compile & Install FEMU:

	```bash
	./femu-compile.sh
	```
	FEMU binary will appear as ``x86_64-softmmu/qemu-system-x86_64``

Run FEMU
--------

### 1. Before running ###

- FEMU currently uses its own malloc'ed space for data storage, instead of using
image-files. However, FEMU still requires a image-file in QEMU command line so
as to cheat QEMU to probe correct internal numbers about the backend storage.
Thus, if you want to emulate an SSD of 32GB, you need to create an image file
of 32GB on your local filesystem and attach it to QEMU. (This limitation will be remove in near future)

- FEMU relies on DRAM to provide accurate delay emulation, so make sure you
  have enough DRAM free space for the emulated SSD.
  
- Only **Guest Linux version >= 4.12** are supported as FEMU requires the shadow doorbell buffer support in Linux NVMe driver implementation. **Optionally**, to achieve best performance, users need to disable the doorbell write operations in guest Linux NVMe driver since FEMU uses polling. Please see [here](#ddb) for how to do this. 

### 2. Run FEMU as an emulated blackbox SSD (device-managed FTL) ###

Under this mode, each emulated NVMe SSD needs configuration files in the format
of vssd1.conf, vssd2.conf, ..., etc. to run.

The key configuration options are explained below:

It configures an emulated SSD with 8 channels and there are 8 chips on each channel.
The total SSD size is 1GB.
	
    	PAGE_SIZE           4096            // SSD page size in bytes
    	PAGE_NB             256             // # of pages in one block
    	SECTOR_SIZE         512             // # sector size in bytes
    	FLASH_NB            64              // total # of NAND chips
    	BLOCK_NB            16              // # of blocks in one chip

    	REG_WRITE_DELAY     40000           // channel transfer time for one page (program) in nanosecond
    	CELL_PROGRAM_DELAY  800000          // NAND page program latency in nanosecond
    	REG_READ_DELAY      60000           // NAND page read latency in nanosecond
    	CELL_READ_DELAY     40000           // channel transfer time for one page (read) in nanosecond
    	BLOCK_ERASE_DELAY   3000000         // Block erase latency in nanosecond
    	CHANNEL_NB          8               // # of channels
    	GC_MODE             2               // GC blocking mode, see hw/block/ssd/common.h for definition
	
After the FEMU configuration file is ready, boot the VM using the following script:

```Bash
./wcc-run.sh
```

### 3. Run FEMU as an emulated whitebox SSD (OpenChannel-SSD) ###

```Bash
./lnvm-run.sh
```

Inside the VM, you can play with LightNVM. 

Currently FEMU only supports [OpenChannel Specification 1.2](http://lightnvm.io/docs/Open-ChannelSSDInterfaceSpecification12-final.pdf), the newer 2.0 spec support in work-in-progress and will be added soon.
  
Tuning
------
To Add ...


Debugging
---------
To Add ...

FEMU Design
-----------
Please refer to our FAST paper and design document (to come) ... 
  
  
Additonal Tweaks
----------------

1. <a name="ddb"></a>Disable doorbell writes in your guest Linux NVMe driver:

In Linux 4.12 source code, file ``drivers/nvme/host/pcie.c``, around ``line 293``, you will find below function which is used to indicate whether to perform doorbell write operations. 

What we need to do is to add one sentence (``return false;``) after ``*dbbuf_db = value;``, as shown in the code block below.

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




