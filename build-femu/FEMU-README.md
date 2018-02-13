# FEMU README #

## Installation ##

**Make sure you already install necessary libraries for building QEMU**

Then,

  $ cd build-femu

  $ ./femu-compile.sh

## Before running ##

- **FEMU currently uses its own malloc'ed space for data storage, instead of using
image-files. However, FEMU still requires a image-file in QEMU command line so
as to cheat QEMU to probe correct internal numbers about the backend storage.
Thus, if you want to emulate an SSD of 32GB, you need to create an image file
of 32GB on your local filesystem and attach it to QEMU**

- FEMU relies on DRAM to provide accurate delay emulation, so make sure you
  have enought available DRAM free space for the emulated SSD

## Run an emulated SSD in blackbox mode (device-managed FTL) ##


Under this mode, each emulated NVMe SSD needs configuration files in the format
of vssd1.conf, vssd2.conf to run.

The key configuration options are explained below:

It configures an emulated SSD with 8 channels and there are 8 chips on each channel.
The total SSD size is 1GB.

```
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
```




  $ cd build-femu

  $ ./wcc-run.sh

## Run an emulated SSD in whitebox mode (OpenChannel-SSD) ##

  $ cd build-femu

  $ ./femu-run.sh



