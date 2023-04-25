# Running skiboot and Linux in AWAN

AWAN is a hardware accelerator composed of programmable gate arrays that can
emulate a POWER logic core.  The AWAN environment can be used to run hardware
procedures or test binaries on the logic, before hardware is available or when
hardware is scarce.

The AWAN environment is slow compared to Mambo and QEMU.  Each timebase tick is
equivalent to 8 simclocks, and simclock is slow.  For example, on the core
model we get through Skiboot in about 6 million simclock cycles and that takes
approximately 1 minute wall-clock time to complete.

# Getting started

To run in AWAN, you need a an initial checkpoint, a loader, and a method to
read memory.

The high-level sequence for running in AWAN is:

1.  Load an initial checkpoint provided by the person that built the model

2.  Load a stripped vmlinux at 0

3.  Load an initramfs at 0x28200000

4.  Load skiboot.lid at 0x30000000

5.  Load a small piece of start code at 0x100 that tells skiboot where to find
    the device tree blob

6.  Load a compiled device tree blob at 0x1f00000

7.  Run "simclock 5000000" and check the console buffer for the Skiboot log
    by reading memory at 784MB.
