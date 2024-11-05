# Running skiboot and Linux in Mambo

The POWER8 Functional Simulator (aka Mambo) is free to use but not
open source and is only supported on limited platforms.  This is a
guide to getting started guide with it with skiboot and linux.

## Getting Started

From a bare x86_64 Ubuntu 16.04 install, to running skiboot and linux
in the simulator, you can do do the following:

### Steps to get Running on Ubuntu
xterm is needed by the simulator.
```
apt-get install xterm
```

### Download mambo from IBM
Download systemsim-p8..deb from:
http://www-304.ibm.com/support/customercare/sas/f/pwrfs/home.html
```
dpkg -i systemsim-p8*deb
```

### Grab your skiboot, linux and initramfs images
How to build a skiboot.lid is in the top level README file.

Use a 64 bit powerpc kernel here. If compiling yourself, we suggest
using powernv_defconfig.

If you use op-build to build a full set of OpenPower images, you’ll
likely be able to extract skiboot, zImage.epapr (or vmlinux and
rootfs.cpio.xz) from output/images. We suggest using the
opal_defconfig.

### Setup environment variables
Setup environment variables to point to your images
```
export SKIBOOT_ZIMAGE=$HOME/src/op-build/output/images/zImage.epapr
export SKIBOOT=$HOME/src/op-build/output/images/skiboot.lid
export SKIBOOT_AUTORUN=1
```
If you want Mambo to autmatically run *AND* exit when the system is
shutdown (or has a HW crash) use this:
```
export SKIBOOT_AUTORUN=2
```
If you want a vmlinux and separate initramfs you can also do this:
```
export SKIBOOT_ZIMAGE=$HOME/src/op-build/output/images/vmlinux
export SKIBOOT_INITRD=$HOME/src/op-build/output/images/rootfs.cpio.xz
export SKIBOOT=$HOME/src/skiboot/skiboot.lid
export SKIBOOT_AUTORUN=1
```

### Using Real Container Verification Code for Secure Boot

The CVC code dump is from a real machine, and the code is from the Hostboot
project (see src/securerom). We just include the dump here for testing
purposes.

```
export SKIBOOT_CVC_CODE=$HOME/src/skiboot/external/mambo/cvc.bin
export SKIBOOT_ENABLE_MAMBO_STB=1
```

### Run the simulator
```
/opt/ibm/systemsim-p8/run/pegasus/power8 -f $HOME/src/skiboot/external/mambo/skiboot.tcl
```

This should open an xterm and start booting.  It should take around
20sec to get to a petitboot console.
