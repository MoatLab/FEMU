# skiboot

Firmware for OpenPower systems.

Source: https://github.com/open-power/skiboot

Mailing list: skiboot@lists.ozlabs.org

Info/subscribe: https://lists.ozlabs.org/listinfo/skiboot

Archives: https://lists.ozlabs.org/pipermail/skiboot/

Patchwork: http://patchwork.ozlabs.org/project/skiboot/list/

Documentation: http://open-power.github.io/skiboot/doc/index.html

## Overview
OPAL firmware (OpenPower Abstraction Layer) comes in several parts.

A simplified flow of what happens when the power button is pressed is:

1. The baseboard management controller (BMC) powers the system on.
2. The BMC selects the master chip and releases the self-boot engines (SBEs)
   on the POWER8 chips, master last.
3. The BMC relinquishes control of the flexible service interface (FSI)
   SCAN/SCOM engines.
4. The hostboot firmware IPLs the system. It initiates a secondary power-on
   sequence through a digital power systems sweep (DPSS).
5. The hostboot firmware loads the OPAL image and moves all processors to
   their execution starting points.

Here, the OPAL image is three parts:

1. skiboot (includes OPAL runtime services)
2. skiroot - the bootloader environment
   * kernel
   * initramfs (containing petitboot bootloader)

They may be all part of one payload or three separate images (depending on
platform).

The bootloader will kexec a host kernel (probably linux). The host OS can
make OPAL calls. The OPAL API is documented in doc/opal-api/ (there are
missing parts, patches are welcome!)

See doc/overview.rst for a more in depth overview of skiboot.

## Building

Any host OS can build and test skiboot provided it has a C cross compiler
for *big endian* powerpc64. All good Linux distributions (and several bad
ones) provide a packaged compiler that can be installed through the usual
package management tools.

To build on Ubuntu:
```
apt-get install gcc-powerpc64le-linux-gnu gcc valgrind \
	expect libssl-dev device-tree-compiler make \
	xz-utils libmbedtls-dev
CROSS=powerpc64le-linux-gnu- make -j`nproc`
```

To build on Fedora:
```
dnf install gcc-powerpc64le-linux-gnu binutils-powerpc64-linux-gnu gcc make \
    diffutils findutils expect valgrind-devel dtc openssl-devel xz \
    mbedtls-devel
CROSS=powerpc64le-linux-gnu- make -j`nproc`
```

(The little-endian powerpc64le compilers in Ubuntu and Fedora are actually
bi-endian and can compile skiboot even though it's big-endian. We recommend
installing a little-endian toolchain if you plan on building other projects.)

On any POWER system with a bi-endian system compiler:
```
CROSS="" make -j`nproc`
```

Alternatively, pre-built cross compilers for x86 systems can be downloaded
from here: https://www.kernel.org/pub/tools/crosstool/ When using
these compilers add /opt/cross/gcc-4.8.0-nolibc/powerpc64-linux/bin/
to your PATH. Once this is done skiboot can be compiler by just running `make`

### Building Documentation

We use [Sphinx](http://www.sphinx-doc.org/) to produce various documentation
from reStructuredText (preferred) and Markdown. The Sphinx documentation has
a useful primer for  reStructuredText
[here](http://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html).
And the docutils website has a nice [quick
reference](http://docutils.sourceforge.net/docs/user/rst/quickref.html) for the
basic constructes.

Building on Fedora
```
dnf install python3-sphinx python3-recommonmark.noarch
pip install -r doc/requirements.txt
make -C doc/ html SPHINXBUILD=sphinx-build-3
```

On Ubuntu:
```
Patches welcome!
```

View the output using `doc/_build/html/index.html`

## Testing
Skiboot comes with a set of unit tests that can be run on your desktop.
They can can be run with:
```
make check
```

To test in a simulator, install the IBM POWER8 Functional Simulator from:
http://www-304.ibm.com/support/customercare/sas/f/pwrfs/home.html
Also see external/mambo/README.md

Qemu as of version 2.8 implements the 'powernv' machine model and is sufficient
to run skiboot:

 qemu-system-ppc64 -M powernv -m 3G -nographic -L /path/to/skiboot/

To run a boot-to-bootloader test you need a Linux kernel image 'zImage.epapr'.
Build one using the `opal_defconfig` config for op-build. See
https://github.com/open-power/op-build/ on how to build, or download one from
https://openpower.xyz/job/openpower/job/openpower-op-build/.

Drop zImage.epapr in the skiboot directory and the skiboot test suite will
automatically pick it up. You can also run a combined skiboot and Linux test in
Qemu (version 3.0+):

 qemu-system-ppc64 -M powernv -m 3G -nographic -kernel zImage.epapr -L /path/to/skiboot/

See opal-ci/README for further testing instructions.

To test on real hardware, you will need to understand how to flash new
skiboot onto your system. This will vary from platform to platform.

You may want to start with external/boot-tests/boot_test.sh as it can
(provided the correct usernames/passwords) automatically flash a new
skiboot onto ASTBMC based OpenPower machines.

## Hacking

All patches should be sent to the mailing list with linux-kernel style
'Signed-Off-By'. The following git commands are your friends:
```
git commit -s
git format-patch
```

You probably want to read the linux
https://kernel.org/doc/html/latest/process/submitting-patches.html as
much of it applies to skiboot.


## Output files

The Skiboot build process produces a bunch of different outputs. This is what
they are, and where you should use them:

 skiboot.elf: The output of the linker. Don't flash to a system, but useful when debugging

 skiboot.lid: The raw binary object, named .lid because IBM. Flash this on
	      really old P8 systems, the POWER Functional Simulator (mambo), or
	      FSP systems

 skiboot.lid.stb: Lid wrapped with secure boot header. Use on FSP systems

 skiboot.lid.xz: Compressed raw binary. Use this on a OpenPower P8

 skiboot.lid.xz.stb: Compressed raw binary wrapped with a secure boot header.
                     Use this on OpenPower P9 systems

## License

See LICENSE
