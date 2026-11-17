Windows Hypervisor Platform
===========================

Windows Hypervisor Platform is the Windows API for use of
third-party virtual machine monitors with hardware acceleration
on Hyper-V.

It's implemented on top of ``Vid``, which is itself implemented
on the same set of hypercalls as the ``mshv`` driver on Linux.

WHPX is the name of the Windows Hypervisor Platform accelerator
backend in QEMU. It enables using QEMU with hardware acceleration
on both x86_64 and arm64 Windows machines.

Prerequisites
-------------

WHPX requires the Windows Hypervisor Platform feature to be installed.

Installation
^^^^^^^^^^^^
On client editions of Windows, that means installation through
Windows Features (``optionalfeatures.exe``). On server editions,
feature-based installation in Server Manager can be used.

Alternatively, command line installation is also possible through:
``DISM /online /Enable-Feature /FeatureName:HypervisorPlatform /All``

Minimum OS version
^^^^^^^^^^^^^^^^^^

On x86_64, QEMU's Windows Hypervisor Platform backend is tested 
starting from Windows 10 version 2004. Earlier Windows 10 releases
*might* work but are not tested.

On arm64, Windows 11 24H2 with the April 2025 optional updates
or May 2025 security updates is the minimum required release. 

Prior releases of Windows 11 version 24H2 on ARM64 shipped 
with a pre-release version of the Windows Hypervisor Platform
API, which is not supported in QEMU.

Quick Start
-----------

Launching a virtual machine on x86_64 with WHPX acceleration::

    $ qemu-system-x86_64.exe -accel whpx -M pc \
        -smp cores=2 -m 2G -device ich9-usb-ehci1 \
        -device usb-tablet -hda OS.qcow2

Launching a virtual machine on arm64 with WHPX acceleration::

    $ qemu-system-aarch64.exe -accel whpx -M virt \
        -cpu host -smp cores=2 -m 2G \
        -bios edk2-aarch64-code.fd \
        -device ramfb -device nec-usb-xhci \
        -device usb-kbd -device usb-tablet \
        -hda OS.qcow2

On arm64, for non-Windows guests, ``-device virtio-gpu-pci`` provides
additional functionality compared to ``-device ramfb``, but is
incompatible with Windows's UEFI GOP implementation, which
expects a linear framebuffer to be available.

Accelerator options
--------------------

x86_64
^^^^^^

``-trace whpx_unsupported_msr_access`` can be used to log accesses
to undocumented MSRs.

``-d invalid_mem`` allows to trace accesses to unmapped
GPAs.

``-accel whpx,ssd=off`` disables the separate security domain feature,
as in a BTB flush when entering/exiting the guest. This results in a
significant MMIO performance increase at the detriment of security
mitigations.

Known issues on x86_64
----------------------

Guests using legacy VGA modes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In guests using VGA modes that QEMU doesn't pass through framebuffer
memory for, performance will be quite suboptimal.

Workaround: for affected guests, use a more modern graphics mode.
Alternatively, use TCG to run those guests.

Guests using MMX, SSE or AVX instructions for MMIO
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Currently, ``target/i386/emulate`` does not support guests that use
MMX, SSE or AVX instructions for access to MMIO memory ranges.

Attempts to run such guests will result in an ``Unimplemented handler``
warning for MMX and a failure to decode for newer instructions.

PIC interrupts on Windows 10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On Windows 10, a legacy PIC interrupt injected does not wake the guest
from an HLT when using the Hyper-V provided interrupt controller.

As such, on Windows 10, using the Hyper-V interrupt controller is
disabled by default. You can enable it via ``-M q35,pic=off`` which
disables the PIC. In that configuration, using a UEFI is recommended.

On this release, ``-M kernel-irqchip=`` is not expected to be manually
set during normal operation. It remains as a debugging option.

Known issues on Windows 11
^^^^^^^^^^^^^^^^^^^^^^^^^^

arm64
-----

ISA feature support
^^^^^^^^^^^^^^^^^^^

SVE and SME are not currently supported.
