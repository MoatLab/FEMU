\ *****************************************************************************
\ * Copyright (c) 2015 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Note: The PCI ID 1af4:1050 is used for both, virtio-vga and virtio-gpu
\ devices. Only the first one provides a VGA interface that we currently
\ support in SLOF.

my-space pci-class@ 30000 = IF
    s" virtio [ vga ]" type cr
    s" qemu-vga.fs" included
ELSE
    s" virtio [ gpu ]" type cr
    my-space pci-device-generic-setup
THEN
