\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Handle virtio-fs device

s" virtio [ network ]" type cr

my-space pci-device-generic-setup
s" virtio-9p" device-name

pci-master-enable
pci-mem-enable
pci-io-enable

s" virtio-fs.fs" included

pci-device-disable
