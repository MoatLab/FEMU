/*
 * QEMU "hardware version" constant
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_HW_VERSION_H
#define QEMU_HW_VERSION_H

/*
 * Starting on QEMU 2.5, devices with a version string in their
 * identification data return "2.5+" instead of QEMU_VERSION.  Do
 * NOT change this string as it is visible to guests.
 */
#define QEMU_HW_VERSION "2.5+"

#endif
