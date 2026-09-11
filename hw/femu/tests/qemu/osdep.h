/*
 * Minimal stand-in so the NAND media layer and its unit test build outside
 * QEMU. The real osdep.h provides these standard headers among much else; the
 * media layer needs nothing further from QEMU -- see the Makefile for why that
 * is worth keeping true.
 */
#ifndef FEMU_TEST_OSDEP_H
#define FEMU_TEST_OSDEP_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#endif
