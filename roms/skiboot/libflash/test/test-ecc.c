// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libflash/ecc.h>

#include "../ecc.c"

#define __unused		__attribute__((unused))

#define ERR(fmt...) fprintf(stderr, fmt)

#define NUM_ECC_ROWS 320

/*
 * Note this data is big endian as this is what the ecc code expects.
 * The ECC code returns IBM bit numbers assuming the word was in CPU
 * endian!
 */

/* 8 data bytes 1 ecc byte per row */
struct ecc64 ecc_data[] = {
	{ 0xfeffffffffffffff, 0x00 }, /* This row will have ecc correct bit 63 */
	{ 0xfdffffffffffffff, 0x00 }, /* This row will have ecc correct bit 62 */
	{ 0xfbffffffffffffff, 0x00 }, /* This row will have ecc correct bit 61 */
	{ 0xf7ffffffffffffff, 0x00 }, /* This row will have ecc correct bit 60 */
	{ 0xefffffffffffffff, 0x00 }, /* This row will have ecc correct bit 59 */
	{ 0xdfffffffffffffff, 0x00 }, /* This row will have ecc correct bit 58 */
	{ 0xbfffffffffffffff, 0x00 }, /* This row will have ecc correct bit 57 */
	{ 0x7fffffffffffffff, 0x00 }, /* This row will have ecc correct bit 56 */
	{ 0xfffeffffffffffff, 0x00 }, /* This row will have ecc correct bit 55 */
	{ 0xfffdffffffffffff, 0x00 }, /* This row will have ecc correct bit 54 */
	{ 0xfffbffffffffffff, 0x00 }, /* This row will have ecc correct bit 53 */
	{ 0xfff7ffffffffffff, 0x00 }, /* This row will have ecc correct bit 52 */
	{ 0xffefffffffffffff, 0x00 }, /* This row will have ecc correct bit 51 */
	{ 0xffdfffffffffffff, 0x00 }, /* This row will have ecc correct bit 50 */
	{ 0xffbfffffffffffff, 0x00 }, /* This row will have ecc correct bit 49 */
	{ 0xff7fffffffffffff, 0x00 }, /* This row will have ecc correct bit 48 */
	{ 0xfffffeffffffffff, 0x00 }, /* This row will have ecc correct bit 47 */
	{ 0xfffffdffffffffff, 0x00 }, /* This row will have ecc correct bit 46 */
	{ 0xfffffbffffffffff, 0x00 }, /* This row will have ecc correct bit 45 */
	{ 0xfffff7ffffffffff, 0x00 }, /* This row will have ecc correct bit 44 */
	{ 0xffffefffffffffff, 0x00 }, /* This row will have ecc correct bit 43 */
	{ 0xffffdfffffffffff, 0x00 }, /* This row will have ecc correct bit 42 */
	{ 0xffffbfffffffffff, 0x00 }, /* This row will have ecc correct bit 41 */
	{ 0xffff7fffffffffff, 0x00 }, /* This row will have ecc correct bit 40 */
	{ 0xfffffffeffffffff, 0x00 }, /* This row will have ecc correct bit 39 */
	{ 0xfffffffdffffffff, 0x00 }, /* This row will have ecc correct bit 38 */
	{ 0xfffffffbffffffff, 0x00 }, /* This row will have ecc correct bit 37 */
	{ 0xfffffff7ffffffff, 0x00 }, /* This row will have ecc correct bit 36 */
	{ 0xffffffefffffffff, 0x00 }, /* This row will have ecc correct bit 35 */
	{ 0xffffffdfffffffff, 0x00 }, /* This row will have ecc correct bit 34 */
	{ 0xffffffbfffffffff, 0x00 }, /* This row will have ecc correct bit 33 */
	{ 0xffffff7fffffffff, 0x00 }, /* This row will have ecc correct bit 32 */
	{ 0xfffffffffeffffff, 0x00 }, /* This row will have ecc correct bit 31 */
	{ 0xfffffffffdffffff, 0x00 }, /* This row will have ecc correct bit 30 */
	{ 0xfffffffffbffffff, 0x00 }, /* This row will have ecc correct bit 29 */
	{ 0xfffffffff7ffffff, 0x00 }, /* This row will have ecc correct bit 28 */
	{ 0xffffffffefffffff, 0x00 }, /* This row will have ecc correct bit 27 */
	{ 0xffffffffdfffffff, 0x00 }, /* This row will have ecc correct bit 26 */
	{ 0xffffffffbfffffff, 0x00 }, /* This row will have ecc correct bit 25 */
	{ 0xffffffff7fffffff, 0x00 }, /* This row will have ecc correct bit 24 */
	{ 0xfffffffffffeffff, 0x00 }, /* This row will have ecc correct bit 23 */
	{ 0xfffffffffffdffff, 0x00 }, /* This row will have ecc correct bit 22 */
	{ 0xfffffffffffbffff, 0x00 }, /* This row will have ecc correct bit 21 */
	{ 0xfffffffffff7ffff, 0x00 }, /* This row will have ecc correct bit 20 */
	{ 0xffffffffffefffff, 0x00 }, /* This row will have ecc correct bit 19 */
	{ 0xffffffffffdfffff, 0x00 }, /* This row will have ecc correct bit 18 */
	{ 0xffffffffffbfffff, 0x00 }, /* This row will have ecc correct bit 17 */
	{ 0xffffffffff7fffff, 0x00 }, /* This row will have ecc correct bit 16 */
	{ 0xfffffffffffffeff, 0x00 }, /* This row will have ecc correct bit 15 */
	{ 0xfffffffffffffdff, 0x00 }, /* This row will have ecc correct bit 14 */
	{ 0xfffffffffffffbff, 0x00 }, /* This row will have ecc correct bit 13 */
	{ 0xfffffffffffff7ff, 0x00 }, /* This row will have ecc correct bit 12 */
	{ 0xffffffffffffefff, 0x00 }, /* This row will have ecc correct bit 11 */
	{ 0xffffffffffffdfff, 0x00 }, /* This row will have ecc correct bit 10 */
	{ 0xffffffffffffbfff, 0x00 }, /* This row will have ecc correct bit 9 */
	{ 0xffffffffffff7fff, 0x00 }, /* This row will have ecc correct bit 8 */
	{ 0xfffffffffffffffe, 0x00 }, /* This row will have ecc correct bit 7 */
	{ 0xfffffffffffffffd, 0x00 }, /* This row will have ecc correct bit 6 */
	{ 0xfffffffffffffffb, 0x00 }, /* This row will have ecc correct bit 5 */
	{ 0xfffffffffffffff7, 0x00 }, /* This row will have ecc correct bit 4 */
	{ 0xffffffffffffffef, 0x00 }, /* This row will have ecc correct bit 3 */
	{ 0xffffffffffffffdf, 0x00 }, /* This row will have ecc correct bit 2 */
	{ 0xffffffffffffffbf, 0x00 }, /* This row will have ecc correct bit 1 */
	{ 0xffffffffffffff7f, 0x00 }, /* This row will have ecc correct bit 0 */
	/*
	 * 'Randomised' input into eccgenerate 0x54f7c5d1 was seeded to rand()
	 * Note: eccgenerate from skiboot commit 6cfaa3ba1015c6ac9cc4a06f878b4289022cff54
	 * was used to generate these ecc numbers
	 */
	{ 0x29d87c7c8ab7d46d, 0xb9 }, /* Use this row to check eccgenerate() */
	{ 0x9064174098381641, 0x3b }, /* Use this row to check eccgenerate() */
	{ 0x77fd7d2fc7d22154, 0xe4 }, /* Use this row to check eccgenerate() */
	{ 0x6b02ba39b64a6168, 0xbf }, /* Use this row to check eccgenerate() */
	{ 0x68fa9c633eef0544, 0x2a }, /* Use this row to check eccgenerate() */
	{ 0xe814b258b3f92e55, 0x35 }, /* Use this row to check eccgenerate() */
	{ 0xc3e2bd658db4db6d, 0xda }, /* Use this row to check eccgenerate() */
	{ 0xe1dd487b6209876a, 0x45 }, /* Use this row to check eccgenerate() */
	{ 0x309f9e6b91831433, 0xe4 }, /* Use this row to check eccgenerate() */
	{ 0xd8b77d39f4d66410, 0x6c }, /* Use this row to check eccgenerate() */
	{ 0x83ba293cf30a9e6a, 0xc9 }, /* Use this row to check eccgenerate() */
	{ 0x3aeaef79af97ec1a, 0x09 }, /* Use this row to check eccgenerate() */
	{ 0xa90ef431e4778c43, 0x91 }, /* Use this row to check eccgenerate() */
	{ 0xa74bbf1e6b6fda00, 0xc5 }, /* Use this row to check eccgenerate() */
	{ 0x67b5a872efa57c30, 0xb9 }, /* Use this row to check eccgenerate() */
	{ 0x795d511e3605ff67, 0x03 }, /* Use this row to check eccgenerate() */
	{ 0xce3d1529918d256f, 0x36 }, /* Use this row to check eccgenerate() */
	{ 0x586047430ac2685e, 0xab }, /* Use this row to check eccgenerate() */
	{ 0xc00cca46463b9358, 0x42 }, /* Use this row to check eccgenerate() */
	{ 0x842a991cc362017d, 0xb2 }, /* Use this row to check eccgenerate() */
	{ 0x765c30522807672a, 0x26 }, /* Use this row to check eccgenerate() */
	{ 0xb5bb42186c3f4b75, 0x2b }, /* Use this row to check eccgenerate() */
	{ 0xce48d25f393fee37, 0x90 }, /* Use this row to check eccgenerate() */
	{ 0xcbc2026b96998b13, 0x40 }, /* Use this row to check eccgenerate() */
	{ 0x8b70f023ffe7704b, 0x23 }, /* Use this row to check eccgenerate() */
	{ 0xf2f20e36a37a8024, 0x19 }, /* Use this row to check eccgenerate() */
	{ 0x52126d3f0e2b1a60, 0xa0 }, /* Use this row to check eccgenerate() */
	{ 0xf2a2a6232dddfe2f, 0xc4 }, /* Use this row to check eccgenerate() */
	{ 0x984cd930fb206171, 0xa5 }, /* Use this row to check eccgenerate() */
	{ 0xeac6dd2199ee6542, 0xea }, /* Use this row to check eccgenerate() */
	{ 0xd0f3642aff018223, 0x3b }, /* Use this row to check eccgenerate() */
	{ 0x908fa71263242f40, 0x0a }, /* Use this row to check eccgenerate() */
	{ 0x6de6971e9e317a53, 0xa6 }, /* Use this row to check eccgenerate() */
	{ 0xe46c0d2ce8efee55, 0xa4 }, /* Use this row to check eccgenerate() */
	{ 0xab52f0522df36165, 0x06 }, /* Use this row to check eccgenerate() */
	{ 0x55fac80f6997a648, 0x9a }, /* Use this row to check eccgenerate() */
	{ 0xd5d6f13d21af2025, 0xed }, /* Use this row to check eccgenerate() */
	{ 0x5bee0e5d0bb60b28, 0x66 }, /* Use this row to check eccgenerate() */
	{ 0xa14f973ba41fc41d, 0xa8 }, /* Use this row to check eccgenerate() */
	{ 0xa307356926b11148, 0x5a }, /* Use this row to check eccgenerate() */
	{ 0xc92b926c2cc0875f, 0x7e }, /* Use this row to check eccgenerate() */
	{ 0x3aeba13f95fa431f, 0x92 }, /* Use this row to check eccgenerate() */
	{ 0xc2d7424f1b3eff2b, 0xe6 }, /* Use this row to check eccgenerate() */
	{ 0x165f601d2c8e4863, 0x2b }, /* Use this row to check eccgenerate() */
	{ 0xc67cae255a241c00, 0x78 }, /* Use this row to check eccgenerate() */
	{ 0x5a269e2300263e3f, 0x07 }, /* Use this row to check eccgenerate() */
	{ 0x634a6d7f96701350, 0xe9 }, /* Use this row to check eccgenerate() */
	{ 0x34a28d23eab54536, 0xd2 }, /* Use this row to check eccgenerate() */
	{ 0xd3a5340cd130051e, 0x48 }, /* Use this row to check eccgenerate() */
	{ 0xfe236703190f9b4f, 0x7e }, /* Use this row to check eccgenerate() */
	{ 0x82a641187ef8245f, 0x20 }, /* Use this row to check eccgenerate() */
	{ 0xa0a74504541e3013, 0xc7 }, /* Use this row to check eccgenerate() */
	{ 0x5fd43b3b577d3356, 0x85 }, /* Use this row to check eccgenerate() */
	{ 0xfb9cf773fb955461, 0x06 }, /* Use this row to check eccgenerate() */
	{ 0x214766290024d376, 0x80 }, /* Use this row to check eccgenerate() */
	{ 0x2de45a569ea42c5d, 0x22 }, /* Use this row to check eccgenerate() */
	{ 0x349f707cea72f815, 0xf3 }, /* Use this row to check eccgenerate() */
	{ 0x05b1f74167cffc15, 0xe9 }, /* Use this row to check eccgenerate() */
	{ 0x945d4579f676b34b, 0x63 }, /* Use this row to check eccgenerate() */
	{ 0x519bcf4b1b10585f, 0x47 }, /* Use this row to check eccgenerate() */
	{ 0x1b36961e5adaf31e, 0x25 }, /* Use this row to check eccgenerate() */
	{ 0xf04a076fabc16d6f, 0x20 }, /* Use this row to check eccgenerate() */
	{ 0x9577b3257e80031e, 0xef }, /* Use this row to check eccgenerate() */
	{ 0x4fb1083c24ed9412, 0x97 }, /* Use this row to check eccgenerate() */
	{ 0x3dfc2f62681de831, 0x1f }, /* Use this row to check eccgenerate() */
	{ 0xe7150d114ed56f3f, 0x10 }, /* Use this row to check eccgenerate() */
	{ 0xa2f39f52bfa2717a, 0x40 }, /* Use this row to check eccgenerate() */
	{ 0x1720a55087bd5215, 0xb3 }, /* Use this row to check eccgenerate() */
	{ 0x8253a77601c8db0d, 0x45 }, /* Use this row to check eccgenerate() */
	{ 0x01ecae0412bd9c44, 0x5f }, /* Use this row to check eccgenerate() */
	{ 0xb161c921a39a0d20, 0x51 }, /* Use this row to check eccgenerate() */
	{ 0x8d0d06362ed0095b, 0x94 }, /* Use this row to check eccgenerate() */
	{ 0x969f0671e5003a1e, 0x9b }, /* Use this row to check eccgenerate() */
	{ 0xdb77ed6992befd77, 0x63 }, /* Use this row to check eccgenerate() */
	{ 0xadce55572afd4b6a, 0x3e }, /* Use this row to check eccgenerate() */
	{ 0x84d73f092c13bd35, 0x50 }, /* Use this row to check eccgenerate() */
	{ 0xd7d42a25c804ec75, 0x05 }, /* Use this row to check eccgenerate() */
	{ 0x4685ef1374224778, 0x72 }, /* Use this row to check eccgenerate() */
	{ 0x980fdc0a6d4cde4a, 0x9d }, /* Use this row to check eccgenerate() */
	{ 0xd569c67c9636f84f, 0x81 }, /* Use this row to check eccgenerate() */
	{ 0xe40b680fd60b0c6d, 0x2c }, /* Use this row to check eccgenerate() */
	{ 0x95ae7d67bc7fd30d, 0x72 }, /* Use this row to check eccgenerate() */
	{ 0x433d262386ff0762, 0xf4 }, /* Use this row to check eccgenerate() */
	{ 0x87c7e36facce2238, 0x5a }, /* Use this row to check eccgenerate() */
	{ 0xbf8bbf7cc590cd19, 0xe0 }, /* Use this row to check eccgenerate() */
	{ 0x682bdb3988b39274, 0x4f }, /* Use this row to check eccgenerate() */
	{ 0xb7839c4f70ed881e, 0x6b }, /* Use this row to check eccgenerate() */
	{ 0x55eec23cf538e16f, 0x72 }, /* Use this row to check eccgenerate() */
	{ 0x87f7de674d23a340, 0xb4 }, /* Use this row to check eccgenerate() */
	{ 0x7720ef2a3066b026, 0x7c }, /* Use this row to check eccgenerate() */
	{ 0x5d796d5c34c6343f, 0x5e }, /* Use this row to check eccgenerate() */
	{ 0xfcca2035fbf72e34, 0xc6 }, /* Use this row to check eccgenerate() */
	{ 0x6f1a762c344e9801, 0x87 }, /* Use this row to check eccgenerate() */
	{ 0xa19a764c43501049, 0x35 }, /* Use this row to check eccgenerate() */
	{ 0xd9860819072a5237, 0x6a }, /* Use this row to check eccgenerate() */
	{ 0xdd355e2477043d49, 0x2d }, /* Use this row to check eccgenerate() */
	{ 0x33841057bd927028, 0xaa }, /* Use this row to check eccgenerate() */
	{ 0x4392780a73e4db0b, 0xfa }, /* Use this row to check eccgenerate() */
	{ 0x1fb3fe4377c1367a, 0x47 }, /* Use this row to check eccgenerate() */
	{ 0x3c520414ca595c7a, 0x58 }, /* Use this row to check eccgenerate() */
	{ 0x520def6ede3ebe40, 0xac }, /* Use this row to check eccgenerate() */
	{ 0x4e2c475fa57ddf4d, 0x5c }, /* Use this row to check eccgenerate() */
	{ 0x9ab6c03d09918b3e, 0x95 }, /* Use this row to check eccgenerate() */
	{ 0x56b42e7fa31a0a1c, 0x5d }, /* Use this row to check eccgenerate() */
	{ 0xd480ba4222ae9f25, 0x87 }, /* Use this row to check eccgenerate() */
	{ 0x5674d464cdd41d2a, 0xc7 }, /* Use this row to check eccgenerate() */
	{ 0xc8cc4c5e31fa271f, 0x6e }, /* Use this row to check eccgenerate() */
	{ 0x6548c020533ff519, 0x00 }, /* Use this row to check eccgenerate() */
	{ 0x968f056337e7c20a, 0x0e }, /* Use this row to check eccgenerate() */
	{ 0x3f11154207e3366d, 0xbe }, /* Use this row to check eccgenerate() */
	{ 0x7ee773366f160e7c, 0x53 }, /* Use this row to check eccgenerate() */
	{ 0x2ca97e241c477366, 0x1c }, /* Use this row to check eccgenerate() */
	{ 0x8f2b4f72b16b840d, 0x88 }, /* Use this row to check eccgenerate() */
	{ 0x282dbb076f3bf72e, 0xd0 }, /* Use this row to check eccgenerate() */
	{ 0x39955329afde4d36, 0xc7 }, /* Use this row to check eccgenerate() */
	{ 0x8d1d0c77657fbf1b, 0x22 }, /* Use this row to check eccgenerate() */
	{ 0x0afd9e698ba24218, 0x1a }, /* Use this row to check eccgenerate() */
	{ 0x9533ce56dc495356, 0x2a }, /* Use this row to check eccgenerate() */
	{ 0x7f645d72a4b35f27, 0x80 }, /* Use this row to check eccgenerate() */
	{ 0xc661ff4cebe7fc55, 0xe2 }, /* Use this row to check eccgenerate() */
	{ 0xb9bc1a0053e51735, 0xff }, /* Use this row to check eccgenerate() */
	{ 0x84df3f541dd6d331, 0x54 }, /* Use this row to check eccgenerate() */
	{ 0x7015c94b8189675e, 0x02 }, /* Use this row to check eccgenerate() */
	{ 0xb9702a69ea270075, 0x1f }, /* Use this row to check eccgenerate() */
	{ 0xf10a376206a5ce2e, 0x6f }, /* Use this row to check eccgenerate() */
	{ 0x75bbdc2af8813f2b, 0xb1 }, /* Use this row to check eccgenerate() */
	{ 0x14c9b2116ff2aa18, 0x7a }, /* Use this row to check eccgenerate() */
	{ 0x205e2f26a1645b4f, 0x2b }, /* Use this row to check eccgenerate() */
	{ 0x10a0527ea4f40104, 0xf6 }, /* Use this row to check eccgenerate() */
	{ 0x53d34f3a498bea2d, 0x93 }, /* Use this row to check eccgenerate() */
	{ 0xae0aaa494935a627, 0xbf }, /* Use this row to check eccgenerate() */
	{ 0xd4d7e83fe0f05b31, 0x58 }, /* Use this row to check eccgenerate() */
	{ 0xbc3aaf07b8074933, 0x74 }, /* Use this row to check eccgenerate() */
	{ 0x5cbba85a690bb716, 0xbf }, /* Use this row to check eccgenerate() */
	{ 0x55f3b36c3c9f0c7a, 0x3a }, /* Use this row to check eccgenerate() */
	{ 0x8f84242f231da827, 0x50 }, /* Use this row to check eccgenerate() */
	{ 0x40f37b590eb0ce6c, 0x9c }, /* Use this row to check eccgenerate() */
	{ 0x8f39364b14646403, 0x0b }, /* Use this row to check eccgenerate() */
	{ 0xfe8b6478b0084525, 0x21 }, /* Use this row to check eccgenerate() */
	{ 0xb6ad135448aa6034, 0x1c }, /* Use this row to check eccgenerate() */
	{ 0x402ca05fef969b5a, 0x90 }, /* Use this row to check eccgenerate() */
	{ 0x5e8946732b69f07e, 0xaa }, /* Use this row to check eccgenerate() */
	{ 0xcccd4b4e55f55271, 0xe8 }, /* Use this row to check eccgenerate() */
	{ 0xf9e954757ee77519, 0xf8 }, /* Use this row to check eccgenerate() */
	{ 0xc7726047dc6d9e4c, 0x67 }, /* Use this row to check eccgenerate() */
	{ 0x25a344744cbda42f, 0x77 }, /* Use this row to check eccgenerate() */
	{ 0x2cae0061757d0a11, 0xca }, /* Use this row to check eccgenerate() */
	{ 0x2d855344f97a2d34, 0x9b }, /* Use this row to check eccgenerate() */
	{ 0x6386e44ae9e8af68, 0x6c }, /* Use this row to check eccgenerate() */
	{ 0x2588bc628a40fc1e, 0x4c }, /* Use this row to check eccgenerate() */
	{ 0xad5da446b8799837, 0x31 }, /* Use this row to check eccgenerate() */
	{ 0xc6296724b40ce111, 0xde }, /* Use this row to check eccgenerate() */
	{ 0xc8704515ed502020, 0x72 }, /* Use this row to check eccgenerate() */
	{ 0x9d59654555639d6f, 0x16 }, /* Use this row to check eccgenerate() */
	{ 0x9e0dfe23c6fca90d, 0x37 }, /* Use this row to check eccgenerate() */
	{ 0xb593456853077919, 0xee }, /* Use this row to check eccgenerate() */
	{ 0x7e706918de399e03, 0xe7 }, /* Use this row to check eccgenerate() */
	{ 0x332ff174131d8c5b, 0x34 }, /* Use this row to check eccgenerate() */
	{ 0x920402754a3eb566, 0x2f }, /* Use this row to check eccgenerate() */
	{ 0x26ac53332c19466a, 0x0c }, /* Use this row to check eccgenerate() */
	{ 0x78d6ea195977623c, 0x6f }, /* Use this row to check eccgenerate() */
	{ 0xcff46c4d4b4f9827, 0x20 }, /* Use this row to check eccgenerate() */
	{ 0x44cac55ba584eb7a, 0x5f }, /* Use this row to check eccgenerate() */
	{ 0x8e6d9b63fc79c011, 0xc8 }, /* Use this row to check eccgenerate() */
	{ 0x86babc30a750aa26, 0x20 }, /* Use this row to check eccgenerate() */
	{ 0x5fca425eb3f55746, 0x12 }, /* Use this row to check eccgenerate() */
	{ 0x6702395833186177, 0xaf }, /* Use this row to check eccgenerate() */
	{ 0x2069811725f4a902, 0x87 }, /* Use this row to check eccgenerate() */
	{ 0x7b57477230737e6d, 0xd9 }, /* Use this row to check eccgenerate() */
	{ 0xf66f287bbdc2e65c, 0xfa }, /* Use this row to check eccgenerate() */
	{ 0x10ca5f7619654516, 0x52 }, /* Use this row to check eccgenerate() */
	{ 0xf79ee319ac036e63, 0x58 }, /* Use this row to check eccgenerate() */
	{ 0xbf20fa3e8e3ac90e, 0x82 }, /* Use this row to check eccgenerate() */
	{ 0xd8787e752bced40e, 0x54 }, /* Use this row to check eccgenerate() */
	{ 0x57e71a795125fc33, 0xfe }, /* Use this row to check eccgenerate() */
	{ 0xab9c5e70fe24d228, 0xfc }, /* Use this row to check eccgenerate() */
	{ 0x49746a50d0bd0513, 0x9d }, /* Use this row to check eccgenerate() */
	{ 0x7542f10d7a91cb3d, 0xb9 }, /* Use this row to check eccgenerate() */
	{ 0x760b8c4f8e3e302c, 0x82 }, /* Use this row to check eccgenerate() */
	{ 0x358fda5203b08c71, 0x23 }, /* Use this row to check eccgenerate() */
	{ 0xb6a5e437fdc54800, 0xb6 }, /* Use this row to check eccgenerate() */
	{ 0x30dea97795591d31, 0x7c }, /* Use this row to check eccgenerate() */
	{ 0xba4dc7331da81d10, 0x11 }, /* Use this row to check eccgenerate() */
	{ 0x4d1b9c7d51472b0f, 0x37 }, /* Use this row to check eccgenerate() */
	{ 0x0e0a126c35a50e26, 0xd6 }, /* Use this row to check eccgenerate() */
	{ 0x4e0a543c448bc478, 0x0f }, /* Use this row to check eccgenerate() */
	{ 0xf08e325c1fd47162, 0x6b }, /* Use this row to check eccgenerate() */
	{ 0xad0e3b7146a93756, 0x86 }, /* Use this row to check eccgenerate() */
	{ 0x71770c65afaf2c1b, 0xae }, /* Use this row to check eccgenerate() */
	{ 0x01d5284f8687b966, 0x37 }, /* Use this row to check eccgenerate() */
	{ 0x84ac8b0fc85e275e, 0x86 }, /* Use this row to check eccgenerate() */
	{ 0x981c2d71ac71873f, 0x4e }, /* Use this row to check eccgenerate() */
	{ 0x2603537dce20f65f, 0xb5 }, /* Use this row to check eccgenerate() */
	{ 0x5c5f260c0d5f1e7f, 0x0b }, /* Use this row to check eccgenerate() */
	{ 0x100fab709c0edf4c, 0xc9 }, /* Use this row to check eccgenerate() */
	{ 0x99d4274d91ee005f, 0x83 }, /* Use this row to check eccgenerate() */
	{ 0x26481e10c6b48f28, 0x16 }, /* Use this row to check eccgenerate() */
	{ 0xe45cad38cab2d144, 0x9c }, /* Use this row to check eccgenerate() */
	{ 0x1bfafc53e195e543, 0x8e }, /* Use this row to check eccgenerate() */
	{ 0x163bf46931784936, 0xdc }, /* Use this row to check eccgenerate() */
	{ 0x75030e2f29040f40, 0x48 }, /* Use this row to check eccgenerate() */
	{ 0x48d8802265454826, 0x2a }, /* Use this row to check eccgenerate() */
	{ 0xabee7f7c6592400b, 0x2b }, /* Use this row to check eccgenerate() */
	{ 0x15426d26f6e6bb13, 0x89 }, /* Use this row to check eccgenerate() */
	{ 0x7c6e757a1c668c61, 0x6d }, /* Use this row to check eccgenerate() */
	{ 0xe4c4b33f16179675, 0x74 }, /* Use this row to check eccgenerate() */
	{ 0xc2881d35001b010a, 0xd4 }, /* Use this row to check eccgenerate() */
	{ 0xce3bf7697de1e030, 0x65 }, /* Use this row to check eccgenerate() */
	{ 0x8a40ff2fe88b7032, 0x19 }, /* Use this row to check eccgenerate() */
	{ 0x849a4f7f2a9b1d76, 0x58 }, /* Use this row to check eccgenerate() */
	{ 0xbc891e559b4faa20, 0x4c }, /* Use this row to check eccgenerate() */
	{ 0x61043a491e6f774c, 0x28 }, /* Use this row to check eccgenerate() */
	{ 0xe8214911e2d13c65, 0x9e }, /* Use this row to check eccgenerate() */
	{ 0xc36722294561e701, 0x3d }, /* Use this row to check eccgenerate() */
	{ 0x77d93038031c4665, 0x55 }, /* Use this row to check eccgenerate() */
	{ 0x2c205525daa21613, 0x85 }, /* Use this row to check eccgenerate() */
	{ 0x3fe85e39ecdc3e67, 0x20 }, /* Use this row to check eccgenerate() */
	{ 0x526f7f7275f8d547, 0xa4 }, /* Use this row to check eccgenerate() */
	{ 0x6bdf915bead6de35, 0xac }, /* Use this row to check eccgenerate() */
	{ 0x063d6b1767b1ec18, 0x78 }, /* Use this row to check eccgenerate() */
	{ 0x7dc8820ee74d0756, 0x31 }, /* Use this row to check eccgenerate() */
	{ 0xe7680860ea011f57, 0x3f }, /* Use this row to check eccgenerate() */
	{ 0x67e3ff073f51a043, 0xd6 }, /* Use this row to check eccgenerate() */
	{ 0x27dd1076b6a4ff49, 0x10 }, /* Use this row to check eccgenerate() */
	{ 0xe03f1d40f223ff37, 0xec }, /* Use this row to check eccgenerate() */
	{ 0x8d73a958ab776075, 0x6f }, /* Use this row to check eccgenerate() */
	{ 0xc9e6d7419cc93b15, 0x8f }, /* Use this row to check eccgenerate() */
	{ 0x7f9b787aee77e321, 0xb7 }, /* Use this row to check eccgenerate() */
	{ 0x34d9ca23b1082153, 0xa9 }, /* Use this row to check eccgenerate() */
	{ 0xb424673842039b23, 0xe2 }, /* Use this row to check eccgenerate() */
	{ 0x1ca6b136abb2fb5b, 0xe1 }, /* Use this row to check eccgenerate() */
	{ 0x978f3a43e144bc5d, 0x64 }, /* Use this row to check eccgenerate() */
	{ 0x563d92255b8e1070, 0x14 }, /* Use this row to check eccgenerate() */
	{ 0x4565ef25e9feb935, 0x2d }, /* Use this row to check eccgenerate() */
	{ 0x50b0a64ec11c2401, 0x3c }, /* Use this row to check eccgenerate() */
	{ 0xa86a2b574ba25a3d, 0x8b }, /* Use this row to check eccgenerate() */
	{ 0x36a47914cd78295d, 0xf1 }, /* Use this row to check eccgenerate() */
	{ 0x0ccac9208fd33337, 0xe4 }, /* Use this row to check eccgenerate() */
	{ 0x457833019d87791c, 0xc4 }, /* Use this row to check eccgenerate() */
	{ 0x8fab785433a7da16, 0x0c }, /* Use this row to check eccgenerate() */
	{ 0xdf1e3b0c26b85041, 0x94 }, /* Use this row to check eccgenerate() */
	{ 0xc2818c561c1f222d, 0x9a }, /* Use this row to check eccgenerate() */
	{ 0x0b97054fa805134e, 0xec }, /* Use this row to check eccgenerate() */
	{ 0x5a0e3421411d0551, 0x57 }, /* Use this row to check eccgenerate() */
	{ 0x8420a0743f70d072, 0xa8 }, /* Use this row to check eccgenerate() */
	{ 0xea22cc4e0e339b59, 0x15 }, /* Use this row to check eccgenerate() */
	{ 0xef775737a0c6512b, 0xe7 }, /* Use this row to check eccgenerate() */
	{ 0xfc54621b81b20612, 0x9a }, /* Use this row to check eccgenerate() */
	{ 0x6bb1c04745b5e95c, 0x1e }, /* Use this row to check eccgenerate() */
	{ 0x06d20d5e41ba5141, 0x56 }, /* Use this row to check eccgenerate() */
	{ 0x8d5cac7ebb616716, 0x43 }, /* Use this row to check eccgenerate() */
	{ 0x89da9073ae3c3935, 0xb1 }, /* Use this row to check eccgenerate() */
	{ 0x3e106d6cc3002613, 0xec }, /* Use this row to check eccgenerate() */
	{ 0x60889f2f95a45a14, 0x69 }, /* Use this row to check eccgenerate() */
	{ 0xc94b352b8388a06d, 0x53 }, /* Use this row to check eccgenerate() */
	{ 0xa940f12ef0331804, 0x7a }, /* Use this row to check eccgenerate() */

};

int main(void)
{
	int i;
	uint8_t ret_memcpy;
	uint8_t ret_verify;
	uint64_t dst;
	uint64_t *buf;
	struct ecc64 *ret_buf;

	/*
	 * Test that eccgenerate() still works, but skip the first 64 because they
	 * have intentional bitflips
	 */
	printf("Checking eccgenerate()\n");
	for (i = 64; i < NUM_ECC_ROWS; i++) {
		if (eccgenerate(be64toh(ecc_data[i].data)) != ecc_data[i].ecc) {
			ERR("ECC did not generate the correct value, expecting 0x%02x, got 0x%02x\n",
					ecc_data[i].ecc, eccgenerate(be64toh(ecc_data[i].data)));
		}
	}

	/* Test that the ecc code can detect and recover bitflips */
	printf("Testing bitflip recovery\n");
	for (i = 0; i < 64; i++) {
		ret_memcpy = memcpy_from_ecc(&dst, &ecc_data[i], sizeof(dst));
		if (dst != 0xffffffffffffffff || ret_memcpy) {
			ERR("ECC code didn't correct bad bit %d in 0x%016lx\n", 63 - i, be64toh(ecc_data[i].data));
			exit(1);
		}

		ret_verify = eccverify(be64toh(ecc_data[i].data), ecc_data[i].ecc);
		if (ret_verify != 63 - i) {
			ERR("ECC did not catch incorrect bit %d in row 0x%016lx 0x%02x, got 0x%02x\n",
					i, ecc_data[i].data, ecc_data[i].ecc, ret_verify);
			exit(1);
		}
	}

	buf = malloc(NUM_ECC_ROWS * sizeof(*buf));
	if (!buf) {
		ERR("malloc #1 failed during ecc test\n");
		exit(1);
	}
	printf("pass\n");

	/* Test a large memcpy */
	printf("Testing a large(ish) memcpy_from_ecc()\n");
	ret_memcpy = memcpy_from_ecc(buf, ecc_data, NUM_ECC_ROWS * sizeof(*buf));
	if (ret_memcpy) {
		ERR("ECC Couldn't memcpy entire buffer\n");
		exit(1);
	}

	for (i = 0; i < NUM_ECC_ROWS; i++) {
		/* Large memcpy should have fixed the bitflips */
		if (i < 64 && buf[i] != 0xffffffffffffffff) {
			ERR("memcpy_from_ecc got it wrong for uint64_t number %d, got 0x%016lx, expecting 0xffffffffffffffff\n",
					i, buf[i]);
			exit(1);
		}

		/* But not changed any of the correct data */
		if (i > 63 && buf[i] != ecc_data[i].data) {
			ERR("memcpy_from_ecc got it wrong for uint64_t number %d, git 0x%016lx, expecting 0x%016lx\n",
					i, buf[i], ecc_data[i].data);
			exit(1);
		}
	}
	printf("pass\n");

	/* Test a memcpy to add ecc data */
	printf("Testing a large(ish) memcpy_to_ecc()\n");
	ret_buf = malloc(ecc_buffer_size(NUM_ECC_ROWS * sizeof(*buf)));
	if (!buf) {
		ERR("malloc #2 failed during ecc test\n");
		exit(1);
	}

	ret_memcpy = memcpy_to_ecc(ret_buf, buf, NUM_ECC_ROWS * sizeof(*buf));
	if (ret_memcpy) {
		ERR("ECC Couldn't memcpy entire buffer\n");
		exit(1);
	}

	for (i = 0; i < NUM_ECC_ROWS; i++) {
		/* The data should be the same */
		if (ret_buf[i].data != buf[i]) {
			ERR("memcpy_to_ecc got it wrong on uint64_t %d, expecting 0x%016lx, got 0x%016lx\n",
					i, buf[i], ret_buf[i].data);
			exit(1);
		}

		/* Check the correctness of ecc bytes */
		if (ret_buf[i].ecc != ecc_data[i].ecc) {
			ERR("memcpy_to_ecc got it on the ecc for uint64_t %d, expecting 0x%02x, got 0x%02x\n",
					i, ecc_data[i].ecc, ret_buf[i].ecc);
			exit(1);
		}
	}
	printf("ECC tests pass\n");

	printf("ECC test error conditions\n");
	if (memcpy_to_ecc(ret_buf, buf, 7) == 0) {
		ERR("memcpy_to_ecc didn't detect bad size 7\n");
		exit(1);
	}

	if (memcpy_to_ecc(ret_buf, buf, 15) == 0) {
		ERR("memcpy_to_ecc didn't detect bad size 15\n");
		exit(1);
	}
	if (memcpy_from_ecc(buf, ret_buf, 7) == 0) {
		ERR("memcpy_from_ecc didn't detect bad size 7\n");
		exit(1);
	}
	if (memcpy_from_ecc(buf, ret_buf, 15) == 0) {
		ERR("memcpy_from_ecc didn't detect bad size 15\n");
		exit(1);
	}
	printf("ECC error conditions pass\n");

	free(buf);
	free(ret_buf);

	/* Check that unaligned address become aligned */
	if (ecc_buffer_align(0, 5) != 0) {
		ERR("ecc_buffer_align(0, 5) not 0 -> %ld\n", ecc_buffer_align(0, 5));
		exit(1);
	}

	if (ecc_buffer_align(0, 8) != 0) {
		ERR("ecc_buffer_align(0, 8) not 0 -> %ld\n", ecc_buffer_align(0, 8));
		exit(1);
	}
	if (ecc_buffer_align(0, 9) != 9) {
		ERR("ecc_buffer_align(0, 9) not 9 -> %ld\n", ecc_buffer_align(0, 9));
		exit(1);
	}
	if (ecc_buffer_align(0, 15) != 9) {
		ERR("ecc_buffer_align(0, 15) not 9 -> %ld\n", ecc_buffer_align(0, 15));
		exit(1);
	}
	if (ecc_buffer_align(5, 10) != 5) {
		ERR("ecc_buffer_align(5, 10) not 5 -> %ld\n", ecc_buffer_align(5, 10));
		exit(1);
	}
	if (ecc_buffer_align(5, 18) != 14) {
		ERR("ecc_buffer_align(5, 18) not 14 -> %ld\n", ecc_buffer_align(5, 18));
		exit(1);
	}
	if (ecc_buffer_align(0, 50) != 45) {
		ERR("ecc_buffer_align(0, 50) not 45 -> %ld\n", ecc_buffer_align(0, 50));
		exit(1);
	}
	return 0;
}
