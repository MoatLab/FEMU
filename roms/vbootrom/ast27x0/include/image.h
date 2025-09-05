/*
 * Copyright (C) 2025 ASPEED Technology Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AST27X0_INCLUDE_IMAGE_H__
#define __AST27X0_INCLUDE_IMAGE_H__

#define DRAM_ADDR   0x400000000ULL
#define FMCCS0      0x100000000ULL

/* FMC v2 */
/* ASTH */
#define FMC_HDR_MAGIC 0x48545341
#define ECC_SIGN_LEN  96
#define LMS_SIGN_LEN  1620
#define SHA_DGST_LEN  48

struct hdr_preamble {
    uint32_t magic;
    uint32_t version;
    uint32_t ecc_key_idx;
    uint32_t lms_key_idx;
    uint8_t ecc_sig[ECC_SIGN_LEN];
    uint8_t lms_sig[LMS_SIGN_LEN];
    uint32_t raz[15];
};

struct hdr_body {
    uint32_t svn;
    uint32_t size;
    uint8_t dgst[SHA_DGST_LEN];
    /* 712 bytes */
    uint8_t reserved[178 * 4];
};

struct ast_fmc_header {
    struct hdr_preamble preamble;
    struct hdr_body body;
} __attribute__((packed));

struct fmc_img_info {
    uint64_t payload_start;
    uint64_t payload_end;
};

#endif /* __AST27X0_INCLUDE_IMAGE_H__ */
