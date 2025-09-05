/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#pragma pack(1)
typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_negotiate_algorithms_request_spdm11_t;

typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    uint32_t extra[21];
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_negotiate_algorithms_request_spdm11_oversized_t;

typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[12];
} libspdm_negotiate_algorithms_request_spdm11_multiple_tables_t;

typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_negotiate_algorithms_request_spdm12_t;

typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[5];
} libspdm_negotiate_algorithms_request_spdm12_more_algo_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t reserved;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint8_t reserved2[12];
    uint8_t ext_asym_sel_count;
    uint8_t ext_hash_sel_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_algorithms_response_mine_t;
#pragma pack()

spdm_negotiate_algorithms_request_t m_libspdm_negotiate_algorithms_request1 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
    sizeof(spdm_negotiate_algorithms_request_t),
    SPDM_MEASUREMENT_SPECIFICATION_DMTF,
};
size_t m_libspdm_negotiate_algorithms_request1_size =
    sizeof(m_libspdm_negotiate_algorithms_request1);

spdm_negotiate_algorithms_request_t m_libspdm_negotiate_algorithms_request2 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
    sizeof(spdm_negotiate_algorithms_request_t),
    SPDM_MEASUREMENT_SPECIFICATION_DMTF,
};
size_t m_libspdm_negotiate_algorithms_request2_size = sizeof(spdm_message_header_t);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request3 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request3_size = sizeof(m_libspdm_negotiate_algorithm_request3);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request4 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request4_size = sizeof(m_libspdm_negotiate_algorithm_request4);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request5 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request5_size = sizeof(m_libspdm_negotiate_algorithm_request5);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request6 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request6_size = sizeof(m_libspdm_negotiate_algorithm_request6);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request7 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request7_size = sizeof(m_libspdm_negotiate_algorithm_request7);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request8 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request8_size = sizeof(m_libspdm_negotiate_algorithm_request8);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request9 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            0x00000020
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request9_size = sizeof(m_libspdm_negotiate_algorithm_request9);

spdm_negotiate_algorithms_request_t m_libspdm_negotiate_algorithm_request10 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_NEGOTIATE_ALGORITHMS,
        0,
        0
    },
    0x44,
    SPDM_MEASUREMENT_SPECIFICATION_DMTF,
};
size_t m_libspdm_negotiate_algorithm_request10_size = 0x44;

libspdm_negotiate_algorithms_request_spdm11_oversized_t m_libspdm_negotiate_algorithm_request11 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_oversized_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {0},
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request11_size =
    sizeof(m_libspdm_negotiate_algorithm_request11);

libspdm_negotiate_algorithms_request_spdm11_multiple_tables_t
    m_libspdm_negotiate_algorithm_request12 =
{
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            12,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_multiple_tables_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request12_size =
    sizeof(m_libspdm_negotiate_algorithm_request12);

libspdm_negotiate_algorithms_request_spdm11_t
    m_libspdm_negotiate_algorithm_request13 =
{
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            3,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t)-
        sizeof(spdm_negotiate_algorithms_common_struct_table_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request13_size =
    sizeof(m_libspdm_negotiate_algorithm_request13)-
    sizeof(
        spdm_negotiate_algorithms_common_struct_table_t);

libspdm_negotiate_algorithms_request_spdm11_t
    m_libspdm_negotiate_algorithm_request14 =
{
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            5,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t)+
        sizeof(spdm_negotiate_algorithms_common_struct_table_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
    }
};
size_t m_libspdm_negotiate_algorithm_request14_size =
    sizeof(m_libspdm_negotiate_algorithm_request14)+
    sizeof(
        spdm_negotiate_algorithms_common_struct_table_t);

libspdm_negotiate_algorithms_request_spdm11_t
    m_libspdm_negotiate_algorithm_request15 =
{
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            12,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            1,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request15_size =
    sizeof(m_libspdm_negotiate_algorithm_request15);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request16 = {
    {
        {
            SPDM_MESSAGE_VERSION_11,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request16_size =
    sizeof(m_libspdm_negotiate_algorithm_request16);

libspdm_negotiate_algorithms_request_spdm12_t
    m_libspdm_negotiate_algorithm_request17 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request17_size =
    sizeof(m_libspdm_negotiate_algorithm_request17);

libspdm_negotiate_algorithms_request_spdm12_t
    m_libspdm_negotiate_algorithm_request18 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        /* Illegal OpaqueDataFmt. */
        0x04,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request18_size =
    sizeof(m_libspdm_negotiate_algorithm_request18);

libspdm_negotiate_algorithms_request_spdm11_t m_libspdm_negotiate_algorithm_request24 = {
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm11_t),
        0, /* SPDM_MEASUREMENT_SPECIFICATION_DMTF */
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request24_size =
    sizeof(m_libspdm_negotiate_algorithm_request24);

libspdm_negotiate_algorithms_request_spdm12_t
    m_libspdm_negotiate_algorithm_request25 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request25_size =
    sizeof(m_libspdm_negotiate_algorithm_request25);

libspdm_negotiate_algorithms_request_spdm12_t
    m_libspdm_negotiate_algorithm_request26 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request26_size =
    sizeof(m_libspdm_negotiate_algorithm_request26);

libspdm_negotiate_algorithms_request_spdm12_more_algo_t
    m_libspdm_negotiate_algorithm_request27 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            5,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_more_algo_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE - 1,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
    }
};
size_t m_libspdm_negotiate_algorithm_request27_size =
    sizeof(m_libspdm_negotiate_algorithm_request27);

libspdm_negotiate_algorithms_request_spdm12_more_algo_t
    m_libspdm_negotiate_algorithm_request28 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            5,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_more_algo_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE + 1,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request28_size =
    sizeof(m_libspdm_negotiate_algorithm_request28);

libspdm_negotiate_algorithms_request_spdm12_t
    m_libspdm_negotiate_algorithm_request29 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm12_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            /* No supported AlgTypes */
            0x00
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};
size_t m_libspdm_negotiate_algorithm_request29_size =
    sizeof(m_libspdm_negotiate_algorithm_request29);

spdm_negotiate_algorithms_request_t m_libspdm_negotiate_algorithms_request30 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_NEGOTIATE_ALGORITHMS, 0, 0 },
    sizeof(spdm_negotiate_algorithms_request_t),
    SPDM_MEASUREMENT_SPECIFICATION_DMTF,
    SPDM_ALGORITHMS_MULTI_KEY_CONN,
};
size_t m_libspdm_negotiate_algorithms_request30_size =
    sizeof(m_libspdm_negotiate_algorithms_request30);

void libspdm_test_responder_algorithms_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
}

void libspdm_test_responder_algorithms_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request2_size,
        &m_libspdm_negotiate_algorithms_request2, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
}

void libspdm_test_responder_algorithms_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
}

void libspdm_test_responder_algorithms_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case7(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request3_size,
                                              &m_libspdm_negotiate_algorithm_request3,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_algorithms_response_t)+4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

    assert_int_equal (spdm_response->struct_table[0].alg_supported,
                      spdm_context->local_context.algorithm.dhe_named_group);
    assert_int_equal (spdm_response->struct_table[1].alg_supported,
                      spdm_context->local_context.algorithm.aead_cipher_suite);
    assert_int_equal (spdm_response->struct_table[2].alg_supported,
                      spdm_context->local_context.algorithm.req_base_asym_alg);
    assert_int_equal (spdm_response->struct_table[3].alg_supported,
                      spdm_context->local_context.algorithm.key_schedule);
}

void libspdm_test_responder_algorithms_case8(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request4_size,
                                              &m_libspdm_negotiate_algorithm_request4,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case9(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request5_size,
                                              &m_libspdm_negotiate_algorithm_request5,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request6_size,
                                              &m_libspdm_negotiate_algorithm_request6,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case11(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request7_size,
                                              &m_libspdm_negotiate_algorithm_request7,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case12(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request8_size,
                                              &m_libspdm_negotiate_algorithm_request8,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case13(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request9_size,
                                              &m_libspdm_negotiate_algorithm_request9,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case14(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request10_size,
                                              &m_libspdm_negotiate_algorithm_request10,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case15(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request11_size,
                                              &m_libspdm_negotiate_algorithm_request11,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case16(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request12_size,
                                              &m_libspdm_negotiate_algorithm_request12,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case17(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request13_size,
                                              &m_libspdm_negotiate_algorithm_request13,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case18(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request14_size,
                                              &m_libspdm_negotiate_algorithm_request14,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case19(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request15_size,
                                              &m_libspdm_negotiate_algorithm_request15,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/* When both of requester and responder support multiple algorithms, then defaults to choose the strongest available algorithm*/
void libspdm_test_responder_algorithms_case20(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->local_context.algorithm.base_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    spdm_context->local_context.algorithm.dhe_named_group =
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
        SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request16_size,
                                              &m_libspdm_negotiate_algorithm_request16,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_algorithms_response_t)+4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

    assert_int_equal (spdm_response->base_hash_sel, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512);
    assert_int_equal (spdm_response->base_hash_sel,
                      spdm_context->connection_info.algorithm.base_hash_algo);

    assert_int_equal (spdm_response->base_asym_sel,
                      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
    assert_int_equal (spdm_response->base_asym_sel,
                      spdm_context->connection_info.algorithm.base_asym_algo);

    assert_int_equal (spdm_response->struct_table[0].alg_supported,
                      SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1);
    assert_int_equal (spdm_response->struct_table[0].alg_supported,
                      spdm_context->connection_info.algorithm.dhe_named_group);

    assert_int_equal (spdm_response->struct_table[1].alg_supported,
                      spdm_context->connection_info.algorithm.aead_cipher_suite);
    assert_int_equal (spdm_response->struct_table[2].alg_supported,
                      spdm_context->connection_info.algorithm.req_base_asym_alg);
    assert_int_equal (spdm_response->struct_table[3].alg_supported,
                      spdm_context->connection_info.algorithm.key_schedule);
}

void libspdm_test_responder_algorithms_case21(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;
    size_t arbitrary_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    /*filling A with arbitrary data*/
    arbitrary_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = arbitrary_size;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context,
        m_libspdm_negotiate_algorithm_request3_size, &m_libspdm_negotiate_algorithm_request3,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_algorithms_response_t) +
                     4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_11);

    assert_int_equal(spdm_response->struct_table[0].alg_supported,
                     spdm_context->local_context.algorithm.dhe_named_group);
    assert_int_equal(spdm_response->struct_table[1].alg_supported,
                     spdm_context->local_context.algorithm.aead_cipher_suite);
    assert_int_equal(spdm_response->struct_table[2].alg_supported,
                     spdm_context->local_context.algorithm.req_base_asym_alg);
    assert_int_equal(spdm_response->struct_table[3].alg_supported,
                     spdm_context->local_context.algorithm.key_schedule);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     arbitrary_size + m_libspdm_negotiate_algorithm_request3_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size,
                        &m_libspdm_negotiate_algorithm_request3,
                        m_libspdm_negotiate_algorithm_request3_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size +
                        m_libspdm_negotiate_algorithm_request3_size, response, response_size);
}

void libspdm_test_responder_algorithms_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_algorithms_response_mine_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    /* spdm_context->connection_info.algorithm.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1; */
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request17_size,
                                              &m_libspdm_negotiate_algorithm_request17,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_algorithms_response_t)+4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->header.param1, 4);
    assert_int_equal (spdm_response->struct_table[0].alg_supported,
                      spdm_context->local_context.algorithm.dhe_named_group);
    assert_int_equal (spdm_response->struct_table[1].alg_supported,
                      spdm_context->local_context.algorithm.aead_cipher_suite);
    assert_int_equal (spdm_response->struct_table[2].alg_supported,
                      spdm_context->local_context.algorithm.req_base_asym_alg);
    assert_int_equal (spdm_response->struct_table[3].alg_supported,
                      spdm_context->local_context.algorithm.key_schedule);
}

void libspdm_test_responder_algorithms_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    /* Sub Case 1: other_params_support set Illegal OpaqueDataFmt */
    m_libspdm_negotiate_algorithm_request18.spdm_request_version10.other_params_support = 0x04;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request18_size,
                                              &m_libspdm_negotiate_algorithm_request18,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);

    /* Sub Case 2: other_params_support set OpaqueDataFmt1 */
    m_libspdm_negotiate_algorithm_request18.spdm_request_version10.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request18_size,
                                              &m_libspdm_negotiate_algorithm_request18,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_algorithms_response_t) + 4*
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->other_params_selection, SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    assert_int_equal(spdm_context->connection_info.algorithm.other_params_support,
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);

    /* Sub Case 3: Populate reserved field for version 1.2, field values marked as Reserved shall be written as zero ( 0 )*/
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 |
        SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);
    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request18_size,
                                              &m_libspdm_negotiate_algorithm_request18,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_algorithms_response_t) + 4*
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->other_params_selection, SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    assert_int_equal(spdm_context->connection_info.algorithm.other_params_support,
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);

    /* Sub Case 4: OpaqueDataFmt. Supports both SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0 and SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1*/
    m_libspdm_negotiate_algorithm_request18.spdm_request_version10.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0 |
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0 |
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);
    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request18_size,
                                              &m_libspdm_negotiate_algorithm_request18,
                                              &response_size,
                                              response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_algorithms_response_t) + 4*
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->other_params_selection, SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    assert_int_equal(spdm_context->connection_info.algorithm.other_params_support,
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
}

void libspdm_test_responder_algorithms_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request24_size,
                                              &m_libspdm_negotiate_algorithm_request24,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_algorithms_response_t) +
                     4*sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->measurement_hash_algo, 0);
    assert_int_equal(spdm_response->measurement_specification_sel, 0);
}

void libspdm_test_responder_algorithms_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request25_size,
                                              &m_libspdm_negotiate_algorithm_request25,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request26_size,
                                              &m_libspdm_negotiate_algorithm_request26,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request27_size,
                                              &m_libspdm_negotiate_algorithm_request27,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.capability.flags = 0;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request28_size,
                                              &m_libspdm_negotiate_algorithm_request28,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

void libspdm_test_responder_algorithms_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms (spdm_context,
                                              m_libspdm_negotiate_algorithm_request29_size,
                                              &m_libspdm_negotiate_algorithm_request29,
                                              &response_size,
                                              response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}

/**
 * Test 30: MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP value calculation
 * +---------------+--------------------------+--------------------+
 * | MULTI_KEY_CAP | RequesterMultiKeyConnSel | MULTI_KEY_CONN_REQ |
 * +---------------+--------------------------+--------------------+
 * | 00b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 00b           | 1                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 0                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 1                        | true               |
 *  ----------------------------------------------------------------
 * | 10b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 10b           | 1                        | true               |
 * +---------------+--------------------------+--------------------+
 * | MULTI_KEY_CAP | ResponderMultiKeyConn    | MULTI_KEY_CONN_RSP |
 * +---------------+--------------------------+--------------------+
 * | 00b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 00b           | 1                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 0                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 1                        | true               |
 *  ----------------------------------------------------------------
 * | 10b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 10b           | 1                        | true               |
 *  ----------------------------------------------------------------
 **/
void libspdm_test_responder_algorithms_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_hash_algo = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->local_context.capability.flags = 0;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->connection_info.capability.flags = 0;
    m_libspdm_negotiate_algorithms_request30.other_params_support = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, false);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, false);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.capability.flags = 0;
    m_libspdm_negotiate_algorithms_request30.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);
    /* MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP invalid */
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    m_libspdm_negotiate_algorithms_request30.other_params_support = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);
    /* MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP invalid */
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    m_libspdm_negotiate_algorithms_request30.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, true);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, true);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;
    m_libspdm_negotiate_algorithms_request30.other_params_support = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, false);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, false);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;
    m_libspdm_negotiate_algorithms_request30.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, true);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, true);
}


/**
 * Test 31: NEGOTIATE_ALGORITHMS message received with MEL correct
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_responder_algorithms_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_hash_algo = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    /* Sub Case 1: MEL_CAP set 1, mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    m_libspdm_negotiate_algorithms_request30.other_params_support = 0;
    m_libspdm_negotiate_algorithms_request30.mel_specification = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->mel_specification_sel, SPDM_MEL_SPECIFICATION_DMTF);
    assert_int_equal(spdm_context->connection_info.algorithm.mel_spec, SPDM_MEL_SPECIFICATION_DMTF);

    /* Sub Case 2: MEL_CAP set 0, mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    m_libspdm_negotiate_algorithms_request30.mel_specification = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request30_size,
        &m_libspdm_negotiate_algorithms_request30, &response_size,
        response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->mel_specification_sel, 0);
    assert_int_equal(spdm_context->connection_info.algorithm.mel_spec, 0);
}

/**
 * Test 32: NEGOTIATE_ALGORITHMS message received with MEAS correct
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_responder_algorithms_case32(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_algorithms_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->local_context.algorithm.measurement_spec |= SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.other_params_support = 0;
    libspdm_reset_message_a(spdm_context);

    /* Sub Case 1: MEL_CAP set 1, measurement_spec set SPDM_MEASUREMENT_SPECIFICATION_DMTF*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.algorithm.measurement_spec |= SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->measurement_specification_sel,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    assert_int_equal(spdm_context->connection_info.algorithm.measurement_spec,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);

    /* Sub Case 2: MEL_CAP set 0, measurement_spec set 0*/
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.measurement_hash_algo = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    m_libspdm_negotiate_algorithms_request1.measurement_specification = 0;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_algorithms(
        spdm_context, m_libspdm_negotiate_algorithms_request1_size,
        &m_libspdm_negotiate_algorithms_request1, &response_size,
        response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_algorithms_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ALGORITHMS);
    assert_int_equal(spdm_response->measurement_specification_sel, 0);
    assert_int_equal(spdm_context->connection_info.algorithm.measurement_spec, 0);
}

libspdm_test_context_t m_libspdm_responder_algorithms_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_algorithms_test_main(void)
{
    const struct CMUnitTest spdm_responder_algorithms_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case2),
        /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case4),
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case6),
        /* Success case V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case7),
        /* No match for base_asym_algo*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case8),
        /* No match for base_hash_algo*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case9),
        /* No match for dhe_named_group*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case10),
        /* No match for aead_cipher_suite*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case11),
        /* No match for req_base_asym_alg*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case12),
        /* No match for key_schedule*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case13),
        /* Spdm length greater than 64 bytes for V1.0*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case14),
        /* Spdm length greater than 128 bytes for V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case15),
        /* Multiple repeated Alg structs for V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case16),
        /* param1 is smaller than the number of Alg structs for V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case17),
        /* param1 is bigger than the number of  Alg structs for V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case18),
        /* Invalid  Alg structs + valid Alg Structs for V1.1*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case19),
        /* When support multiple algorithms, then defaults to choose the strongest available algorithm*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case20),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case21),
        /* Success case V1.2*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case22),
        /* Version 1.2 Check other_params_support */
        cmocka_unit_test(libspdm_test_responder_algorithms_case23),
        /* No support for MEASUREMENT from requester*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case24),
        /* Invalid (Redundant) alg_type value*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case25),
        /* Invalid (Decreasing) alg_type value*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case26),
        /* Invalid (smaller than DHE) alg_type value*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case27),
        /* Invalid (bigger than KEY_SCHEDULE) alg_type value*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case28),
        /* Invalid AlgStruct, contains an AlgSupported=0 (Non-supported)*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case29),
        /* MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP value validation*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case30),
        /* Success Case , set MELspecificationSel*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case31),
        /* Success Case , set MeasurementSpecification*/
        cmocka_unit_test(libspdm_test_responder_algorithms_case32),
    };

    m_libspdm_negotiate_algorithms_request1.base_asym_algo = m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithms_request1.base_hash_algo = m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithms_request2.base_asym_algo = m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithms_request2.base_hash_algo = m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request3.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request3.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request4.spdm_request_version10.base_asym_algo =
        (m_libspdm_use_asym_algo >> 1);
    m_libspdm_negotiate_algorithm_request4.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request5.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request5.spdm_request_version10.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    m_libspdm_negotiate_algorithm_request6.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request6.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request7.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request7.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request8.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request8.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request9.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request9.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request10.base_asym_algo = m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request10.base_hash_algo = m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request10.ext_asym_count = 0x09;
    m_libspdm_negotiate_algorithm_request11.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request11.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request11.spdm_request_version10.ext_asym_count = 0x15;
    m_libspdm_negotiate_algorithm_request12.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request12.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request13.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request13.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request14.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request14.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request15.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request15.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request16.spdm_request_version10.base_asym_algo =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    m_libspdm_negotiate_algorithm_request16.spdm_request_version10.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    m_libspdm_negotiate_algorithm_request17.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request17.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request18.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_negotiate_algorithm_request18.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    m_libspdm_negotiate_algorithm_request24.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;
    libspdm_setup_test_context(&m_libspdm_responder_algorithms_test_context);

    return cmocka_run_group_tests(spdm_responder_algorithms_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
