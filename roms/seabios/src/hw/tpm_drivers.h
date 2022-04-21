#ifndef TPM_DRIVERS_H
#define TPM_DRIVERS_H

#include "types.h" // u32


enum tpmDurationType {
    TPM_DURATION_TYPE_SHORT = 0,
    TPM_DURATION_TYPE_MEDIUM,
    TPM_DURATION_TYPE_LONG,
};

typedef u8 TPMVersion;

#define TPM_VERSION_NONE 0
#define TPM_VERSION_1_2  1
#define TPM_VERSION_2    2

TPMVersion tpmhw_probe(void);
int tpmhw_is_present(void);
struct tpm_req_header;
int tpmhw_transmit(u8 locty, struct tpm_req_header *req,
                   void *respbuffer, u32 *respbufferlen,
                   enum tpmDurationType to_t);
void tpmhw_set_timeouts(u32 timeouts[4], u32 durations[3]);

/* CRB driver */
/* address of locality 0 (CRB) */
#define TPM_CRB_BASE_ADDRESS        0xfed40000

#define CRB_REG(LOCTY, REG)                                 \
    (void *)(TPM_CRB_BASE_ADDRESS + (LOCTY << 12) + REG)

/* hardware registers */
#define CRB_REG_LOC_STATE              0x0
#define CRB_REG_LOC_CTRL               0x8
#define CRB_REG_LOC_STS                0xC
#define CRB_REG_INTF_ID                0x30
#define CRB_REG_CTRL_EXT               0x38
#define CRB_REG_CTRL_REQ               0x40
#define CRB_REG_CTRL_STS               0x44
#define CRB_REG_CTRL_CANCEL            0x48
#define CRB_REG_CTRL_START             0x4C
#define CRB_REG_INT_ENABLE             0x50
#define CRB_REG_INT_STS                0x54
#define CRB_REG_CTRL_CMD_SIZE          0x58
#define CRB_REG_CTRL_CMD_LADDR         0x5C
#define CRB_REG_CTRL_CMD_HADDR         0x60
#define CRB_REG_CTRL_RSP_SIZE          0x64
#define CRB_REG_CTRL_RSP_ADDR          0x68
#define CRB_REG_DATA_BUFFER            0x80

/* TIS driver */
/* address of locality 0 (TIS) */
#define TPM_TIS_BASE_ADDRESS        0xfed40000

#define TIS_REG(LOCTY, REG) \
    (void *)(TPM_TIS_BASE_ADDRESS + (LOCTY << 12) + REG)

/* hardware registers */
#define TIS_REG_ACCESS                 0x0
#define TIS_REG_INT_ENABLE             0x8
#define TIS_REG_INT_VECTOR             0xc
#define TIS_REG_INT_STATUS             0x10
#define TIS_REG_INTF_CAPABILITY        0x14
#define TIS_REG_STS                    0x18
#define TIS_REG_DATA_FIFO              0x24
#define TIS_REG_IFACE_ID               0x30
#define TIS_REG_DID_VID                0xf00
#define TIS_REG_RID                    0xf04

#define TIS_STS_VALID                  (1 << 7) /* 0x80 */
#define TIS_STS_COMMAND_READY          (1 << 6) /* 0x40 */
#define TIS_STS_TPM_GO                 (1 << 5) /* 0x20 */
#define TIS_STS_DATA_AVAILABLE         (1 << 4) /* 0x10 */
#define TIS_STS_EXPECT                 (1 << 3) /* 0x08 */
#define TIS_STS_RESPONSE_RETRY         (1 << 1) /* 0x02 */

#define TIS_ACCESS_TPM_REG_VALID_STS   (1 << 7) /* 0x80 */
#define TIS_ACCESS_ACTIVE_LOCALITY     (1 << 5) /* 0x20 */
#define TIS_ACCESS_BEEN_SEIZED         (1 << 4) /* 0x10 */
#define TIS_ACCESS_SEIZE               (1 << 3) /* 0x08 */
#define TIS_ACCESS_PENDING_REQUEST     (1 << 2) /* 0x04 */
#define TIS_ACCESS_REQUEST_USE         (1 << 1) /* 0x02 */
#define TIS_ACCESS_TPM_ESTABLISHMENT   (1 << 0) /* 0x01 */

/*
 * Default TIS timeouts used before getting them from the TPM itself
 */
#define TIS_DEFAULT_TIMEOUT_A           750000 /* us */
#define TIS_DEFAULT_TIMEOUT_B          2000000 /* us */
#define TIS_DEFAULT_TIMEOUT_C           750000 /* us */
#define TIS_DEFAULT_TIMEOUT_D           750000 /* us */

/*
 * Default TIS 2 timeouts given in TPM Profile (TPT) Spec
 */
#define TIS2_DEFAULT_TIMEOUT_A          750000 /* us */
#define TIS2_DEFAULT_TIMEOUT_B         2000000 /* us */
#define TIS2_DEFAULT_TIMEOUT_C          200000 /* us */
#define TIS2_DEFAULT_TIMEOUT_D           30000 /* us */

enum tisTimeoutType {
    TIS_TIMEOUT_TYPE_A = 0,
    TIS_TIMEOUT_TYPE_B,
    TIS_TIMEOUT_TYPE_C,
    TIS_TIMEOUT_TYPE_D,
};

/*
 * Default command durations used before getting them from the
 * TPM itself
 */
#define TPM_DEFAULT_DURATION_SHORT      2000000 /* us */
#define TPM_DEFAULT_DURATION_MEDIUM    20000000 /* us */
#define TPM_DEFAULT_DURATION_LONG      60000000 /* us */

/*
 * TPM 2 command durations; we set them to the timeout values
 * given in TPM Profile (PTP) Specification; exceeding those
 * timeout values indicates a faulty TPM.
 */
#define TPM2_DEFAULT_DURATION_SHORT       750000 /* us */
#define TPM2_DEFAULT_DURATION_MEDIUM     2000000 /* us */
#define TPM2_DEFAULT_DURATION_LONG       2000000 /* us */

#endif /* TPM_DRIVERS_H */
