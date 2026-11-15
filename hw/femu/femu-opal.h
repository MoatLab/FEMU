/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer: the security protocol engine behind NVMe Security
 * Send and Security Receive. It takes byte buffers in and gives byte
 * buffers out, and has no QEMU device types, so a unit test builds it alone.
 */

#ifndef FEMU_OPAL_H
#define FEMU_OPAL_H

#include <stdbool.h>
#include <stdint.h>

/* the one static ComID (Opal 3.3.3, Table 14) */
#define FEMU_OPAL_COMID         0x1000
#define FEMU_OPAL_COMID_L0      0x0001
#define FEMU_OPAL_COMID_TPER_RESET 0x0004
#define FEMU_OPAL_COMID_BLOCK_SID 0x0005
/* VERIFY_COMID_VALID state of the static ComID with no session */
#define FEMU_OPAL_COMID_ISSUED  2
/* MaxComPacketSize and MaxResponseComPacketSize (Opal Table 17) */
#define FEMU_OPAL_BUF           2048

/* security protocols (SECP) the TPer answers */
#define FEMU_OPAL_SECP_INFO     0x00
#define FEMU_OPAL_SECP_TCG      0x01
#define FEMU_OPAL_SECP_COMID    0x02

/* Session Manager methods */
#define FEMU_OPAL_UID_SMUID     0x00000000000000FFull
#define FEMU_OPAL_UID_PROPERTIES 0x000000000000FF01ull

/* method status codes (Core Table 166) */
#define FEMU_OPAL_ST_SUCCESS            0x00
#define FEMU_OPAL_ST_NOT_AUTHORIZED     0x01
#define FEMU_OPAL_ST_SP_BUSY            0x03
#define FEMU_OPAL_ST_NO_SESSIONS        0x07
#define FEMU_OPAL_ST_INVALID_PARAMETER  0x0C
#define FEMU_OPAL_ST_LOCKED_OUT         0x12
#define FEMU_OPAL_ST_FAIL               0x3F

/* Locking SP life cycle states (Core Table 241) */
#define FEMU_OPAL_LIFE_INACTIVE         0x08
#define FEMU_OPAL_LIFE_MANUFACTURED     0x09

#define FEMU_OPAL_PIN_MAX               32

/*
 * Authorities, one bit each in a session's authenticated set. Admin SP:
 * Anybody, SID, PSID, Admin1. Locking SP: Anybody, Admin1 to 4, User1 to 8.
 */
enum {
    FEMU_OPAL_AU_ANYBODY = 0,
    FEMU_OPAL_AU_SID,
    FEMU_OPAL_AU_PSID,
    FEMU_OPAL_AU_ASP_ADMIN1,
    FEMU_OPAL_AU_LSP_ADMIN1,
    FEMU_OPAL_AU_LSP_USER1 = FEMU_OPAL_AU_LSP_ADMIN1 + 4,
    FEMU_OPAL_AU_COUNT = FEMU_OPAL_AU_LSP_USER1 + 8,
};

typedef struct FemuOpalPin {
    uint8_t len;
    uint8_t v[FEMU_OPAL_PIN_MAX];
} FemuOpalPin;

/* one authority with its C_PIN row */
typedef struct FemuOpalAuth {
    bool enabled;
    FemuOpalPin pin;
    uint32_t try_limit;
} FemuOpalAuth;

/*
 * The personalization a transaction can roll back. Tries stays outside it:
 * a TPer update to Tries survives an abort (Core 5.3.4.1.1.2).
 */
typedef struct FemuOpalSp {
    FemuOpalAuth au[FEMU_OPAL_AU_COUNT];
    uint8_t lsp_life;
    bool pre;                   /* TPerInfo ProgrammaticResetEnable */
} FemuOpalSp;

/* the one session (MaxSessions 1) */
typedef struct FemuOpalSession {
    bool open;
    bool locking;               /* the Locking SP, else the Admin SP */
    bool write;
    uint32_t hsn;
    uint32_t tsn;
    uint32_t auth;              /* authenticated authorities, by bit */
    bool txn;                   /* a transaction is open */
    uint32_t txn_auth;
    FemuOpalSp txn_sp;
} FemuOpalSession;

/*
 * The TPer errors of SIIS 6.5 Table 25 that S1 can raise. The caller maps
 * each one to an NVMe status with DNR set.
 */
typedef enum FemuOpalIf {
    FEMU_OPAL_IF_GOOD = 0,
    FEMU_OPAL_IF_INVALID,       /* Invalid Field in Command */
    FEMU_OPAL_IF_SEQUENCE,      /* Command Sequence Error */
} FemuOpalIf;

/* a decoded token (Core 3.2.2.3) */
typedef enum FemuOpalTokType {
    FEMU_OPAL_TOK_UINT,
    FEMU_OPAL_TOK_BYTES,
    FEMU_OPAL_TOK_CTRL,         /* F0 to FC: the value is the token byte */
} FemuOpalTokType;

typedef struct FemuOpalTok {
    FemuOpalTokType type;
    uint64_t val;               /* UINT value, or the CTRL byte */
    const uint8_t *p;           /* BYTES data */
    uint32_t len;               /* BYTES length */
} FemuOpalTok;

/* one token per byte at most, so a ComPacket never runs out */
#define FEMU_OPAL_MAX_TOKS      FEMU_OPAL_BUF

typedef struct FemuOpalEnc {
    uint8_t *buf;
    uint32_t cap;
    uint32_t len;
    bool overflow;
} FemuOpalEnc;

typedef struct FemuOpalCfg {
    uint32_t lba_size;
    uint16_t admins;            /* Locking SP admin authorities */
    uint16_t users;             /* Locking SP user authorities */
    bool crypto_erase;          /* GenKey, Revert and RevertSP erase */
    FemuOpalPin msid;           /* C_PIN_MSID */
    FemuOpalPin psid;           /* C_PIN_PSID */
} FemuOpalCfg;

/* communication properties a host may set (Core 5.2.2.4) */
typedef struct FemuOpalHostProps {
    uint32_t max_compacket;
    uint32_t max_packet;
    uint32_t max_ind_token;
    uint32_t max_packets;
    uint32_t max_subpackets;
    uint32_t max_methods;
} FemuOpalHostProps;

typedef struct FemuOpal {
    FemuOpalCfg cfg;
    FemuOpalHostProps host;
    /* ComID state machine (Core 3.3.10): a response waits in resp */
    bool ready;
    uint32_t resp_len;
    uint8_t resp[FEMU_OPAL_BUF];
    /* the last HANDLE_COMID_REQUEST, answered by GET_COMID_RESPONSE */
    uint32_t mgmt_req;
    uint32_t mgmt_ext;          /* the Extended ComID VERIFY asked about */
    /* what the last Receive returned, taken by femu_opal_consume() */
    uint8_t consume;
    FemuOpalSp sp;
    uint32_t tries[FEMU_OPAL_AU_COUNT];
    FemuOpalSession s;
    uint32_t next_tsn;
    /* Block SID Authentication (Block SID 4.2) */
    bool sid_blocked;
    bool sid_block_hw;          /* a Hardware Reset clears it too */
    FemuOpalTok toks[FEMU_OPAL_MAX_TOKS];
} FemuOpal;

void femu_opal_init(FemuOpal *o, const FemuOpalCfg *cfg);

/*
 * The checks of a Security Send that need no data: the caller runs them
 * before it moves any, so an interface error transfers nothing.
 */
FemuOpalIf femu_opal_send_check(FemuOpal *o, uint8_t secp, uint16_t spsp,
                                uint32_t len);

/*
 * Security Send of @len bytes from @buf. A method runs to its end inside
 * this call; its response waits for the next Security Receive.
 */
FemuOpalIf femu_opal_send(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          const uint8_t *buf, uint32_t len);

/*
 * Security Receive: fill @buf (@al bytes, zeroed by the caller). The
 * response stays until femu_opal_consume() runs after the data reached the
 * host, so a failed transfer keeps it.
 */
FemuOpalIf femu_opal_recv(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          uint8_t *buf, uint32_t al);
void femu_opal_consume(FemuOpal *o);

/* a TCG Power Cycle: the state a device has when it comes up */
void femu_opal_power_cycle(FemuOpal *o);

/* Level 0 discovery data; returns the full length, copies at most @cap */
uint32_t femu_opal_level0(const FemuOpal *o, uint8_t *buf, uint32_t cap);

/* token codec, exposed for the unit test */
int femu_opal_decode(const uint8_t *p, uint32_t len, FemuOpalTok *toks,
                     int max);
void femu_opal_enc_uint(FemuOpalEnc *e, uint64_t v);
void femu_opal_enc_bytes(FemuOpalEnc *e, const void *p, uint32_t len);
void femu_opal_enc_uid(FemuOpalEnc *e, uint64_t uid);
void femu_opal_enc_ctrl(FemuOpalEnc *e, uint8_t tok);

#endif
