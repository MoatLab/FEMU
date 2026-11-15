/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer: transport, Level 0 discovery and the Session
 * Manager (TCG Storage Architecture Core 2.01, Opal SSC 2.30, SIIS 1.20).
 *
 * Every method finishes inside Security Send. Its response waits in one
 * buffer for the ComID until a Security Receive large enough takes it.
 */

#include "qemu/osdep.h"
#include "femu-opal.h"

enum {
    TOK_SL = 0xF0, TOK_EL = 0xF1, TOK_SN = 0xF2, TOK_EN = 0xF3,
    TOK_CALL = 0xF8, TOK_EOD = 0xF9, TOK_EOS = 0xFA,
    TOK_ST = 0xFB, TOK_ET = 0xFC, TOK_EMPTY = 0xFF,
};

/* frame header sizes (Core 3.2.3, Tables 17, 18 and 20) */
#define COMPKT_HDR      20
#define PKT_HDR         24
#define SUBPKT_HDR      12
#define FRAME_HDR       (COMPKT_HDR + PKT_HDR + SUBPKT_HDR)

/* HANDLE_COMID_REQUEST codes (Core 3.3.4.7) */
#define MGMT_VERIFY_COMID 1
#define MGMT_STACK_RESET  2

/* what femu_opal_consume() takes away after a Receive */
enum { CONSUME_NONE, CONSUME_RESP, CONSUME_MGMT };

/* host property minimums (Opal Table 17) */
static const FemuOpalHostProps host_min = {
    .max_compacket = 2048,
    .max_packet = 2028,
    .max_ind_token = 1992,
    .max_packets = 1,
    .max_subpackets = 1,
    .max_methods = 1,
};

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static uint16_t get16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint64_t get_be(const uint8_t *p, uint32_t n)
{
    uint64_t v = 0;

    while (n--) {
        v = (v << 8) | *p++;
    }
    return v;
}

static void femu_opal_stack_reset(FemuOpal *o)
{
    o->ready = false;
    o->resp_len = 0;
    o->host = host_min;
}

void femu_opal_init(FemuOpal *o, const FemuOpalCfg *cfg)
{
    memset(o, 0, sizeof(*o));
    o->cfg = *cfg;
    femu_opal_stack_reset(o);
}

/*
 * Token decoder (Core 3.2.2.3; Opal 3.3.4.1.1 needs every atom form with
 * B = 0 or 1 and S = 0). Empty atoms are dropped. Returns the token count,
 * or -1 for a streaming protocol violation.
 */
int femu_opal_decode(const uint8_t *p, uint32_t len, FemuOpalTok *toks,
                     int max)
{
    uint32_t i = 0;
    int n = 0;

    while (i < len) {
        uint8_t b = p[i];
        uint32_t hdr;
        uint32_t dlen;
        bool bytes;
        bool sign;

        if (b == TOK_EMPTY) {
            i++;
            continue;
        }
        if (n == max) {
            return -1;
        }
        if (b < 0x80) {
            /* tiny atom: 0 S dddddd */
            if (b & 0x40) {
                return -1;
            }
            toks[n].type = FEMU_OPAL_TOK_UINT;
            toks[n++].val = b & 0x3f;
            i++;
            continue;
        }
        if (b < 0xC0) {
            bytes = b & 0x20;
            sign = b & 0x10;
            dlen = b & 0x0f;
            hdr = 1;
        } else if (b < 0xE0) {
            if (i + 2 > len) {
                return -1;
            }
            bytes = b & 0x10;
            sign = b & 0x08;
            dlen = ((b & 0x07) << 8) | p[i + 1];
            hdr = 2;
        } else if (b < 0xE4) {
            if (i + 4 > len) {
                return -1;
            }
            bytes = b & 0x02;
            sign = b & 0x01;
            dlen = (p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3];
            hdr = 4;
        } else if ((b >= TOK_SL && b <= TOK_EN) ||
                   (b >= TOK_CALL && b <= TOK_ET)) {
            toks[n].type = FEMU_OPAL_TOK_CTRL;
            toks[n++].val = b;
            i++;
            continue;
        } else {
            return -1;
        }
        if (sign || dlen > len - i - hdr) {
            return -1;
        }
        /* only the short byte atom A0 may be empty (Core Tables 8 to 13) */
        if (!dlen && (!bytes || hdr != 1)) {
            return -1;
        }
        if (bytes) {
            toks[n].type = FEMU_OPAL_TOK_BYTES;
            toks[n].p = p + i + hdr;
            toks[n].len = dlen;
        } else {
            uint32_t k;

            /* leading zero bytes are legal; a value above 64 bits is not */
            for (k = 0; k + 8 < dlen; k++) {
                if (p[i + hdr + k]) {
                    return -1;
                }
            }
            toks[n].type = FEMU_OPAL_TOK_UINT;
            toks[n].val = get_be(p + i + hdr + k, dlen - k);
        }
        n++;
        i += hdr + dlen;
    }
    return n;
}

static void enc_raw(FemuOpalEnc *e, const void *p, uint32_t len)
{
    if (e->overflow || len > e->cap - e->len) {
        e->overflow = true;
        return;
    }
    memcpy(e->buf + e->len, p, len);
    e->len += len;
}

void femu_opal_enc_ctrl(FemuOpalEnc *e, uint8_t tok)
{
    enc_raw(e, &tok, 1);
}

/* the shortest atom for @v (Core 3.2.2.3.1) */
void femu_opal_enc_uint(FemuOpalEnc *e, uint64_t v)
{
    uint8_t b[9];
    int n = 0;
    int i;

    if (v < 64) {
        femu_opal_enc_ctrl(e, v);
        return;
    }
    for (i = 7; i >= 0; i--) {
        if (n || (v >> (i * 8)) & 0xff) {
            b[1 + n++] = v >> (i * 8);
        }
    }
    b[0] = 0x80 | n;
    enc_raw(e, b, 1 + n);
}

void femu_opal_enc_bytes(FemuOpalEnc *e, const void *p, uint32_t len)
{
    uint8_t h[4];

    /* a long atom holds a 24-bit length */
    if (len > 0xffffff) {
        e->overflow = true;
        return;
    }
    if (len < 16) {
        h[0] = 0xA0 | len;
        enc_raw(e, h, 1);
    } else if (len < 2048) {
        h[0] = 0xD0 | (len >> 8);
        h[1] = len;
        enc_raw(e, h, 2);
    } else {
        h[0] = 0xE2;
        h[1] = len >> 16;
        h[2] = len >> 8;
        h[3] = len;
        enc_raw(e, h, 4);
    }
    enc_raw(e, p, len);
}

void femu_opal_enc_uid(FemuOpalEnc *e, uint64_t uid)
{
    uint8_t b[8];

    put32(b, uid >> 32);
    put32(b + 4, uid);
    femu_opal_enc_bytes(e, b, 8);
}

static void enc_named_uint(FemuOpalEnc *e, const char *name, uint64_t v)
{
    femu_opal_enc_ctrl(e, TOK_SN);
    femu_opal_enc_bytes(e, name, strlen(name));
    femu_opal_enc_uint(e, v);
    femu_opal_enc_ctrl(e, TOK_EN);
}

/*
 * Level 0 discovery (Opal 3.1.1): header, then descriptors in increasing
 * feature code order. Locking Supported stays 0 until the Locking SP
 * exists.
 */
uint32_t femu_opal_level0(const FemuOpal *o, uint8_t *buf, uint32_t cap)
{
    uint8_t d[256];
    uint8_t *p = d + 48;

    memset(d, 0, sizeof(d));
    put32(d + 4, 1);                    /* data structure revision */

    /* TPer 0001h: Sync, Streaming */
    put16(p, 0x0001);
    p[2] = 0x10;
    p[3] = 0x0c;
    p[4] = 0x11;
    p += 16;

    /* Locking 0002h: Media Encryption */
    put16(p, 0x0002);
    p[2] = 0x30;
    p[3] = 0x0c;
    p[4] = 0x08;
    p += 16;

    /* Geometry Reporting 0003h: no alignment requirement */
    put16(p, 0x0003);
    p[2] = 0x10;
    p[3] = 0x1c;
    put32(p + 12, o->cfg.lba_size);
    p[23] = 1;                          /* AlignmentGranularity */
    p += 32;

    /* SIIS 0005h (SIIS 3.6): revision 1.20 */
    put16(p, 0x0005);
    p[2] = 0x10;
    p[3] = 0x0c;
    p[4] = 0x20;
    p += 16;

    /* Opal SSC V2 0203h: version 2, SSC minor version 3 (2.30) */
    put16(p, 0x0203);
    p[2] = 0x23;
    p[3] = 0x10;
    put16(p + 4, FEMU_OPAL_COMID);
    put16(p + 6, 1);
    put16(p + 9, o->cfg.admins);
    put16(p + 11, o->cfg.users);
    p += 20;

    /* Supported Data Removal Mechanism 0404h: set once erase exists */
    put16(p, 0x0404);
    p[2] = 0x20;
    p[3] = 0x20;
    p[6] = o->cfg.crypto_erase ? 0x04 : 0;
    p += 36;

    put32(d, (p - d) - 4);
    memcpy(buf, d, MIN(cap, (uint32_t)(p - d)));
    return p - d;
}

/* frame @slen payload bytes (already at o->resp + FRAME_HDR) */
static void femu_opal_frame(FemuOpal *o, uint32_t tsn, uint32_t hsn,
                            uint32_t slen)
{
    uint32_t pad = -slen & 3;
    uint32_t plen = SUBPKT_HDR + slen + pad;
    uint8_t *r = o->resp;

    memset(r, 0, FRAME_HDR);
    memset(r + FRAME_HDR + slen, 0, pad);
    put16(r + 4, FEMU_OPAL_COMID);
    put32(r + 16, PKT_HDR + plen);
    put32(r + COMPKT_HDR, tsn);
    put32(r + COMPKT_HDR + 4, hsn);
    put32(r + COMPKT_HDR + 20, plen);
    put32(r + COMPKT_HDR + PKT_HDR + 8, slen);
    o->resp_len = COMPKT_HDR + PKT_HDR + plen;
    o->ready = true;
}

static bool tok_is(const FemuOpalTok *t, uint8_t ctrl)
{
    return t->type == FEMU_OPAL_TOK_CTRL && t->val == ctrl;
}

static bool tok_uid(const FemuOpalTok *t, uint64_t *uid)
{
    if (t->type != FEMU_OPAL_TOK_BYTES || t->len != 8) {
        return false;
    }
    *uid = get_be(t->p, 8);
    return true;
}

static bool tok_name(const FemuOpalTok *t, const char *name)
{
    return t->type == FEMU_OPAL_TOK_BYTES && t->len == strlen(name) &&
           !memcmp(t->p, name, t->len);
}

/* the HostProperties name @t names, or NULL */
static uint32_t *host_field(FemuOpalHostProps *h, const FemuOpalTok *t,
                            uint32_t *min)
{
    static const struct {
        const char *name;
        size_t off;
    } names[] = {
        { "MaxComPacketSize", offsetof(FemuOpalHostProps, max_compacket) },
        { "MaxPacketSize", offsetof(FemuOpalHostProps, max_packet) },
        { "MaxIndTokenSize", offsetof(FemuOpalHostProps, max_ind_token) },
        { "MaxPackets", offsetof(FemuOpalHostProps, max_packets) },
        { "MaxSubpackets", offsetof(FemuOpalHostProps, max_subpackets) },
        { "MaxMethods", offsetof(FemuOpalHostProps, max_methods) },
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(names); i++) {
        if (tok_name(t, names[i].name)) {
            *min = *(const uint32_t *)((const uint8_t *)&host_min +
                                       names[i].off);
            return (uint32_t *)((uint8_t *)h + names[i].off);
        }
    }
    return NULL;
}

/*
 * The optional HostProperties parameter: SN 0 SL {SN name uint EN}* EL EN.
 * @t holds the @n tokens between the parameter list's SL and EL. Unknown
 * names are ignored; a value below the minimum is raised (Core 5.2.2.4).
 * Returns false for a malformed list.
 */
static bool host_props(const FemuOpalTok *t, int n, FemuOpalHostProps *h,
                       bool *given)
{
    int i;

    *given = n > 0;
    if (!n) {
        return true;
    }
    if (n < 5 || !tok_is(&t[0], TOK_SN) || t[1].type != FEMU_OPAL_TOK_UINT ||
        t[1].val != 0 || !tok_is(&t[2], TOK_SL)) {
        return false;
    }
    for (i = 3; i + 3 < n && tok_is(&t[i], TOK_SN); i += 4) {
        uint32_t min;
        uint32_t *f;

        if (t[i + 1].type != FEMU_OPAL_TOK_BYTES ||
            t[i + 2].type != FEMU_OPAL_TOK_UINT ||
            !tok_is(&t[i + 3], TOK_EN)) {
            return false;
        }
        f = host_field(h, &t[i + 1], &min);
        if (f) {
            *f = MAX(min, MIN(t[i + 2].val, UINT32_MAX));
        }
    }
    return i + 2 == n && tok_is(&t[i], TOK_EL) && tok_is(&t[i + 1], TOK_EN);
}

/* start a Session Manager reply: CALL SMUID method SL */
static void sm_reply_start(FemuOpalEnc *e, FemuOpal *o, uint64_t method)
{
    *e = (FemuOpalEnc){
        .buf = o->resp + FRAME_HDR,
        .cap = FEMU_OPAL_BUF - FRAME_HDR,
    };
    femu_opal_enc_ctrl(e, TOK_CALL);
    femu_opal_enc_uid(e, FEMU_OPAL_UID_SMUID);
    femu_opal_enc_uid(e, method);
    femu_opal_enc_ctrl(e, TOK_SL);
}

/* end it: EL EOD SL status 0 0 EL, then frame it */
static void sm_reply_end(FemuOpalEnc *e, FemuOpal *o, uint8_t status)
{
    femu_opal_enc_ctrl(e, TOK_EL);
    femu_opal_enc_ctrl(e, TOK_EOD);
    femu_opal_enc_ctrl(e, TOK_SL);
    femu_opal_enc_uint(e, status);
    femu_opal_enc_uint(e, 0);
    femu_opal_enc_uint(e, 0);
    femu_opal_enc_ctrl(e, TOK_EL);
    if (!e->overflow) {
        femu_opal_frame(o, 0, 0, e->len);
    }
}

/*
 * Properties (Core 5.2.2.4): take the HostProperties, then report the TPer
 * properties (Opal Table 17) and, when the host sent some, the host values
 * in use. A nonzero host status aborts the method (Core 3.2.4.2).
 */
static void femu_opal_properties(FemuOpal *o, const FemuOpalTok *t, int n,
                                 uint8_t host_status)
{
    FemuOpalHostProps h = o->host;
    FemuOpalEnc e;
    bool given;

    sm_reply_start(&e, o, FEMU_OPAL_UID_PROPERTIES);
    if (host_status) {
        sm_reply_end(&e, o, host_status);
        return;
    }
    if (!host_props(t, n, &h, &given)) {
        sm_reply_end(&e, o, FEMU_OPAL_ST_INVALID_PARAMETER);
        return;
    }
    o->host = h;
    femu_opal_enc_ctrl(&e, TOK_SL);
    enc_named_uint(&e, "MaxComPacketSize", FEMU_OPAL_BUF);
    enc_named_uint(&e, "MaxResponseComPacketSize", FEMU_OPAL_BUF);
    enc_named_uint(&e, "MaxPacketSize", FEMU_OPAL_BUF - COMPKT_HDR);
    enc_named_uint(&e, "MaxIndTokenSize", FEMU_OPAL_BUF - FRAME_HDR);
    enc_named_uint(&e, "MaxPackets", 1);
    enc_named_uint(&e, "MaxSubpackets", 1);
    enc_named_uint(&e, "MaxMethods", 1);
    enc_named_uint(&e, "MaxSessions", 1);
    enc_named_uint(&e, "MaxAuthentications", 2);
    enc_named_uint(&e, "MaxTransactionLimit", 1);
    /* 0: no session timeout */
    enc_named_uint(&e, "DefSessionTimeout", 0);
    femu_opal_enc_ctrl(&e, TOK_EL);
    if (given) {
        femu_opal_enc_ctrl(&e, TOK_SN);
        femu_opal_enc_uint(&e, 0);
        femu_opal_enc_ctrl(&e, TOK_SL);
        enc_named_uint(&e, "MaxComPacketSize", o->host.max_compacket);
        enc_named_uint(&e, "MaxPacketSize", o->host.max_packet);
        enc_named_uint(&e, "MaxIndTokenSize", o->host.max_ind_token);
        enc_named_uint(&e, "MaxPackets", o->host.max_packets);
        enc_named_uint(&e, "MaxSubpackets", o->host.max_subpackets);
        enc_named_uint(&e, "MaxMethods", o->host.max_methods);
        femu_opal_enc_ctrl(&e, TOK_EL);
        femu_opal_enc_ctrl(&e, TOK_EN);
    }
    sm_reply_end(&e, o, FEMU_OPAL_ST_SUCCESS);
}

/*
 * A Session Manager call: CALL SMUID method SL params EL EOD SL s 0 0 EL.
 * The control session ignores unknown methods with no response (Core
 * 3.3.7.1.3). A known method with a bad status list gets
 * INVALID_PARAMETER.
 */
static void femu_opal_session_manager(FemuOpal *o, const FemuOpalTok *t,
                                      int n)
{
    uint64_t inv;
    uint64_t method;
    uint8_t status = FEMU_OPAL_ST_INVALID_PARAMETER;
    int end;
    int depth = 0;

    if (n < 5 || !tok_is(&t[0], TOK_CALL) || !tok_uid(&t[1], &inv) ||
        !tok_uid(&t[2], &method) || !tok_is(&t[3], TOK_SL) ||
        inv != FEMU_OPAL_UID_SMUID || method != FEMU_OPAL_UID_PROPERTIES) {
        return;
    }
    /* the EL that closes the parameter list */
    for (end = 3; end < n; end++) {
        if (tok_is(&t[end], TOK_SL)) {
            depth++;
        } else if (tok_is(&t[end], TOK_EL) && --depth == 0) {
            break;
        }
    }
    if (end + 6 < n && tok_is(&t[end + 1], TOK_EOD) &&
        tok_is(&t[end + 2], TOK_SL) &&
        t[end + 3].type == FEMU_OPAL_TOK_UINT &&
        t[end + 4].type == FEMU_OPAL_TOK_UINT &&
        t[end + 5].type == FEMU_OPAL_TOK_UINT &&
        tok_is(&t[end + 6], TOK_EL)) {
        status = t[end + 3].val ? MIN(t[end + 3].val, 0xff) : 0;
        femu_opal_properties(o, t + 4, end - 4, status);
        return;
    }
    femu_opal_properties(o, t + 4, 0, status);
}

/*
 * One ComPacket with one Packet and one Subpacket (Opal 3.3.4.1.2). A bad
 * header, nonzero pad, a second Subpacket or a streaming error drops the
 * payload, and the ComID stays idle. Packets after the first are ignored.
 */
static void femu_opal_compacket(FemuOpal *o, const uint8_t *buf, uint32_t len)
{
    FemuOpalTok *toks = o->toks;
    const uint8_t *pkt = buf + COMPKT_HDR;
    const uint8_t *sub = pkt + PKT_HDR;
    uint32_t cplen;
    uint32_t plen;
    uint32_t slen;
    uint32_t pad;
    uint32_t k;
    int n;

    if (len < FRAME_HDR || get16(buf + 4) != FEMU_OPAL_COMID ||
        get16(buf + 6)) {
        return;
    }
    cplen = get32(buf + 16);
    if (cplen < PKT_HDR + SUBPKT_HDR || cplen > len - COMPKT_HDR) {
        return;
    }
    plen = get32(pkt + 20);
    if (plen < SUBPKT_HDR || plen > cplen - PKT_HDR) {
        return;
    }
    slen = get32(sub + 8);
    pad = -slen & 3;
    if (get16(sub + 6) || slen > plen - SUBPKT_HDR ||
        plen - SUBPKT_HDR - slen != pad) {
        return;
    }
    for (k = 0; k < pad; k++) {
        if (sub[SUBPKT_HDR + slen + k]) {
            return;
        }
    }
    n = femu_opal_decode(sub + SUBPKT_HDR, slen, toks, FEMU_OPAL_MAX_TOKS);
    if (n <= 0) {
        return;
    }
    if (!get32(pkt) && !get32(pkt + 4)) {
        femu_opal_session_manager(o, toks, n);
    }
}

FemuOpalIf femu_opal_send_check(FemuOpal *o, uint8_t secp, uint16_t spsp,
                                uint32_t len)
{
    switch (secp) {
    case FEMU_OPAL_SECP_TCG:
        if (spsp == FEMU_OPAL_COMID_L0) {
            return FEMU_OPAL_IF_GOOD;
        }
        if (spsp != FEMU_OPAL_COMID || len > FEMU_OPAL_BUF) {
            return FEMU_OPAL_IF_INVALID;
        }
        return o->ready ? FEMU_OPAL_IF_SEQUENCE : FEMU_OPAL_IF_GOOD;
    case FEMU_OPAL_SECP_COMID:
        /* TPER_RESET needs ProgrammaticResetEnable, which is False */
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        if (len < 8) {
            /* a bad request leaves "No Response Available" */
            o->mgmt_req = 0;
            return FEMU_OPAL_IF_INVALID;
        }
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

FemuOpalIf femu_opal_send(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          const uint8_t *buf, uint32_t len)
{
    FemuOpalIf r = femu_opal_send_check(o, secp, spsp, len);
    uint32_t code;
    uint32_t ext;

    if (r) {
        return r;
    }
    if (secp == FEMU_OPAL_SECP_TCG) {
        /* a Level 0 send is discarded (Core 3.3.6.1) */
        if (spsp == FEMU_OPAL_COMID) {
            femu_opal_compacket(o, buf, len);
        }
        return FEMU_OPAL_IF_GOOD;
    }
    ext = get32(buf);
    code = get32(buf + 4);
    o->mgmt_req = 0;
    switch (code) {
    case MGMT_VERIFY_COMID:
        /* any ComID: the response says if it is valid */
        o->mgmt_req = code;
        o->mgmt_ext = ext;
        return FEMU_OPAL_IF_GOOD;
    case MGMT_STACK_RESET:
        if (ext != (uint32_t)FEMU_OPAL_COMID << 16) {
            return FEMU_OPAL_IF_INVALID;
        }
        femu_opal_stack_reset(o);
        o->mgmt_req = code;
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

/*
 * GET_COMID_RESPONSE (Core 3.3.4.7.2 to 3.3.4.7.5). A VERIFY_COMID_VALID
 * answer stays for every later Receive; a STACK_RESET answer goes once
 * the host has read all of it. Before any request: all zero.
 */
static void femu_opal_mgmt_resp(FemuOpal *o, uint8_t *buf, uint32_t al)
{
    uint8_t r[46] = { 0 };
    uint32_t n = 12;

    if (o->mgmt_req == MGMT_STACK_RESET) {
        put32(r, (uint32_t)FEMU_OPAL_COMID << 16);
        put32(r + 4, MGMT_STACK_RESET);
        put16(r + 10, 4);
        n = 16;                         /* result 0: success */
        if (al >= n) {
            o->consume = CONSUME_MGMT;
        }
    } else if (o->mgmt_req == MGMT_VERIFY_COMID) {
        put32(r, o->mgmt_ext);
        put32(r + 4, MGMT_VERIFY_COMID);
        put16(r + 10, 0x22);
        /* Issued: no session holds it yet; Invalid for any other; no clock */
        put32(r + 12, o->mgmt_ext == (uint32_t)FEMU_OPAL_COMID << 16 ?
                      FEMU_OPAL_COMID_ISSUED : 0);
        n = 46;
    }
    memcpy(buf, r, MIN(al, n));
}

FemuOpalIf femu_opal_recv(FemuOpal *o, uint8_t secp, uint16_t spsp,
                          uint8_t *buf, uint32_t al)
{
    uint8_t h[COMPKT_HDR] = { 0 };

    o->consume = CONSUME_NONE;
    switch (secp) {
    case FEMU_OPAL_SECP_INFO:
        if (spsp == 0) {
            /* supported protocol list: 00h 01h 02h */
            uint8_t l[11] = { [7] = 3, [8] = 0x00, [9] = 0x01, [10] = 0x02 };

            memcpy(buf, l, MIN(al, sizeof(l)));
            return FEMU_OPAL_IF_GOOD;
        }
        /* no certificate: a zero length (SPSP 0001h) */
        return spsp == 1 ? FEMU_OPAL_IF_GOOD : FEMU_OPAL_IF_INVALID;
    case FEMU_OPAL_SECP_TCG:
        if (spsp == FEMU_OPAL_COMID_L0) {
            femu_opal_level0(o, buf, al);
            return FEMU_OPAL_IF_GOOD;
        }
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        if (o->ready && al >= o->resp_len) {
            memcpy(buf, o->resp, o->resp_len);
            o->consume = CONSUME_RESP;
            return FEMU_OPAL_IF_GOOD;
        }
        /* idle, or too small: Length 0 and what a full Receive needs */
        put16(h + 4, FEMU_OPAL_COMID);
        if (o->ready) {
            put32(h + 8, o->resp_len);
            put32(h + 12, o->resp_len);
        }
        memcpy(buf, h, MIN(al, sizeof(h)));
        return FEMU_OPAL_IF_GOOD;
    case FEMU_OPAL_SECP_COMID:
        if (spsp != FEMU_OPAL_COMID) {
            return FEMU_OPAL_IF_INVALID;
        }
        femu_opal_mgmt_resp(o, buf, al);
        return FEMU_OPAL_IF_GOOD;
    default:
        return FEMU_OPAL_IF_INVALID;
    }
}

void femu_opal_consume(FemuOpal *o)
{
    if (o->consume == CONSUME_MGMT) {
        o->mgmt_req = 0;
    } else if (o->consume == CONSUME_RESP) {
        o->ready = false;
        o->resp_len = 0;
    }
    o->consume = CONSUME_NONE;
}
