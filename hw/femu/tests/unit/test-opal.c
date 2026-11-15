/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer tests: token codec, Level 0, the ComID state machine,
 * STACK_RESET and the Session Manager Properties method. The byte
 * fixtures come from the Core 2.01 and Opal 2.30 tables, not from the
 * encoder under test.
 */

#include "qemu/osdep.h"
#include "hw/femu/femu-opal.h"

static const FemuOpalCfg cfg = { .lba_size = 4096, .admins = 4, .users = 8 };

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint16_t be16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}

static void set32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

/* one ComPacket, Packet and Subpacket around @payload (Core 3.2.3) */
static uint32_t frame(uint8_t *buf, const uint8_t *payload, uint32_t n,
                      uint16_t comid)
{
    uint32_t pad = -n & 3;

    memset(buf, 0, FEMU_OPAL_BUF);
    buf[4] = comid >> 8;
    buf[5] = comid;
    set32(buf + 16, 24 + 12 + n + pad);
    set32(buf + 20 + 20, 12 + n + pad);
    set32(buf + 20 + 24 + 8, n);
    memcpy(buf + 56, payload, n);
    return 56 + n + pad;
}

/* CALL SMUID Properties SL EL EOD SL 0 0 0 EL */
static const uint8_t props_call[] = {
    0xF8,
    0xA8, 0, 0, 0, 0, 0, 0, 0, 0xFF,
    0xA8, 0, 0, 0, 0, 0, 0, 0xFF, 0x01,
    0xF0, 0xF1,
    0xF9, 0xF0, 0x00, 0x00, 0x00, 0xF1,
};

static void test_decode_fixtures(void)
{
    FemuOpalTok t[8];
    /* tiny 5, short int 1234h, 8-byte UID, medium bytes of 16, empty atom */
    uint8_t ok[40] = { 0x05, 0x82, 0x12, 0x34,
                       0xA8, 0, 0, 0, 9, 0, 0, 0, 6,
                       0xD0, 0x10 };
    int n;

    ok[31] = 0xFF;
    ok[32] = 0xF0;
    n = femu_opal_decode(ok, 33, t, 8);
    g_assert_cmpint(n, ==, 5);
    g_assert_cmpint(t[0].type, ==, FEMU_OPAL_TOK_UINT);
    g_assert_cmpuint(t[0].val, ==, 5);
    g_assert_cmpuint(t[1].val, ==, 0x1234);
    g_assert_cmpint(t[2].type, ==, FEMU_OPAL_TOK_BYTES);
    g_assert_cmpuint(t[2].len, ==, 8);
    g_assert_cmpuint(t[3].len, ==, 16);
    g_assert_cmpint(t[4].type, ==, FEMU_OPAL_TOK_CTRL);
    g_assert_cmpuint(t[4].val, ==, 0xF0);
}

static void test_decode_errors(void)
{
    FemuOpalTok t[4];
    static const uint8_t sign_tiny[] = { 0x41 };
    static const uint8_t sign_short[] = { 0x91, 0x01 };
    static const uint8_t reserved[] = { 0xE4 };
    static const uint8_t reserved2[] = { 0xFD };
    static const uint8_t short_cut[] = { 0x84, 0x01 };
    static const uint8_t medium_cut[] = { 0xD0 };
    static const uint8_t wide_int[] = { 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    static const uint8_t empty_int[] = { 0x80 };
    static const uint8_t empty_medium[] = { 0xD0, 0x00 };
    static const uint8_t empty_long[] = { 0xE2, 0, 0, 0 };
    static const uint8_t empty_long_int[] = { 0xE0, 0, 0, 0 };

    g_assert_cmpint(femu_opal_decode(sign_tiny, 1, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(sign_short, 2, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(reserved, 1, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(reserved2, 1, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(short_cut, 2, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(medium_cut, 1, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(wide_int, 10, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(empty_int, 1, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(empty_medium, 2, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(empty_long, 4, t, 4), ==, -1);
    g_assert_cmpint(femu_opal_decode(empty_long_int, 4, t, 4), ==, -1);
}

static void test_decode_wide(void)
{
    FemuOpalTok t[4];
    /* nine bytes with a leading zero: legal, the value fits */
    static const uint8_t lead0[] = { 0x89, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    /* a medium integer atom of 3 bytes */
    static const uint8_t medium[] = { 0xC0, 0x03, 0x01, 0x02, 0x03 };
    /* the empty byte string A0 is legal */
    static const uint8_t a0[] = { 0xA0 };

    g_assert_cmpint(femu_opal_decode(lead0, 10, t, 4), ==, 1);
    g_assert_cmphex(t[0].val, ==, 0x0102030405060708ull);
    g_assert_cmpint(femu_opal_decode(medium, 5, t, 4), ==, 1);
    g_assert_cmphex(t[0].val, ==, 0x010203);
    g_assert_cmpint(femu_opal_decode(a0, 1, t, 4), ==, 1);
    g_assert_cmpint(t[0].type, ==, FEMU_OPAL_TOK_BYTES);
    g_assert_cmpuint(t[0].len, ==, 0);
}

static void test_encode(void)
{
    uint8_t b[4096];
    uint8_t big[2048] = { 0 };
    FemuOpalEnc e = { .buf = b, .cap = sizeof(b) };
    FemuOpalTok t[16];
    int n;

    femu_opal_enc_uint(&e, 63);
    femu_opal_enc_uint(&e, 64);
    femu_opal_enc_uint(&e, 0x123456);
    femu_opal_enc_uint(&e, UINT64_MAX);
    femu_opal_enc_bytes(&e, big, 0);
    femu_opal_enc_bytes(&e, big, 15);
    femu_opal_enc_bytes(&e, big, 16);
    femu_opal_enc_bytes(&e, big, 2048);
    g_assert_false(e.overflow);
    /* shortest atoms: 3F, 81 40, 83 12 34 56 */
    g_assert_cmpuint(b[0], ==, 0x3F);
    g_assert_cmpuint(b[1], ==, 0x81);
    g_assert_cmpuint(b[2], ==, 0x40);
    g_assert_cmpuint(b[3], ==, 0x83);
    g_assert_cmpuint(b[7], ==, 0x88);
    g_assert_cmpuint(b[16], ==, 0xA0);
    n = femu_opal_decode(b, e.len, t, 16);
    g_assert_cmpint(n, ==, 8);
    g_assert_cmpuint(t[3].val, ==, UINT64_MAX);
    g_assert_cmpuint(t[6].len, ==, 16);
    g_assert_cmpuint(t[7].len, ==, 2048);

    e = (FemuOpalEnc){ .buf = b, .cap = 4 };
    femu_opal_enc_bytes(&e, big, 8);
    g_assert_true(e.overflow);
}

static void test_level0(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t b[FEMU_OPAL_BUF] = { 0 };
    static const struct {
        uint32_t off;
        uint16_t code;
        uint8_t ver;
        uint8_t len;
    } d[] = {
        { 48, 0x0001, 0x10, 0x0c },
        { 64, 0x0002, 0x30, 0x0c },
        { 80, 0x0003, 0x10, 0x1c },
        { 112, 0x0005, 0x10, 0x0c },
        { 128, 0x0203, 0x23, 0x10 },
        { 148, 0x0402, 0x20, 0x0c },
        { 164, 0x0404, 0x20, 0x20 },
    };
    int i;

    femu_opal_init(o, &cfg);
    g_assert_cmpint(femu_opal_recv(o, 1, 1, b, sizeof(b)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be32(b), ==, 200 - 4);
    g_assert_cmpuint(be32(b + 4), ==, 1);
    for (i = 0; i < ARRAY_SIZE(d); i++) {
        g_assert_cmpuint(be16(b + d[i].off), ==, d[i].code);
        g_assert_cmpuint(b[d[i].off + 2], ==, d[i].ver);
        g_assert_cmpuint(b[d[i].off + 3], ==, d[i].len);
    }
    g_assert_cmpuint(b[52], ==, 0x11);          /* Sync, Streaming */
    g_assert_cmpuint(b[68], ==, 0x09);          /* Supported, encryption */
    g_assert_cmpuint(be32(b + 92), ==, 4096);   /* LogicalBlockSize */
    g_assert_cmpuint(b[116], ==, 0x20);         /* SIIS 1.20 */
    g_assert_cmpuint(be16(b + 132), ==, FEMU_OPAL_COMID);
    g_assert_cmpuint(be16(b + 134), ==, 1);
    g_assert_cmpuint(be16(b + 137), ==, 4);
    g_assert_cmpuint(be16(b + 139), ==, 8);
    g_assert_cmpuint(b[152], ==, 0);            /* SID is MSID */
    g_assert_cmpuint(b[170], ==, 0);            /* no erase yet */
    g_free(o);
}

static void test_protocol_list(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t b[64] = { 0 };

    femu_opal_init(o, &cfg);
    g_assert_cmpint(femu_opal_recv(o, 0, 0, b, sizeof(b)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be16(b + 6), ==, 3);
    g_assert_cmpuint(b[8], ==, 0);
    g_assert_cmpuint(b[9], ==, 1);
    g_assert_cmpuint(b[10], ==, 2);
    g_assert_cmpint(femu_opal_recv(o, 0, 2, b, sizeof(b)), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_recv(o, 3, 0, b, sizeof(b)), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 0, 0, b, 8), ==, FEMU_OPAL_IF_INVALID);
    g_free(o);
}

static void test_comid_state(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t s[FEMU_OPAL_BUF];
    uint8_t r[FEMU_OPAL_BUF];
    uint32_t n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    uint32_t need;

    femu_opal_init(o, &cfg);

    /* idle: an empty ComPacket */
    memset(r, 0xAA, sizeof(r));
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, 20), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be16(r + 4), ==, FEMU_OPAL_COMID);
    g_assert_cmpuint(be32(r + 8), ==, 0);
    g_assert_cmpuint(be32(r + 16), ==, 0);

    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_true(o->ready);
    need = o->resp_len;

    /* a Send while the response waits */
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_SEQUENCE);

    /* a short Receive keeps the response and says what it needs */
    memset(r, 0, sizeof(r));
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, need - 1), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_true(o->ready);
    g_assert_cmpuint(be32(r + 8), ==, need);
    g_assert_cmpuint(be32(r + 12), ==, need);
    g_assert_cmpuint(be32(r + 16), ==, 0);

    /* zero length: nothing moves, nothing is taken */
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, 0), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_true(o->ready);

    /* a Receive whose transfer failed: no consume, the response stays */
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_true(o->ready);

    memset(r, 0, sizeof(r));
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_false(o->ready);
    g_assert_cmpuint(be32(r + 8), ==, 0);
    g_assert_cmpuint(be32(r + 16) + 20, ==, need);
    /* Packet TSN and HSN echo the control session: 0 */
    g_assert_cmpuint(be32(r + 20), ==, 0);
    g_assert_cmpuint(be32(r + 24), ==, 0);
    /* the reply opens with CALL SMUID Properties */
    g_assert_cmpuint(r[56], ==, 0xF8);
    g_assert_cmpmem(r + 57, 19, props_call + 1, 18 + 1);
    g_free(o);
}

/* the status list at the end of a reply: EOD SL 0 0 0 EL */
static void assert_status_ok(const uint8_t *r)
{
    uint32_t slen = be32(r + 52);
    const uint8_t *e = r + 56 + slen;

    g_assert_cmpuint(e[-6], ==, 0xF9);
    g_assert_cmpuint(e[-5], ==, 0xF0);
    g_assert_cmpuint(e[-4], ==, 0);
    g_assert_cmpuint(e[-1], ==, 0xF1);
}

static void test_properties_host(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t p[256];
    uint8_t s[FEMU_OPAL_BUF];
    uint8_t r[FEMU_OPAL_BUF] = { 0 };
    FemuOpalEnc e = { .buf = p, .cap = sizeof(p) };
    FemuOpalTok *t = g_new(FemuOpalTok, 256);
    uint64_t host_cp = 0;
    uint64_t host_pkts = 0;
    int n;
    int i;
    int section = 0;

    femu_opal_init(o, &cfg);
    memcpy(p, props_call, 19);
    e.len = 19;
    femu_opal_enc_ctrl(&e, 0xF0);
    femu_opal_enc_ctrl(&e, 0xF2);
    femu_opal_enc_uint(&e, 0);
    femu_opal_enc_ctrl(&e, 0xF0);
    femu_opal_enc_ctrl(&e, 0xF2);
    femu_opal_enc_bytes(&e, "MaxComPacketSize", 16);
    femu_opal_enc_uint(&e, 100);            /* below the minimum */
    femu_opal_enc_ctrl(&e, 0xF3);
    femu_opal_enc_ctrl(&e, 0xF2);
    femu_opal_enc_bytes(&e, "MaxPackets", 10);
    femu_opal_enc_uint(&e, 3);
    femu_opal_enc_ctrl(&e, 0xF3);
    femu_opal_enc_ctrl(&e, 0xF1);
    femu_opal_enc_ctrl(&e, 0xF3);
    femu_opal_enc_ctrl(&e, 0xF1);
    memcpy(p + e.len, props_call + 21, 6);
    e.len += 6;

    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s,
                                   frame(s, p, e.len, FEMU_OPAL_COMID)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    assert_status_ok(r);
    n = femu_opal_decode(r + 56, be32(r + 52), t, 256);
    g_assert_cmpint(n, >, 0);
    /* the host list is the second SL inside the parameters */
    for (i = 0; i + 2 < n; i++) {
        if (t[i].type == FEMU_OPAL_TOK_CTRL && t[i].val == 0xF2 &&
            t[i + 1].type == FEMU_OPAL_TOK_UINT && t[i + 1].val == 0) {
            section = 1;
        }
        if (section && t[i].type == FEMU_OPAL_TOK_BYTES &&
            t[i].len == 16 && !memcmp(t[i].p, "MaxComPacketSize", 16)) {
            host_cp = t[i + 1].val;
        }
        if (section && t[i].type == FEMU_OPAL_TOK_BYTES &&
            t[i].len == 10 && !memcmp(t[i].p, "MaxPackets", 10)) {
            host_pkts = t[i + 1].val;
        }
    }
    g_assert_cmpuint(host_cp, ==, 2048);
    g_assert_cmpuint(host_pkts, ==, 3);

    /* STACK_RESET puts the host properties back to their minimums */
    memset(s, 0, 8);
    set32(s, FEMU_OPAL_COMID << 16);
    set32(s + 4, 2);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, s, 8), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(o->host.max_packets, ==, 1);
    g_free(t);
    g_free(o);
}

static void test_bad_frames(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t s[FEMU_OPAL_BUF];
    uint32_t n;
    static const uint8_t other_method[] = {
        0xF8,
        0xA8, 0, 0, 0, 0, 0, 0, 0, 0xFF,
        0xA8, 0, 0, 0, 0, 0, 0, 0xFF, 0x77,
        0xF0, 0xF1,
        0xF9, 0xF0, 0x00, 0x00, 0x00, 0xF1,
    };

    femu_opal_init(o, &cfg);
    /* wrong ComID inside the ComPacket: dropped, no response */
    n = frame(s, props_call, sizeof(props_call), 0x1001);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* Subpacket length past the Packet */
    n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    set32(s + 52, 4000);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* ComPacket length past the transfer */
    n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n - 8), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* a nonzero pad byte */
    n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    s[56 + sizeof(props_call)] = 1;
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* a Packet with room for a second Subpacket */
    n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    set32(s + 16, be32(s + 16) + 16);
    set32(s + 40, be32(s + 40) + 16);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n + 16), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* an unknown Session Manager method gets no response */
    n = frame(s, other_method, sizeof(other_method), FEMU_OPAL_COMID);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* a session other than the control session: none exists yet */
    n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    set32(s + 20, 4096);
    set32(s + 24, 0x41);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* interface errors */
    g_assert_cmpint(femu_opal_send(o, 1, 0x1001, s, 64), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s,
                                   FEMU_OPAL_BUF + 1), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID_TPER_RESET, s, 64),
                    ==, FEMU_OPAL_IF_INVALID);
    /* a Level 0 send is discarded */
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID_L0, s, 64), ==,
                    FEMU_OPAL_IF_GOOD);
    g_free(o);
}

/* a host status of 1 aborts Properties: empty result, status 1 */
static void test_properties_abort(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t p[sizeof(props_call)];
    uint8_t s[FEMU_OPAL_BUF];
    uint8_t r[FEMU_OPAL_BUF] = { 0 };
    uint32_t slen;

    femu_opal_init(o, &cfg);
    memcpy(p, props_call, sizeof(p));
    p[23] = 0x01;
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s,
                                   frame(s, p, sizeof(p), FEMU_OPAL_COMID)),
                    ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    slen = be32(r + 52);
    /* CALL SMUID Properties SL EL EOD SL 1 0 0 EL */
    g_assert_cmpuint(slen, ==, sizeof(props_call));
    g_assert_cmpuint(r[56 + 19], ==, 0xF0);
    g_assert_cmpuint(r[56 + 20], ==, 0xF1);
    g_assert_cmpuint(r[56 + 23], ==, 0x01);
    g_free(o);
}

static void test_properties_count(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t s[FEMU_OPAL_BUF];
    uint8_t r[FEMU_OPAL_BUF] = { 0 };
    FemuOpalTok *t = g_new(FemuOpalTok, FEMU_OPAL_MAX_TOKS);
    int n;
    int i;
    bool dst = false;

    femu_opal_init(o, &cfg);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s,
                                   frame(s, props_call, sizeof(props_call),
                                         FEMU_OPAL_COMID)),
                    ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    assert_status_ok(r);
    n = femu_opal_decode(r + 56, be32(r + 52), t, FEMU_OPAL_MAX_TOKS);
    /* Linux parses at most 64 tokens */
    g_assert_cmpint(n, >, 0);
    g_assert_cmpint(n, <=, 64);
    for (i = 0; i < n; i++) {
        if (t[i].type == FEMU_OPAL_TOK_BYTES && t[i].len == 17 &&
            !memcmp(t[i].p, "DefSessionTimeout", 17)) {
            dst = true;
        }
    }
    g_assert_true(dst);
    g_free(t);
    g_free(o);
}

static void test_stack_reset(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t s[FEMU_OPAL_BUF];
    uint8_t r[64];
    uint32_t n = frame(s, props_call, sizeof(props_call), FEMU_OPAL_COMID);
    uint8_t m[8] = { 0 };

    femu_opal_init(o, &cfg);
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, s, n), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_true(o->ready);

    /* no request yet: "No Response Available" */
    memset(r, 0xAA, sizeof(r));
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_cmpuint(be32(r), ==, 0);
    g_assert_cmpuint(be32(r + 4), ==, 0);
    g_assert_cmpuint(be16(r + 10), ==, 0);
    g_assert_true(o->ready);

    /* fewer than 8 bytes, a wrong ComID, an unknown request */
    set32(m, FEMU_OPAL_COMID << 16);
    set32(m + 4, 2);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 7), ==,
                    FEMU_OPAL_IF_INVALID);
    set32(m, 0x10010000);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_INVALID);
    set32(m, FEMU_OPAL_COMID << 16);
    set32(m + 4, 3);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_true(o->ready);

    set32(m + 4, 2);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_false(o->ready);
    /* a short Receive leaves the result for a full one */
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, 12), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_cmpuint(o->mgmt_req, ==, 2);
    memset(r, 0xAA, sizeof(r));
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    g_assert_cmpuint(be32(r + 4), ==, 2);
    g_assert_cmpuint(be16(r + 8), ==, 0);
    g_assert_cmpuint(be16(r + 10), ==, 4);
    g_assert_cmpuint(be32(r + 12), ==, 0);
    /* the response is taken once */
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be32(r + 4), ==, 0);

    /* VERIFY_COMID_VALID: Issued, no clock; it stays for each Receive */
    set32(m + 4, 1);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_GOOD);
    for (int i = 0; i < 2; i++) {
        g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)),
                        ==, FEMU_OPAL_IF_GOOD);
        femu_opal_consume(o);
        g_assert_cmpuint(be32(r), ==, FEMU_OPAL_COMID << 16);
        g_assert_cmpuint(be16(r + 10), ==, 0x22);
        g_assert_cmpuint(be32(r + 12), ==, FEMU_OPAL_COMID_ISSUED);
    }
    /* about another ComID: Invalid */
    set32(m, 0x20000000);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be32(r), ==, 0x20000000);
    g_assert_cmpuint(be32(r + 12), ==, 0);
    /* a bad request after it: "No Response Available" */
    set32(m + 4, 9);
    g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, m, 8), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_recv(o, 2, FEMU_OPAL_COMID, r, sizeof(r)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be32(r + 4), ==, 0);
    g_free(o);
}

/*
 * S2: sessions, the Admin SP and Block SID. Requests come from a small
 * byte builder here, so the encoder under test does not write them.
 */
#define U_SMUID     0x00000000000000FFull
#define U_START     0x000000000000FF02ull
#define U_THISSP    0x0000000000000001ull
#define U_ADMINSP   0x0000020500000001ull
#define U_LOCKINGSP 0x0000020500000002ull
#define U_TPERINFO  0x0000020100030001ull
#define U_ANYBODY   0x0000000900000001ull
#define U_ADMINS    0x0000000900000002ull
#define U_SID       0x0000000900000006ull
#define U_ASP_ADM1  0x0000000900000201ull
#define U_PSID      0x000000090001FF01ull
#define U_LSP_ADM1  0x0000000900010001ull
#define U_CPIN_SID  0x0000000B00000001ull
#define U_CPIN_MSID 0x0000000B00008402ull
#define U_CPIN_ADM1 0x0000000B00000201ull
#define U_CPIN_PSID 0x0000000B0001FF01ull
#define U_T_CPIN    0x0000000B00000000ull
#define M_NEXT      0x0000000600000008ull
#define M_GET       0x0000000600000016ull
#define M_SET       0x0000000600000017ull
#define M_AUTH      0x000000060000001Cull
#define M_REVERT    0x0000000600000202ull
#define M_ACTIVATE  0x0000000600000203ull
#define M_RANDOM    0x0000000600000601ull
#define HSN         0x42

typedef struct Tb {
    uint8_t b[FEMU_OPAL_BUF];
    uint32_t n;
} Tb;

static void tb_c(Tb *t, uint8_t c)
{
    t->b[t->n++] = c;
}

/* tiny atom below 64, else a short atom (Core 3.2.2.3.1) */
static void tb_u(Tb *t, uint64_t v)
{
    int len = 0;
    int i;

    if (v < 64) {
        tb_c(t, v);
        return;
    }
    for (i = 0; i < 8; i++) {
        if (v >> (8 * i)) {
            len = i + 1;
        }
    }
    tb_c(t, 0x80 | len);
    for (i = len - 1; i >= 0; i--) {
        tb_c(t, v >> (8 * i));
    }
}

static void tb_s(Tb *t, const void *p, uint32_t len)
{
    g_assert_cmpuint(len, <, 16);
    tb_c(t, 0xA0 | len);
    memcpy(t->b + t->n, p, len);
    t->n += len;
}

static void tb_uid(Tb *t, uint64_t uid)
{
    int i;

    tb_c(t, 0xA8);
    for (i = 7; i >= 0; i--) {
        tb_c(t, uid >> (8 * i));
    }
}

static void tb_call(Tb *t, uint64_t obj, uint64_t m)
{
    tb_c(t, 0xF8);
    tb_uid(t, obj);
    tb_uid(t, m);
    tb_c(t, 0xF0);
}

/* EL EOD SL 0 0 0 EL */
static void tb_end(Tb *t)
{
    static const uint8_t e[] = { 0xF1, 0xF9, 0xF0, 0, 0, 0, 0xF1 };

    memcpy(t->b + t->n, e, sizeof(e));
    t->n += sizeof(e);
}

static uint8_t rb[FEMU_OPAL_BUF];
static FemuOpalTok rt[FEMU_OPAL_MAX_TOKS];

/* send @t in a Packet for @tsn; returns the reply token count, or -1 */
static int xfer(FemuOpal *o, Tb *t, uint32_t tsn)
{
    uint8_t b[FEMU_OPAL_BUF];
    uint32_t len = frame(b, t->b, t->n, FEMU_OPAL_COMID);

    if (tsn) {
        set32(b + 20, tsn);
        set32(b + 24, HSN);
    }
    g_assert_cmpint(femu_opal_send(o, 1, FEMU_OPAL_COMID, b, len), ==,
                    FEMU_OPAL_IF_GOOD);
    memset(rb, 0, sizeof(rb));
    g_assert_cmpint(femu_opal_recv(o, 1, FEMU_OPAL_COMID, rb, sizeof(rb)),
                    ==, FEMU_OPAL_IF_GOOD);
    femu_opal_consume(o);
    if (!be32(rb + 16)) {
        return -1;
    }
    if (tsn) {
        g_assert_cmpuint(be32(rb + 20), ==, tsn);
        g_assert_cmpuint(be32(rb + 24), ==, HSN);
    }
    return femu_opal_decode(rb + 56, be32(rb + 52), rt, FEMU_OPAL_MAX_TOKS);
}

/* the status of a method reply: ... EOD SL s 0 0 EL */
static uint64_t reply_status(int n)
{
    g_assert_cmpint(n, >=, 6);
    g_assert_cmpuint(rt[n - 6].val, ==, 0xF9);
    return rt[n - 4].val;
}

/* the Write parameter of the next StartSession calls */
static int start_write = 1;

/* StartSession to @sp as @auth (0: Anybody); sets *tsn, returns status */
static uint64_t start(FemuOpal *o, uint64_t sp, uint64_t auth,
                      const char *pin, uint32_t *tsn)
{
    Tb t = { .n = 0 };
    int n;

    tb_call(&t, U_SMUID, U_START);
    tb_u(&t, HSN);
    tb_uid(&t, sp);
    tb_u(&t, start_write);
    if (pin) {
        tb_c(&t, 0xF2);
        tb_u(&t, 0);
        tb_s(&t, pin, strlen(pin));
        tb_c(&t, 0xF3);
    }
    if (auth) {
        tb_c(&t, 0xF2);
        tb_u(&t, 3);
        tb_uid(&t, auth);
        tb_c(&t, 0xF3);
    }
    tb_end(&t);
    n = xfer(o, &t, 0);
    g_assert_cmpint(n, >, 0);
    if (!reply_status(n)) {
        g_assert_cmpuint(rt[4].val, ==, HSN);
        g_assert_cmpuint(rt[5].val, >=, 0x1000);
        *tsn = rt[5].val;
    }
    return reply_status(n);
}

static void eos(FemuOpal *o, uint32_t tsn)
{
    Tb t = { .n = 0 };

    tb_c(&t, 0xFA);
    g_assert_cmpint(xfer(o, &t, tsn), ==, 1);
    g_assert_cmpuint(rt[0].val, ==, 0xFA);
}

/* Get columns @c0..@c1 of @obj; returns the reply token count */
static int get(FemuOpal *o, uint32_t tsn, uint64_t obj, int c0, int c1)
{
    Tb t = { .n = 0 };

    tb_call(&t, obj, M_GET);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, 3);
    tb_u(&t, c0);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF2);
    tb_u(&t, 4);
    tb_u(&t, c1);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_end(&t);
    return xfer(o, &t, tsn);
}

/* Set one column of @obj to a uint, or to bytes when @s is not NULL */
static uint64_t set(FemuOpal *o, uint32_t tsn, uint64_t obj, int col,
                    const char *s, uint64_t v, bool txn)
{
    Tb t = { .n = 0 };

    if (txn) {
        tb_c(&t, 0xFB);
        tb_u(&t, 0);
    }
    tb_call(&t, obj, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, col);
    if (s) {
        tb_s(&t, s, strlen(s));
    } else {
        tb_u(&t, v);
    }
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

/* a method with no parameters on @obj */
static uint64_t call0(FemuOpal *o, uint32_t tsn, uint64_t obj, uint64_t m)
{
    Tb t = { .n = 0 };

    tb_call(&t, obj, m);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

static void s2_init(FemuOpal *o)
{
    FemuOpalCfg c = cfg;

    c.msid.len = 6;
    memcpy(c.msid.v, "MSID-1", 6);
    c.psid.len = 6;
    memcpy(c.psid.v, "PSID-1", 6);
    femu_opal_init(o, &c);
}

/* the take-ownership flow of sed-opal and sedutil */
static void test_s2_ownership(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    n = get(o, tsn, U_CPIN_MSID, 3, 3);
    g_assert_cmpuint(reply_status(n), ==, 0);
    /* SL SL SN 3 PIN EN EL EL */
    g_assert_cmpuint(rt[3].val, ==, 3);
    g_assert_cmpuint(rt[4].len, ==, 6);
    g_assert(!memcmp(rt[4].p, "MSID-1", 6));
    /* Anybody cannot read C_PIN_SID at all */
    g_assert_cmpuint(reply_status(get(o, tsn, U_CPIN_SID, 0, 7)), ==, 0x01);
    eos(o, tsn);

    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "owner", 0, false), ==, 0);
    /* SID reads the row, but never its PIN */
    n = get(o, tsn, U_CPIN_SID, 0, 7);
    g_assert_cmpuint(reply_status(n), ==, 0);
    for (int i = 0; i < n; i++) {
        g_assert(!(rt[i].type == FEMU_OPAL_TOK_UINT && rt[i].val == 3 &&
                   i > 0 && rt[i - 1].val == 0xF2));
    }
    eos(o, tsn);

    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "owner", &tsn), ==, 0);
    eos(o, tsn);
    g_free(o);
}

static void test_s2_sessions(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    uint32_t t2;
    Tb t = { .n = 0 };

    s2_init(o);
    /* no session to a Manufactured-Inactive Locking SP */
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0x3F);
    /* a class authority cannot open a session */
    g_assert_cmpuint(start(o, U_ADMINSP, U_ADMINS, "x", &tsn), ==, 0x0C);
    /* Anybody ignores a host challenge */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, "x", &tsn), ==, 0);
    /* MaxSessions 1 */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &t2), ==, 0x07);
    /* a Packet for another session gets no reply */
    tb_c(&t, 0xFA);
    g_assert_cmpint(xfer(o, &t, tsn + 1), ==, -1);
    /* Anybody cannot write */
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "x", 0, false), ==, 0x01);
    eos(o, tsn);
    /* each session gets a new TSN */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &t2), ==, 0);
    g_assert_cmpuint(t2, !=, tsn);
    /* STACK_RESET ends it */
    {
        uint8_t b[8] = { 0x10, 0, 0, 0, 0, 0, 0, 2 };

        g_assert_cmpint(femu_opal_send(o, 2, FEMU_OPAL_COMID, b, 8), ==,
                        FEMU_OPAL_IF_GOOD);
    }
    g_assert_cmpint(xfer(o, &t, t2), ==, -1);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    g_free(o);
}

static void test_s2_activate_revert(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    n = get(o, tsn, U_LOCKINGSP, 6, 6);
    g_assert_cmpuint(rt[4].val, ==, 8);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    get(o, tsn, U_LOCKINGSP, 6, 6);
    g_assert_cmpuint(rt[4].val, ==, 9);
    /* a second Activate changes nothing */
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    eos(o, tsn);

    /* Admin1 of the Locking SP took the SID PIN */
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    eos(o, tsn);

    /* Revert of the Admin SP: success, then the session is gone */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_ADMINSP, M_REVERT), ==, 0);
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0x3F);
    g_free(o);
}

static void test_s2_psid(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "lost", 0, false), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    eos(o, tsn);

    g_assert_cmpuint(start(o, U_ADMINSP, U_PSID, "wrong", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, U_PSID, "PSID-1", &tsn), ==, 0);
    /* PSID may not change PINs or activate */
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "x", 0, false), ==, 0x01);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0x01);
    /* C_PIN_PSID never shows its PIN */
    n = get(o, tsn, U_CPIN_PSID, 3, 3);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 6);
    g_assert_cmpuint(call0(o, tsn, U_ADMINSP, M_REVERT), ==, 0);

    /* factory state: SID is MSID again, the Locking SP is inactive */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    get(o, tsn, U_LOCKINGSP, 6, 6);
    g_assert_cmpuint(rt[4].val, ==, 8);
    eos(o, tsn);
    g_free(o);
}

static void test_s2_transactions(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    Tb t = { .n = 0 };
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    /* ST 0, Set: the reply opens with ST 0 */
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "new", 0, true), ==, 0);
    g_assert_cmpuint(rt[0].val, ==, 0xFB);
    /* Activate inside a transaction fails */
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0x3F);
    /* ET 1 aborts, and the reply mirrors it */
    tb_c(&t, 0xFC);
    tb_u(&t, 1);
    n = xfer(o, &t, tsn);
    g_assert_cmpint(n, ==, 2);
    g_assert_cmpuint(rt[0].val, ==, 0xFC);
    g_assert_cmpuint(rt[1].val, ==, 1);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);

    /* ET 0 commits */
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "new", 0, true), ==, 0);
    t.n = 0;
    tb_c(&t, 0xFC);
    tb_u(&t, 0);
    g_assert_cmpint(xfer(o, &t, tsn), ==, 2);
    g_assert_cmpuint(rt[1].val, ==, 0);

    /* nested ST aborts the session with no reply */
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "newer", 0, true), ==, 0);
    t.n = 0;
    tb_c(&t, 0xFB);
    tb_u(&t, 0);
    g_assert_cmpint(xfer(o, &t, tsn), ==, -1);
    g_assert_cmpint(xfer(o, &t, tsn), ==, -1);
    /* the open transaction rolled back with the session */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "newer", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "new", &tsn), ==, 0);
    g_free(o);
}

static uint8_t l0_block_sid(FemuOpal *o, int byte)
{
    uint8_t b[256] = { 0 };

    femu_opal_level0(o, b, sizeof(b));
    g_assert_cmpuint(be16(b + 148), ==, 0x0402);
    return b[148 + byte];
}

static void test_s2_block_sid(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t hw[2] = { 1, 0 };
    uint8_t freeze[2] = { 0, 1 };
    uint32_t tsn;

    s2_init(o);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0);
    g_assert_cmpint(femu_opal_send_check(o, 2, 5, 0), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 2, 5, freeze, 2), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x02);
    g_assert_cmpuint(l0_block_sid(o, 5), ==, 0x01);
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==,
                    FEMU_OPAL_IF_INVALID);
    /* SID with the MSID PIN is blocked; Anybody is not */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    eos(o, tsn);

    femu_opal_power_cycle(o);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "owned", 0, false), ==, 0);
    eos(o, tsn);
    /* an owned SID: the command succeeds and blocks nothing */
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x01);
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "owned", &tsn), ==, 0);
    g_free(o);
}

static void test_s2_tper_reset(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t z[8] = { 0 };
    uint32_t tsn;
    Tb t = { .n = 0 };

    s2_init(o);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_INVALID);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    /* only SID may set ProgrammaticResetEnable */
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0x01);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0);
    get(o, tsn, U_TPERINFO, 8, 8);
    g_assert_cmpuint(rt[4].val, ==, 1);
    /* the reset ends the open session */
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_GOOD);
    tb_c(&t, 0xFA);
    g_assert_cmpint(xfer(o, &t, tsn), ==, -1);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    g_free(o);
}

static void test_s2_methods(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    Tb t = { .n = 0 };
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    /* Next on C_PIN: four rows */
    tb_call(&t, U_T_CPIN, M_NEXT);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 4 + 6);
    /* Random: at most 32 bytes */
    t.n = 0;
    tb_call(&t, U_THISSP, M_RANDOM);
    tb_u(&t, 16);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(rt[1].len, ==, 16);
    t.n = 0;
    tb_call(&t, U_THISSP, M_RANDOM);
    tb_u(&t, 33);
    tb_end(&t);
    g_assert_cmpuint(reply_status(xfer(o, &t, tsn)), ==, 0x0C);

    /* enable Admin1 of the Admin SP and give it a PIN */
    g_assert_cmpuint(set(o, tsn, U_ASP_ADM1, 5, NULL, 1, false), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_ADM1, 3, "adm", 0, false), ==, 0);
    /* Authenticate: a wrong PIN is a SUCCESS with result False */
    t.n = 0;
    tb_call(&t, U_THISSP, M_AUTH);
    tb_uid(&t, U_ASP_ADM1);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_s(&t, "bad", 3);
    tb_c(&t, 0xF3);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(rt[1].val, ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_ADMINSP, U_ASP_ADM1, "adm", &tsn), ==, 0);
    /* Admin1 cannot set ProgrammaticResetEnable */
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0x01);
    eos(o, tsn);
    g_free(o);
}

#define U_T_AUTH    0x0000000900000000ull
#define U_T_AC      0x0000000700000000ull
#define M_GETACL    0x000000060000000Dull

/* send raw payload bytes in session @tsn; returns the reply token count */
static int raw(FemuOpal *o, uint32_t tsn, const uint8_t *p, uint32_t len)
{
    Tb t = { .n = len };

    memcpy(t.b, p, len);
    return xfer(o, &t, tsn);
}

/* true when session @tsn is gone: a Random[1] in it gets no reply */
static bool session_gone(FemuOpal *o, uint32_t tsn)
{
    Tb t = { .n = 0 };

    tb_call(&t, U_THISSP, M_RANDOM);
    tb_u(&t, 1);
    tb_end(&t);
    return xfer(o, &t, tsn) == -1;
}

/* the tables a transaction changes stay hidden outside the session */
static void test_s2_txn_isolation(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t hw[2] = { 1, 0 };
    uint8_t z[8] = { 0 };
    uint32_t tsn;
    Tb t = { .n = 0 };

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "owned", 0, true), ==, 0);
    /* Level 0 still shows the committed MSID PIN, and Block SID blocks */
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0);
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x02);
    /* PRE set in the transaction does not allow TPER_RESET yet */
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_INVALID);
    tb_c(&t, 0xFC);
    tb_u(&t, 1);
    g_assert_cmpint(xfer(o, &t, tsn), ==, 2);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_INVALID);
    g_free(o);
}

/* bad streams abort the session and roll back its transaction */
static void test_s2_aborts(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    static const uint8_t reserved[] = { 0xE4 };
    static const uint8_t st_st[] = { 0xFB, 0x00, 0xFB, 0x00 };
    uint32_t tsn;
    Tb t = { .n = 0 };
    int n;

    s2_init(o);
    /* a reserved token in a transaction: abort, the PIN rolls back */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "new", 0, true), ==, 0);
    g_assert_cmpint(raw(o, tsn, reserved, 1), ==, -1);
    g_assert(session_gone(o, tsn));
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "new", &tsn), ==, 0x01);

    /* ST inside a method's parameters */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    tb_call(&t, U_THISSP, M_RANDOM);
    tb_c(&t, 0xFB);
    tb_u(&t, 0);
    tb_end(&t);
    g_assert_cmpint(xfer(o, &t, tsn), ==, -1);
    g_assert(session_gone(o, tsn));

    /* a status list with a byte string where a uint must be */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    t.n = 0;
    tb_call(&t, U_CPIN_SID, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, 3);
    tb_s(&t, "bad", 3);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    memcpy(t.b + t.n, (uint8_t[]){ 0xF1, 0xF9, 0xF0, 0, 0xA0, 0, 0xF1 }, 7);
    t.n += 7;
    g_assert_cmpint(xfer(o, &t, tsn), ==, -1);
    g_assert(session_gone(o, tsn));
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "bad", &tsn), ==, 0x01);

    /* ST ST: over MaxTransactionLimit */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpint(raw(o, tsn, st_st, 4), ==, -1);
    g_assert(session_gone(o, tsn));

    /* a method, then EOS: the reply has both, and the session ends */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    t.n = 0;
    tb_call(&t, U_THISSP, M_RANDOM);
    tb_u(&t, 1);
    tb_end(&t);
    tb_c(&t, 0xFA);
    n = xfer(o, &t, tsn);
    g_assert_cmpint(n, >, 7);
    g_assert_cmpuint(rt[n - 1].val, ==, 0xFA);
    g_assert(session_gone(o, tsn));
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    g_free(o);
}

static uint64_t authenticate(FemuOpal *o, uint32_t tsn, uint64_t au,
                             const char *pin, bool txn)
{
    Tb t = { .n = 0 };
    int n;

    if (txn) {
        tb_c(&t, 0xFB);
        tb_u(&t, 0);
    }
    tb_call(&t, U_THISSP, M_AUTH);
    tb_uid(&t, au);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_s(&t, pin, strlen(pin));
    tb_c(&t, 0xF3);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    /* [ST 0] SL result EL */
    return rt[txn ? 3 : 1].val;
}

static void test_s2_authenticate(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    Tb t = { .n = 0 };

    s2_init(o);
    /* Anybody, then SID by Authenticate: True, and SID may write */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    g_assert_cmpuint(authenticate(o, tsn, U_SID, "MSID-1", false), ==, 1);
    g_assert_cmpuint(set(o, tsn, U_ASP_ADM1, 5, NULL, 1, false), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_ADM1, 3, "adm", 0, false), ==, 0);
    /* a third authority is over MaxAuthentications 2: False */
    g_assert_cmpuint(authenticate(o, tsn, U_ASP_ADM1, "adm", false), ==, 0);
    eos(o, tsn);

    /* an aborted transaction takes the authentication back */
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    g_assert_cmpuint(authenticate(o, tsn, U_SID, "MSID-1", true), ==, 1);
    tb_c(&t, 0xFC);
    tb_u(&t, 1);
    g_assert_cmpint(xfer(o, &t, tsn), ==, 2);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "x", 0, false), ==, 0x01);
    eos(o, tsn);

    /* TryLimit 0: failures never count in Tries */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "bad", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(authenticate(o, tsn, U_SID, "bad", false), ==, 0);
    get(o, tsn, U_CPIN_SID, 6, 6);
    g_assert_cmpuint(rt[3].val, ==, 6);
    g_assert_cmpuint(rt[4].val, ==, 0);
    eos(o, tsn);
    g_free(o);
}

static void test_s2_tables(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    Tb t = { .n = 0 };
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    /* Admin1: Class is Admins, Credential is C_PIN_Admin1 */
    n = get(o, tsn, U_ASP_ADM1, 4, 4);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(rt[4].len, ==, 8);
    g_assert_cmpuint(rt[4].p[7], ==, 0x02);
    n = get(o, tsn, U_ASP_ADM1, 10, 10);
    g_assert_cmpuint(rt[4].len, ==, 8);
    g_assert_cmpuint(rt[4].p[3], ==, 0x0B);
    g_assert_cmpuint(rt[4].p[6], ==, 0x02);
    /* CharSet is a NULL uid */
    get(o, tsn, U_CPIN_SID, 4, 4);
    g_assert_cmpuint(rt[4].type, ==, FEMU_OPAL_TOK_BYTES);
    g_assert_cmpuint(rt[4].len, ==, 8);
    /* columns outside the table */
    g_assert_cmpuint(reply_status(get(o, tsn, U_CPIN_SID, 32, 32)), ==, 0x0C);
    g_assert_cmpuint(reply_status(get(o, tsn, U_CPIN_SID, 0, 8)), ==, 0x0C);
    g_assert_cmpuint(reply_status(get(o, tsn, U_CPIN_SID, 5, 4)), ==, 0x0C);

    /* Set with one column twice fails and changes nothing */
    tb_call(&t, U_CPIN_SID, M_SET);
    memcpy(t.b + t.n, (uint8_t[]){ 0xF2, 1, 0xF0,
                                   0xF2, 3, 0xA3, 'o', 'n', 'e', 0xF3,
                                   0xF2, 3, 0xA3, 't', 'w', 'o', 0xF3,
                                   0xF1, 0xF3 }, 19);
    t.n += 19;
    tb_end(&t);
    g_assert_cmpuint(reply_status(xfer(o, &t, tsn)), ==, 0x0C);
    /* Set with no Values: success, no change */
    g_assert_cmpuint(call0(o, tsn, U_CPIN_SID, M_SET), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);

    /* Next on Authority: Where = SID, Count = 2 gives Admin1, PSID */
    t.n = 0;
    tb_call(&t, U_T_AUTH, M_NEXT);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_uid(&t, U_SID);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_u(&t, 2);
    tb_c(&t, 0xF3);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 2 + 6);
    g_assert_cmpuint(rt[2].p[6], ==, 0x02);
    g_assert_cmpuint(rt[3].p[5], ==, 0x01);
    /* after the last row: an empty list */
    t.n = 0;
    tb_call(&t, U_T_AUTH, M_NEXT);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_uid(&t, U_PSID);
    tb_c(&t, 0xF3);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpint(n, ==, 4 + 6);
    eos(o, tsn);
    g_free(o);
}

/* GetACL[obj, method] in session @tsn; returns the reply token count */
static int getacl(FemuOpal *o, uint32_t tsn, uint64_t obj, uint64_t m)
{
    Tb t = { .n = 0 };

    tb_call(&t, U_T_AC, M_GETACL);
    tb_uid(&t, obj);
    tb_uid(&t, m);
    tb_end(&t);
    return xfer(o, &t, tsn);
}

static uint64_t uid_of(const FemuOpalTok *k)
{
    uint64_t v = 0;
    uint32_t i;

    g_assert_cmpuint(k->len, ==, 8);
    for (i = 0; i < 8; i++) {
        v = v << 8 | k->p[i];
    }
    return v;
}

static void test_s2_getacl(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint32_t tsn;
    int n;

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, 0, NULL, &tsn), ==, 0);
    /* Revert of the Admin SP: ACE_SP_SID and ACE_SP_PSID */
    n = getacl(o, tsn, U_ADMINSP, M_REVERT);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 2 + 6);
    g_assert_cmphex(uid_of(&rt[2]), ==, 0x0000000800030002ull);
    g_assert_cmphex(uid_of(&rt[3]), ==, 0x00000008000100E0ull);
    /* C_PIN_PSID Get: the NoPIN ACE of the PSID feature */
    n = getacl(o, tsn, U_CPIN_PSID, M_GET);
    g_assert_cmphex(uid_of(&rt[2]), ==, 0x00000008000100E1ull);
    n = getacl(o, tsn, U_CPIN_MSID, M_GET);
    g_assert_cmphex(uid_of(&rt[2]), ==, 0x0000000800008C04ull);
    /* no such association */
    g_assert_cmpuint(reply_status(getacl(o, tsn, 0xDEADBEEFull, M_GET)), ==,
                     0x01);
    g_assert_cmpuint(reply_status(getacl(o, tsn, U_CPIN_PSID, M_SET)), ==,
                     0x01);
    eos(o, tsn);
    g_free(o);
}

/* interface rules: TPER_RESET length, Block SID records its choice */
static void test_s2_interface(void)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    uint8_t hw[2] = { 1, 0 };
    uint8_t z[8] = { 0 };
    uint32_t tsn;
    int n;
    Tb t = { .n = 0 };

    s2_init(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0);
    eos(o, tsn);
    /* Block SID, then TPER_RESET: SID stays blocked */
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(femu_opal_send_check(o, 2, 4, 0), ==,
                    FEMU_OPAL_IF_INVALID);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x02);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0x01);

    /* a failed StartSession still names HSN and TSN 0 */
    tb_call(&t, U_SMUID, U_START);
    tb_u(&t, HSN);
    tb_uid(&t, U_ADMINSP);
    tb_u(&t, 1);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_s(&t, "bad", 3);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF2);
    tb_u(&t, 3);
    tb_uid(&t, U_PSID);
    tb_c(&t, 0xF3);
    tb_end(&t);
    n = xfer(o, &t, 0);
    g_assert_cmpuint(reply_status(n), ==, 0x01);
    g_assert_cmpuint(rt[4].val, ==, HSN);
    g_assert_cmpuint(rt[5].val, ==, 0);

    /* an owned SID: Block SID blocks nothing, but keeps the choice */
    femu_opal_power_cycle(o);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_CPIN_SID, 3, "owned", 0, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpint(femu_opal_send(o, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(o, 4), ==, 0x01);
    g_assert_cmpuint(l0_block_sid(o, 5), ==, 0x01);
    g_free(o);
}

/* ---- S3a: the Locking SP ---- */

#define U_LOCK(r)   ((r) ? 0x0000080200030000ull + (r) : 0x0000080200000001ull)
#define U_KAES(r)   ((r) ? 0x0000080600030000ull + (r) : 0x0000080600000001ull)
#define U_T_LOCK    0x0000080200000000ull
#define U_MBRCTL    0x0000080300000001ull
#define U_T_MBR     0x0000080400000000ull
#define U_T_DS      0x0000100100000000ull
#define U_USER(i)   (0x0000000900030001ull + (i))
#define U_USERS     0x0000000900030000ull
#define U_LCPIN_USER(i) (0x0000000B00030001ull + (i))
#define U_ACE_RDLOCKED(r) (0x000000080003E000ull + (r))
#define U_ACE_WRLOCKED(r) (0x000000080003E800ull + (r))
#define U_ACE_GLOBAL_SET  0x000000080003F000ull
#define U_ACE_RANGE_SET   0x000000080003F001ull
#define U_ACE_ADMINS_CN   0x0000000800000004ull
#define U_ACE_CPIN_USER(i) (0x000000080003A801ull + (i))
#define M_GENKEY    0x0000000600000010ull
#define M_REVERTSP  0x0000000600000011ull
#define NLBAS       1000

/* the erases the engine asked for */
static struct {
    int n;
    uint64_t slba[32];
    uint64_t nlb[32];
} er;

static void erase_cb(void *opaque, uint64_t slba, uint64_t nlb)
{
    g_assert_cmpint(er.n, <, 32);
    er.slba[er.n] = slba;
    er.nlb[er.n] = nlb;
    er.n++;
}

/* exactly the erases @want, as (slba, nlb) pairs, then the log is cleared */
static void erased(int n, const uint64_t *want)
{
    int i;

    g_assert_cmpint(er.n, ==, n);
    for (i = 0; i < n; i++) {
        g_assert_cmpuint(er.slba[i], ==, want[2 * i]);
        g_assert_cmpuint(er.nlb[i], ==, want[2 * i + 1]);
    }
    er.n = 0;
}

/* an active Locking SP and an Admin1 session to it */
static FemuOpal *s3_init(uint32_t *tsn)
{
    FemuOpal *o = g_new(FemuOpal, 1);
    FemuOpalCfg c = cfg;
    uint32_t t;

    c.msid.len = 6;
    memcpy(c.msid.v, "MSID-1", 6);
    c.nlbas = NLBAS;
    c.erase = erase_cb;
    femu_opal_init(o, &c);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &t), ==, 0);
    g_assert_cmpuint(call0(o, t, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    eos(o, t);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", tsn), ==, 0);
    er.n = 0;
    return o;
}

/* Set uint columns @cols[i] = @vals[i] of @obj; -1 ends the list */
static uint64_t lset(FemuOpal *o, uint32_t tsn, uint64_t obj, const int *cols,
                     const uint64_t *vals, bool txn)
{
    Tb t = { .n = 0 };
    int i;

    if (txn) {
        tb_c(&t, 0xFB);
        tb_u(&t, 0);
    }
    tb_call(&t, obj, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_c(&t, 0xF0);
    for (i = 0; cols[i] >= 0; i++) {
        tb_c(&t, 0xF2);
        tb_u(&t, cols[i]);
        tb_u(&t, vals[i]);
        tb_c(&t, 0xF3);
    }
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

static uint64_t range_set(FemuOpal *o, uint32_t tsn, int r, uint64_t start,
                          uint64_t len)
{
    static const int cols[] = { 3, 4, -1 };
    uint64_t vals[] = { start, len };

    return lset(o, tsn, U_LOCK(r), cols, vals, false);
}

/* LockEnabled and Locked for both directions of range @r */
static uint64_t range_lock(FemuOpal *o, uint32_t tsn, int r, bool lock)
{
    static const int cols[] = { 5, 6, 7, 8, -1 };
    uint64_t vals[] = { 1, 1, lock, lock };

    return lset(o, tsn, U_LOCK(r), cols, vals, false);
}

/* Set a reset_types list column of @obj */
static uint64_t resets_set(FemuOpal *o, uint32_t tsn, uint64_t obj, int col,
                           const int *types)
{
    Tb t = { .n = 0 };
    int i;

    tb_call(&t, obj, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, col);
    tb_c(&t, 0xF0);
    for (i = 0; types[i] >= 0; i++) {
        tb_u(&t, types[i]);
    }
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

/* Set the BooleanExpr of ACE @ace to @uids joined by @op (1: OR) */
static uint64_t expr_set(FemuOpal *o, uint32_t tsn, uint64_t ace,
                         const uint64_t *uids, int n, int op)
{
    static const uint8_t au_ref[] = { 0, 0, 0x0C, 0x05 };
    static const uint8_t bool_ace[] = { 0, 0, 0x04, 0x0E };
    Tb t = { .n = 0 };
    int i;

    tb_call(&t, ace, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, 3);
    tb_c(&t, 0xF0);
    for (i = 0; i < n; i++) {
        tb_c(&t, 0xF2);
        tb_s(&t, au_ref, 4);
        tb_uid(&t, uids[i]);
        tb_c(&t, 0xF3);
        if (i) {
            tb_c(&t, 0xF2);
            tb_s(&t, bool_ace, 4);
            tb_u(&t, op);
            tb_c(&t, 0xF3);
        }
    }
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_c(&t, 0xF3);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

/* Set[Where, Values] on a byte table */
static uint64_t bytes_set(FemuOpal *o, uint32_t tsn, uint64_t table,
                          uint64_t off, const char *s, bool txn)
{
    Tb t = { .n = 0 };

    if (txn) {
        tb_c(&t, 0xFB);
        tb_u(&t, 0);
    }
    tb_call(&t, table, M_SET);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_u(&t, off);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_s(&t, s, strlen(s));
    tb_c(&t, 0xF3);
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

/* Get[startRow, endRow] on a byte table; the bytes are rt[1] */
static int bytes_get(FemuOpal *o, uint32_t tsn, uint64_t table,
                     uint64_t first, uint64_t last)
{
    Tb t = { .n = 0 };

    tb_call(&t, table, M_GET);
    tb_c(&t, 0xF0);
    tb_c(&t, 0xF2);
    tb_u(&t, 1);
    tb_u(&t, first);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF2);
    tb_u(&t, 2);
    tb_u(&t, last);
    tb_c(&t, 0xF3);
    tb_c(&t, 0xF1);
    tb_end(&t);
    return xfer(o, &t, tsn);
}

static void et(FemuOpal *o, uint32_t tsn, int abort)
{
    Tb t = { .n = 0 };

    tb_c(&t, 0xFC);
    tb_u(&t, abort);
    g_assert_cmpint(xfer(o, &t, tsn), ==, 2);
    g_assert_cmpuint(rt[1].val, ==, abort);
}

static FemuOpalAccess check(FemuOpal *o, FemuOpalOp op, uint64_t slba,
                            uint64_t nlb)
{
    FemuOpalView v;

    femu_opal_view(o, &v);
    return femu_opal_access(&v, op, slba, nlb);
}

static uint8_t l0_locking(FemuOpal *o)
{
    uint8_t b[256];

    femu_opal_level0(o, b, sizeof(b));
    return b[68];
}

/* RevertSP with KeepGlobalRangeKey = @keep (-1: no parameter) */
static uint64_t revertsp(FemuOpal *o, uint32_t tsn, int keep)
{
    Tb t = { .n = 0 };

    tb_call(&t, U_THISSP, M_REVERTSP);
    if (keep >= 0) {
        tb_c(&t, 0xF2);
        tb_u(&t, 0x060000);
        tb_u(&t, keep);
        tb_c(&t, 0xF3);
    }
    tb_end(&t);
    return reply_status(xfer(o, &t, tsn));
}

static void test_s3_ranges(void)
{
    static const uint64_t r1[] = { 100, 50 };
    static const uint64_t back[] = { 100, 50 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    int n;

    /* Activate keeps the data: no erase so far */
    g_assert_cmpint(er.n, ==, 0);
    g_assert_cmpuint(l0_locking(o), ==, 0x0B);
    /* Range1 takes LBAs 100..149 from Global: they are erased */
    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    erased(1, r1);
    n = get(o, tsn, U_LOCK(1), 3, 4);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(rt[4].val, ==, 100);
    g_assert_cmpuint(rt[8].val, ==, 50);
    /* overlap, past the end, wrap: INVALID_PARAMETER, no change */
    g_assert_cmpuint(range_set(o, tsn, 2, 140, 20), ==, 0x0C);
    g_assert_cmpuint(range_set(o, tsn, 2, 990, 20), ==, 0x0C);
    g_assert_cmpuint(range_set(o, tsn, 2, ~0ull - 5, 10), ==, 0x0C);
    g_assert_cmpint(er.n, ==, 0);
    /* an adjacent range is fine */
    g_assert_cmpuint(range_set(o, tsn, 2, 150, 10), ==, 0);
    er.n = 0;
    /* Global has no start or length to set */
    g_assert_cmpuint(range_set(o, tsn, 0, 0, 10), ==, 0x01);
    /* a range set to its own extent erases nothing */
    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpint(er.n, ==, 0);
    /* back to length 0: the LBAs return to Global and are erased */
    g_assert_cmpuint(range_set(o, tsn, 1, 100, 0), ==, 0);
    erased(1, back);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_locks(void)
{
    static const int lor03[] = { 0, 3, -1 };
    static const int lor3[] = { 3, -1 };
    static const int lor00[] = { 0, 0, -1 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    uint8_t z[8] = { 0 };

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, true), ==, 0);
    g_assert_cmpuint(l0_locking(o) & 0x04, ==, 0x04);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_DENY);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_WRITE, 149, 1), ==, FEMU_OPAL_DENY);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 99, 1), ==, FEMU_OPAL_MEDIA);
    /* one locked LBA in the command denies all of it */
    g_assert_cmpint(check(o, FEMU_OPAL_OP_COPY_SRC, 90, 20), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_WRITE, 150, 10), ==,
                    FEMU_OPAL_MEDIA);
    /* unlock: the next power cycle locks again (LockOnReset {0}) */
    g_assert_cmpuint(range_lock(o, tsn, 1, false), ==, 0);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_MEDIA);
    g_assert_cmpuint(l0_locking(o) & 0x04, ==, 0);
    femu_opal_power_cycle(o);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_DENY);
    /* Global is locked now too, but its lock is not enabled */
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 1), ==, FEMU_OPAL_MEDIA);
    /* LockOnReset takes {0} or {0, 3} only */
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(resets_set(o, tsn, U_LOCK(1), 9, lor3), ==, 0x0C);
    g_assert_cmpuint(resets_set(o, tsn, U_LOCK(1), 9, lor00), ==, 0x0C);
    g_assert_cmpuint(resets_set(o, tsn, U_LOCK(1), 9, lor03), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, false), ==, 0);
    /* Global: lock enabled, unlocked, LockOnReset {0} */
    g_assert_cmpuint(range_lock(o, tsn, 0, false), ==, 0);
    eos(o, tsn);
    /* TPER_RESET is type 3, once ProgrammaticResetEnable is on */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_MEDIA);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_DENY);
    /* Global keeps {0}: still unlocked after TPER_RESET */
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 1), ==, FEMU_OPAL_MEDIA);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_genkey(void)
{
    static const uint64_t r1[] = { 100, 50 };
    static const uint64_t glob[] = { 0, 100, 150, NLBAS - 150 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    er.n = 0;
    g_assert_cmpuint(call0(o, tsn, U_KAES(1), M_GENKEY), ==, 0);
    erased(1, r1);
    g_assert_cmpuint(call0(o, tsn, U_KAES(0), M_GENKEY), ==, 0);
    erased(2, glob);
    /* a GenKey for an empty range erases nothing */
    g_assert_cmpuint(call0(o, tsn, U_KAES(2), M_GENKEY), ==, 0);
    g_assert_cmpint(er.n, ==, 0);
    /* not a key row */
    g_assert_cmpuint(call0(o, tsn, U_LOCK(1), M_GENKEY), ==, 0x01);
    eos(o, tsn);
    /* Anybody may not */
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_KAES(1), M_GENKEY), ==, 0x01);
    g_assert_cmpint(er.n, ==, 0);
    eos(o, tsn);
    /* a read-only session changes nothing, even as Admin1 */
    start_write = 0;
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    start_write = 1;
    g_assert_cmpuint(call0(o, tsn, U_KAES(1), M_GENKEY), ==, 0x01);
    g_assert_cmpuint(range_set(o, tsn, 2, 300, 10), ==, 0x01);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_DS, 0, "x", false), ==, 0x01);
    g_assert_cmpuint(revertsp(o, tsn, -1), ==, 0x01);
    g_assert_cmpint(er.n, ==, 0);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_users(void)
{
    static const int rl[] = { 7, -1 };
    static const int wl[] = { 8, -1 };
    static const uint64_t zero[] = { 0 };
    uint64_t u1[] = { U_USER(0) };
    uint64_t adm_u1[] = { U_ADMINS, U_USER(0) };
    uint64_t adm_u2[] = { U_ADMINS, U_USER(1) };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, true), ==, 0);
    /* a disabled user cannot start a session */
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(0), 3, "u1", 0, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_USER(0), "u1", &tsn), ==, 0x01);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_USER(0), 5, NULL, 1, false), ==, 0);
    /* RdLocked of Range1 by User1 alone; AND is not supported */
    g_assert_cmpuint(expr_set(o, tsn, U_ACE_RDLOCKED(1), u1, 1, 1), ==, 0);
    g_assert_cmpuint(expr_set(o, tsn, U_ACE_WRLOCKED(1), adm_u1, 2, 0),
                     ==, 0x0C);
    /* C_PIN_User1 Set takes Admins, or Admins OR User1 only */
    g_assert_cmpuint(expr_set(o, tsn, U_ACE_CPIN_USER(0), adm_u2, 2, 1),
                     ==, 0x0C);
    g_assert_cmpuint(expr_set(o, tsn, U_ACE_CPIN_USER(0), adm_u1, 2, 1),
                     ==, 0);
    /* the ACE reads back as Admin bits joined by OR */
    g_assert_cmpuint(reply_status(get(o, tsn, U_ACE_RDLOCKED(1), 3, 3)),
                     ==, 0);
    eos(o, tsn);

    g_assert_cmpuint(start(o, U_LOCKINGSP, U_USER(0), "u1", &tsn), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_LOCK(1), rl, zero, false), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_LOCK(1), wl, zero, false), ==, 0x01);
    g_assert_cmpuint(lset(o, tsn, U_LOCK(2), rl, zero, false), ==, 0x01);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_MEDIA);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_WRITE, 100, 1), ==, FEMU_OPAL_DENY);
    /* User1 may now change its own PIN, never User2's */
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(0), 3, "u1b", 0, false), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(1), 3, "x", 0, false), ==, 0x01);
    /* users cannot read the ACE table */
    g_assert_cmpuint(reply_status(get(o, tsn, U_ACE_RDLOCKED(1), 3, 3)),
                     ==, 0x01);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_USER(0), "u1b", &tsn), ==, 0);
    eos(o, tsn);
    /* by default, User2 sets its own PIN */
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_USER(1), 5, NULL, 1, false), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(1), 3, "u2", 0, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_USER(1), "u2", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(1), 3, "u2b", 0, false), ==, 0);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_mbr(void)
{
    static const int enable[] = { 1, -1 };
    static const int done[] = { 2, -1 };
    static const uint64_t one[] = { 1 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    uint64_t mbr_lbas = FEMU_OPAL_MBR_SIZE / 4096;
    char b[8];
    int n;

    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 4090, "hello", false), ==, 0);
    femu_opal_mbr_read(o, 4090, b, 5);
    g_assert(!memcmp(b, "hello", 5));
    n = bytes_get(o, tsn, U_T_MBR, 4091, 4093);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(rt[1].len, ==, 3);
    g_assert(!memcmp(rt[1].p, "ell", 3));
    /* an untouched chunk reads as zeros */
    femu_opal_mbr_read(o, 1 << 20, b, 4);
    g_assert_cmpuint(b[0] | b[1] | b[2] | b[3], ==, 0);
    /* past the end, a reply too large: INVALID_PARAMETER */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, FEMU_OPAL_MBR_SIZE - 2, "abc",
                               false), ==, 0x0C);
    g_assert_cmpuint(reply_status(bytes_get(o, tsn, U_T_MBR, 0, 4095)),
                     ==, 0x0C);

    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, enable, one, false), ==, 0);
    g_assert_cmpuint(l0_locking(o) & 0x30, ==, 0x10);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 8), ==, FEMU_OPAL_SHADOW);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_VERIFY, 0, 8), ==,
                    FEMU_OPAL_SHADOW);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_WRITE, 0, 8), ==, FEMU_OPAL_DENY);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, mbr_lbas - 1, 2), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, mbr_lbas, 2), ==,
                    FEMU_OPAL_MEDIA);
    /* outside the shadow, an all read-locked Read returns zeros */
    g_assert_cmpuint(range_lock(o, tsn, 0, true), ==, 0);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, mbr_lbas, 2), ==,
                    FEMU_OPAL_ZEROS);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_VERIFY, mbr_lbas, 2), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpuint(range_lock(o, tsn, 0, false), ==, 0);
    /* Done hides the shadow until the next power cycle (DoneOnReset {0}) */
    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, done, one, false), ==, 0);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 8), ==, FEMU_OPAL_MEDIA);
    eos(o, tsn);
    femu_opal_power_cycle(o);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 8), ==, FEMU_OPAL_SHADOW);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_txn(void)
{
    static const int cols[] = { 3, 4, -1 };
    static const uint64_t vals[] = { 100, 50 };
    static const uint64_t r1[] = { 100, 50 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    char b[4];

    /* an aborted transaction erases nothing and keeps the bytes */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_DS, 0, "abc", false), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_LOCK(1), cols, vals, true), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_DS, 1, "XY", false), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "Z", false), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_KAES(0), M_GENKEY), ==, 0);
    g_assert_cmpint(er.n, ==, 0);
    et(o, tsn, 1);
    g_assert_cmpint(er.n, ==, 0);
    g_assert_cmpuint(reply_status(bytes_get(o, tsn, U_T_DS, 0, 2)), ==, 0);
    g_assert(!memcmp(rt[1].p, "abc", 3));
    femu_opal_mbr_read(o, 0, b, 1);
    g_assert_cmpuint(b[0], ==, 0);
    /* the lock view shows committed state only */
    g_assert_cmpuint(lset(o, tsn, U_LOCK(1), cols, vals, true), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, true), ==, 0);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_MEDIA);
    g_assert_cmpint(er.n, ==, 0);
    /* commit: the erase happens at ET 0 */
    et(o, tsn, 0);
    erased(1, r1);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_DENY);
    /* EOS inside a transaction rolls the bytes back too */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_DS, 0, "q", true), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    bytes_get(o, tsn, U_T_DS, 0, 0);
    g_assert_cmpuint(rt[1].p[0], ==, 'a');
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_revertsp(void)
{
    static const uint64_t r1[] = { 100, 50 };
    static const uint64_t all[] = { 0, NLBAS };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    char b[4];

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "m", false), ==, 0);
    er.n = 0;
    /* Keep with a fully locked Global range fails */
    g_assert_cmpuint(range_lock(o, tsn, 0, true), ==, 0);
    g_assert_cmpuint(revertsp(o, tsn, 1), ==, 0x3F);
    g_assert_cmpuint(range_lock(o, tsn, 0, false), ==, 0);
    /* Keep: only Range1 changes owner and key */
    g_assert_cmpuint(revertsp(o, tsn, 1), ==, 0);
    erased(1, r1);
    g_assert(session_gone(o, tsn));
    femu_opal_mbr_read(o, 0, b, 1);
    g_assert_cmpuint(b[0], ==, 0);
    g_assert_cmpuint(l0_locking(o), ==, 0x09);
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0x3F);

    /* again, without Keep: every LBA */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(revertsp(o, tsn, -1), ==, 0);
    erased(1, all);

    /* Revert of the Locking SP from the Admin SP erases too */
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0);
    g_assert_cmpint(er.n, ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_REVERT), ==, 0);
    erased(1, all);
    /* while inactive, a revert keeps the data */
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_REVERT), ==, 0);
    g_assert_cmpuint(call0(o, tsn, U_ADMINSP, M_REVERT), ==, 0);
    g_assert_cmpint(er.n, ==, 0);
    femu_opal_cleanup(o);
    g_free(o);
}

static void test_s3_tables(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    Tb t = { .n = 0 };
    int n;

    /* Next on the Locking table: Global, then Range1 to Range8 */
    tb_call(&t, U_T_LOCK, M_NEXT);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 9 + 6);
    g_assert_cmpuint(uid_of(&rt[2]), ==, U_LOCK(0));
    g_assert_cmpuint(uid_of(&rt[10]), ==, U_LOCK(8));
    /* GetACL of Set on Range1 */
    n = getacl(o, tsn, U_LOCK(1), M_SET);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 4 + 6);
    g_assert_cmpuint(uid_of(&rt[2]), ==, U_ACE_RANGE_SET);
    g_assert_cmpuint(uid_of(&rt[3]), ==, U_ACE_RDLOCKED(1));
    g_assert_cmpuint(uid_of(&rt[4]), ==, U_ACE_WRLOCKED(1));
    g_assert_cmpuint(uid_of(&rt[5]), ==, U_ACE_ADMINS_CN);
    n = getacl(o, tsn, U_LOCK(0), M_SET);
    g_assert_cmpuint(uid_of(&rt[2]), ==, U_ACE_GLOBAL_SET);
    /* the K_AES Key column and the C_PIN PIN never show */
    n = get(o, tsn, U_KAES(1), 3, 3);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 6);
    n = get(o, tsn, U_LCPIN_USER(0), 3, 3);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 6);
    /* the Admin SP methods do not exist here */
    g_assert_cmpuint(call0(o, tsn, U_LOCKINGSP, M_ACTIVATE), ==, 0x01);
    eos(o, tsn);
    /* Anybody reads the range CommonName only */
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0);
    n = get(o, tsn, U_LOCK(1), 0, 10);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpint(n, ==, 4 + 2 * 4 + 6);
    g_assert_cmpuint(rt[3].val, ==, 0);
    g_assert_cmpuint(rt[7].val, ==, 2);
    g_assert_cmpuint(reply_status(get(o, tsn, U_T_DS, 0, 0)), ==, 0x01);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* the access table on hand-built views (Core Tables 230 and 231) */
static void test_s3_check(void)
{
    FemuOpalView v = { .enabled = true, .mbr_lbas = 10 };

    v.r[1].start = 20;
    v.r[1].len = 10;
    v.r[1].rlocked = true;
    v.r[2].start = 40;
    v.r[2].len = 10;
    v.r[2].wlocked = true;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 15, 10), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_WRITE, 15, 10), ==,
                    FEMU_OPAL_MEDIA);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 40, 10), ==,
                    FEMU_OPAL_MEDIA);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_WRITE, 49, 2), ==,
                    FEMU_OPAL_DENY);
    /* shadow on: a fully read-locked Read outside it reads zeros */
    v.shadow = true;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 20, 10), ==,
                    FEMU_OPAL_ZEROS);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 15, 10), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 9, 2), ==,
                    FEMU_OPAL_DENY);
    /* inside the shadow: Read ignores locks, Verify and Copy do not */
    v.r[0].rlocked = true;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, 0, 4), ==,
                    FEMU_OPAL_SHADOW);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_VERIFY, 0, 4), ==,
                    FEMU_OPAL_DENY);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_COPY_SRC, 0, 4), ==,
                    FEMU_OPAL_DENY);
    v.r[0].rlocked = false;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_VERIFY, 0, 4), ==,
                    FEMU_OPAL_SHADOW);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_COPY_SRC, 0, 4), ==,
                    FEMU_OPAL_SHADOW);
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_WRITE, 0, 4), ==,
                    FEMU_OPAL_DENY);
    /* an inactive Locking SP never blocks */
    v.enabled = false;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_WRITE, 0, 100), ==,
                    FEMU_OPAL_MEDIA);
}

#define U_T_ACE     0x0000000800000000ull
#define U_T_TABLE   0x0000000100000000ull
#define U_T_TMPL    0x0000000300000000ull
#define U_T_METHOD  0x0000000600000000ull
#define U_T_SECRET  0x0000001D00000000ull
#define U_LOCKINFO  0x0000080100000001ull
#define U_ACE_ANYBODY 0x0000000800000001ull
#define U_ACE_SET_BE  0x0000000800038001ull
#define U_ACE_KAES_MODE 0x000000080003BFFFull
#define U_ACE_DS_SET  0x000000080003FC01ull

/* Next on @table with no parameters; returns the row count */
static int next_rows(FemuOpal *o, uint32_t tsn, uint64_t table)
{
    Tb t = { .n = 0 };
    int n;

    tb_call(&t, table, M_NEXT);
    tb_end(&t);
    n = xfer(o, &t, tsn);
    g_assert_cmpuint(reply_status(n), ==, 0);
    return n - 4 - 6;
}

/* the value token of column @col in a Get reply of @n tokens, or NULL */
static const FemuOpalTok *col_of(int n, uint64_t col)
{
    int i;

    for (i = 2; i + 2 < n; i++) {
        if (rt[i].type == FEMU_OPAL_TOK_CTRL && rt[i].val == 0xF2 &&
            rt[i + 1].type == FEMU_OPAL_TOK_UINT && rt[i + 1].val == col) {
            return &rt[i + 2];
        }
    }
    return NULL;
}

static bool tok_str(const FemuOpalTok *k, const char *s)
{
    return k && k->type == FEMU_OPAL_TOK_BYTES && k->len == strlen(s) &&
           !memcmp(k->p, s, k->len);
}

/* only the ACEs of Opal Table 38 take a new BooleanExpr */
static void test_s3_ace_set(void)
{
    static const uint64_t fixed[] = {
        U_ACE_ANYBODY, U_ACE_SET_BE, U_ACE_KAES_MODE, U_ACE_GLOBAL_SET,
        U_ACE_RANGE_SET, U_ACE_ADMINS_CN, 0x0000000800000002ull,
        0x0000000800000003ull, 0x0000000800039001ull,
        0x000000080003A000ull, 0x000000080003A001ull,
        0x000000080003F800ull,
    };
    uint64_t adm[] = { U_ADMINS };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    int i;
    int n;

    for (i = 0; i < ARRAY_SIZE(fixed); i++) {
        g_assert_cmpuint(expr_set(o, tsn, fixed[i], adm, 1, 1), ==, 0x01);
        g_assert_cmpint(getacl(o, tsn, fixed[i], M_SET), >, 0);
        g_assert_cmpuint(reply_status(getacl(o, tsn, fixed[i], M_SET)),
                         ==, 0x01);
    }
    g_assert_cmpuint(expr_set(o, tsn, U_ACE_DS_SET, adm, 1, 1), ==, 0);
    g_assert_cmpuint(expr_set(o, tsn, 0x000000080003B801ull, adm, 1, 1),
                     ==, 0);
    g_assert_cmpuint(expr_set(o, tsn, 0x000000080003D001ull, adm, 1, 1),
                     ==, 0);
    n = getacl(o, tsn, U_ACE_DS_SET, M_SET);
    g_assert_cmpuint(uid_of(&rt[2]), ==, U_ACE_SET_BE);
    g_assert_cmpuint(reply_status(n), ==, 0);
    /* every ACE has its Name */
    n = get(o, tsn, 0x000000080003D001ull, 1, 1);
    g_assert(tok_str(col_of(n, 1),
                     "ACE_Locking_Range1_Get_RangeStartToActiveKey"));
    n = get(o, tsn, 0x000000080003B800ull, 1, 1);
    g_assert(tok_str(col_of(n, 1), "ACE_K_AES_256_GlobalRange_GenKey"));
    n = get(o, tsn, U_ACE_DS_SET, 1, 1);
    g_assert(tok_str(col_of(n, 1), "ACE_DataStore_Set_All"));
    /* Next walks all 69 ACEs */
    g_assert_cmpint(next_rows(o, tsn, U_T_ACE), ==, FEMU_OPAL_ACE_COUNT);
    g_assert_cmpuint(uid_of(&rt[2 + FEMU_OPAL_ACE_COUNT - 1]), ==,
                     0x000000080003FC01ull);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* BooleanExpr reads back in full, postfix OR included */
static void test_s3_expr_encoding(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    int n;

    /* default of C_PIN_User1_Set_PIN: Admins OR User1 */
    n = get(o, tsn, U_ACE_CPIN_USER(0), 3, 3);
    g_assert_cmpuint(reply_status(n), ==, 0);
    /* SL SL SN 3 SL {SN half uid EN} x2 {SN half 1 EN} EL EN EL EL */
    g_assert_cmpint(n, ==, 4 + 1 + 12 + 1 + 1 + 2 + 6);
    g_assert_cmpuint(rt[3].val, ==, 3);
    g_assert_cmpuint(rt[6].len, ==, 4);
    g_assert(!memcmp(rt[6].p, "\x00\x00\x0c\x05", 4));
    g_assert_cmpuint(uid_of(&rt[7]), ==, U_ADMINS);
    g_assert(!memcmp(rt[10].p, "\x00\x00\x0c\x05", 4));
    g_assert_cmpuint(uid_of(&rt[11]), ==, U_USER(0));
    g_assert(!memcmp(rt[14].p, "\x00\x00\x04\x0e", 4));
    g_assert_cmpuint(rt[15].val, ==, 1);
    g_assert_cmpuint(rt[16].val, ==, 0xF3);
    g_assert_cmpuint(rt[17].val, ==, 0xF1);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* the discovery tables (Opal Tables 35 to 37, 42) and fixed columns */
static void test_s3_discovery(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    const FemuOpalTok *k;
    int n;

    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0x07);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_LOCKINGSP, 0, NULL, &tsn), ==, 0);
    g_assert_cmpint(next_rows(o, tsn, U_T_TABLE), ==, 15);
    g_assert_cmpint(next_rows(o, tsn, U_T_TMPL), ==, 2);
    g_assert_cmpint(next_rows(o, tsn, U_T_METHOD), ==, 8);
    g_assert_cmpint(next_rows(o, tsn, U_T_SECRET), ==, 1);
    /* GetACL names the same rights */
    g_assert_cmpuint(reply_status(getacl(o, tsn, U_T_TABLE, M_NEXT)), ==, 0);
    g_assert_cmpuint(uid_of(&rt[2]), ==, U_ACE_ANYBODY);
    g_assert_cmpuint(reply_status(getacl(o, tsn, U_T_METHOD, M_NEXT)), ==,
                     0);
    g_assert_cmpuint(reply_status(getacl(o, tsn, 0x0000000100000804ull,
                                         M_GET)), ==, 0);
    /* the MBR descriptor: a byte table of 128 MiB, granularity 1 */
    n = get(o, tsn, 0x0000000100000804ull, 0, 14);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert(tok_str(col_of(n, 1), "MBR"));
    g_assert_cmpuint(col_of(n, 4)->val, ==, 2);
    g_assert_cmpuint(col_of(n, 7)->val, ==, FEMU_OPAL_MBR_SIZE);
    g_assert_cmpuint(col_of(n, 13)->val, ==, 1);
    g_assert_cmpuint(col_of(n, 14)->val, ==, 1);
    n = get(o, tsn, 0x0000000100001001ull, 7, 7);
    g_assert_cmpuint(col_of(n, 7)->val, ==, FEMU_OPAL_DS_SIZE);
    n = get(o, tsn, 0x0000000100000802ull, 4, 13);
    g_assert_cmpuint(col_of(n, 4)->val, ==, 1);
    g_assert_cmpuint(col_of(n, 13)->val, ==, 0);
    g_assert_null(col_of(n, 7));
    n = get(o, tsn, 0x0000000300000002ull, 1, 2);
    g_assert_cmpuint(uid_of(col_of(n, 1)), ==, 0x0000020400000006ull);
    g_assert(tok_str(col_of(n, 2), "Locking"));
    n = get(o, tsn, 0x0000000600000011ull, 1, 1);
    g_assert(tok_str(col_of(n, 1), "RevertSP"));
    n = get(o, tsn, 0x0000001D0000001Eull, 1, 2);
    g_assert_cmpuint(uid_of(col_of(n, 1)), ==, 0x0000000100000806ull);
    g_assert_cmpuint(col_of(n, 2)->val, ==, 3);
    /* LockingInfo, every column */
    n = get(o, tsn, U_LOCKINFO, 0, 10);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(col_of(n, 2)->val, ==, 1);
    g_assert_cmpuint(col_of(n, 3)->val, ==, 1);
    g_assert_cmpuint(col_of(n, 4)->val, ==, 8);
    g_assert_cmpuint(col_of(n, 5)->val, ==, 0);
    g_assert_cmpuint(col_of(n, 7)->val, ==, 0);
    g_assert_cmpuint(col_of(n, 8)->val, ==, 4096);
    g_assert_cmpuint(col_of(n, 9)->val, ==, 1);
    g_assert_cmpuint(col_of(n, 10)->val, ==, 0);
    eos(o, tsn);

    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    /* Authority columns 6 to 8, 11 and 12 */
    n = get(o, tsn, U_USER(0), 6, 12);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert_cmpuint(col_of(n, 6)->val, ==, 0);
    g_assert_cmpuint(col_of(n, 7)->val, ==, 0);
    g_assert_cmpuint(col_of(n, 8)->val, ==, 0);
    g_assert_cmpuint(uid_of(col_of(n, 11)), ==, 0);
    g_assert_cmpuint(uid_of(col_of(n, 12)), ==, 0);
    /* C_PIN: UID, CharSet, TryLimit, Tries, Persistence (Table 39) */
    n = get(o, tsn, U_LCPIN_USER(0), 0, 7);
    g_assert_null(col_of(n, 1));
    g_assert_null(col_of(n, 3));
    g_assert_cmpuint(uid_of(col_of(n, 4)), ==, 0);
    g_assert_cmpuint(col_of(n, 5)->val, ==, 0);
    g_assert_cmpuint(col_of(n, 6)->val, ==, 0);
    k = col_of(n, 7);
    g_assert_nonnull(k);
    g_assert_cmpuint(k->val, ==, 0);
    /* K_AES_256 Mode: Media Encryption */
    n = get(o, tsn, U_KAES(1), 4, 4);
    g_assert_cmpuint(col_of(n, 4)->val, ==, 23);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* the MBR reader: bounds, committed bytes, chunk edges */
static void test_s3_mbr_reader(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    char b[8];
    int n;

    /* across a 64 KiB chunk edge */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, FEMU_OPAL_CHUNK - 2,
                               "edge", false), ==, 0);
    g_assert(femu_opal_mbr_read(o, FEMU_OPAL_CHUNK - 2, b, 4));
    g_assert(!memcmp(b, "edge", 4));
    n = bytes_get(o, tsn, U_T_MBR, FEMU_OPAL_CHUNK - 2, FEMU_OPAL_CHUNK + 1);
    g_assert_cmpuint(reply_status(n), ==, 0);
    g_assert(!memcmp(rt[1].p, "edge", 4));
    /* the DataStore is not past the MBR end */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_DS, 0, "secret", false), ==, 0);
    memset(b, 'x', sizeof(b));
    g_assert(!femu_opal_mbr_read(o, FEMU_OPAL_MBR_SIZE, b, 6));
    g_assert(!femu_opal_mbr_read(o, FEMU_OPAL_MBR_SIZE - 2, b, 4));
    g_assert(!femu_opal_mbr_read(o, UINT64_MAX, b, 1));
    g_assert_cmpuint(b[0], ==, 'x');
    g_assert(femu_opal_mbr_read(o, FEMU_OPAL_MBR_SIZE - 2, b, 2));
    g_assert(femu_opal_mbr_read(o, FEMU_OPAL_MBR_SIZE, b, 0));
    /* a transaction's MBR writes stay out of the shadow until ET 0 */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "old", false), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "new", true), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 1, "EW", false), ==, 0);
    g_assert(femu_opal_mbr_read(o, 0, b, 3));
    g_assert(!memcmp(b, "old", 3));
    /* in-session Get sees the open transaction */
    bytes_get(o, tsn, U_T_MBR, 0, 2);
    g_assert(!memcmp(rt[1].p, "nEW", 3));
    et(o, tsn, 1);
    g_assert(femu_opal_mbr_read(o, 0, b, 3));
    g_assert(!memcmp(b, "old", 3));
    /* commit: kept after the session ends */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "new", true), ==, 0);
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 1, "EW", false), ==, 0);
    et(o, tsn, 0);
    eos(o, tsn);
    g_assert(femu_opal_mbr_read(o, 0, b, 3));
    g_assert(!memcmp(b, "nEW", 3));
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    bytes_get(o, tsn, U_T_MBR, 0, 2);
    g_assert(!memcmp(rt[1].p, "nEW", 3));
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* the undo copies of one transaction have a limit */
static void test_s3_undo_budget(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    char b[2];
    int i;

    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, 0, "a", true), ==, 0);
    /* the same chunk again costs nothing */
    for (i = 0; i < 300; i++) {
        g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR, i, "b", false), ==, 0);
    }
    for (i = 1; i < FEMU_OPAL_UNDO_CHUNKS; i++) {
        g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR,
                                   (uint64_t)i * FEMU_OPAL_CHUNK, "c", false),
                         ==, 0);
    }
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR,
                               (uint64_t)i * FEMU_OPAL_CHUNK, "d", false),
                     ==, 0x3F);
    et(o, tsn, 1);
    g_assert(femu_opal_mbr_read(o, 0, b, 1));
    g_assert_cmpuint(b[0], ==, 0);
    g_assert(femu_opal_mbr_read(o, (uint64_t)5 * FEMU_OPAL_CHUNK, b, 1));
    g_assert_cmpuint(b[0], ==, 0);
    /* after the transaction the budget is free again */
    g_assert_cmpuint(bytes_set(o, tsn, U_T_MBR,
                               (uint64_t)i * FEMU_OPAL_CHUNK, "d", true),
                     ==, 0);
    et(o, tsn, 0);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* resets relock writes too, and DoneOnReset {0, 3} follows TPER_RESET */
static void test_s3_resets(void)
{
    static const int enable[] = { 1, 2, -1 };
    static const uint64_t on[] = { 1, 1 };
    static const int lor03[] = { 0, 3, -1 };
    static const int lor0[] = { 0, -1 };
    static const int unlock[] = { 7, 8, -1 };
    static const uint64_t off[] = { 0, 0 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    uint8_t z[8] = { 0 };
    FemuOpalView v;

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, false), ==, 0);
    g_assert_cmpuint(resets_set(o, tsn, U_MBRCTL, 3, lor03), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, enable, on, false), ==, 0);
    g_assert_cmpuint(l0_locking(o) & 0x30, ==, 0x30);
    eos(o, tsn);
    femu_opal_power_cycle(o);
    femu_opal_view(o, &v);
    g_assert(v.r[1].wlocked && v.r[1].rlocked);
    g_assert_cmpuint(l0_locking(o) & 0x30, ==, 0x10);
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_LOCK(1), unlock, off, false), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, enable, on, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpuint(start(o, U_ADMINSP, U_SID, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_TPERINFO, 8, NULL, 1, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 1), ==, FEMU_OPAL_MEDIA);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_GOOD);
    /* Done cleared: the shadow is back; Range1 keeps {0}: still open */
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 1), ==, FEMU_OPAL_SHADOW);
    femu_opal_view(o, &v);
    g_assert(!v.r[1].wlocked && !v.r[1].rlocked);
    /* DoneOnReset {0}: TPER_RESET keeps Done */
    g_assert_cmpuint(start(o, U_LOCKINGSP, U_LSP_ADM1, "MSID-1", &tsn), ==, 0);
    g_assert_cmpuint(resets_set(o, tsn, U_MBRCTL, 3, lor0), ==, 0);
    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, enable, on, false), ==, 0);
    eos(o, tsn);
    g_assert_cmpint(femu_opal_send(o, 2, 4, z, 8), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 0, 1), ==, FEMU_OPAL_MEDIA);
    femu_opal_cleanup(o);
    g_free(o);
}

/* edge cases of Level 0, GenKey parameters, key reuse, wide extents */
static void test_s3_edges(void)
{
    static const int done[] = { 2, -1 };
    static const uint64_t one[] = { 1 };
    static const uint64_t r1[] = { 100, 50 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    FemuOpalView v = { .enabled = true };
    Tb t = { .n = 0 };

    /* Done without Enable: MBR Done stays 0 in Level 0 */
    g_assert_cmpuint(lset(o, tsn, U_MBRCTL, done, one, false), ==, 0);
    g_assert_cmpuint(l0_locking(o), ==, 0x0B);
    /* GenKey takes no parameters on a K_AES row */
    tb_call(&t, U_KAES(0), M_GENKEY);
    tb_c(&t, 0xF2);
    tb_u(&t, 0);
    tb_u(&t, 65537);
    tb_c(&t, 0xF3);
    tb_end(&t);
    g_assert_cmpuint(reply_status(xfer(o, &t, tsn)), ==, 0x0C);
    g_assert_cmpint(er.n, ==, 0);
    /* a new owner erases even if the key numbers matched */
    o->sp.range[1].key = o->sp.range[0].key;
    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    erased(1, r1);
    eos(o, tsn);
    /* an extent that wraps the LBA space is denied */
    v.r[1].start = UINT64_MAX - 10;
    v.r[1].len = 10;
    v.r[1].rlocked = true;
    g_assert_cmpint(femu_opal_access(&v, FEMU_OPAL_OP_READ, UINT64_MAX - 5,
                                    10), ==, FEMU_OPAL_DENY);
    femu_opal_cleanup(o);
    g_free(o);
}

/* a Format that shrinks the LBA count keeps far ranges; other Sets work */
static void test_s3_far_ranges(void)
{
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);

    g_assert_cmpuint(range_set(o, tsn, 1, 800, 100), ==, 0);
    g_assert_cmpuint(range_set(o, tsn, 2, 900, 100), ==, 0);
    o->cfg.nlbas = 500;
    g_assert_cmpuint(range_lock(o, tsn, 1, true), ==, 0);
    g_assert_cmpuint(set(o, tsn, U_LCPIN_USER(0), 3, "x", 0, false), ==, 0);
    /* a moved range must fit the new size and miss the far ones */
    g_assert_cmpuint(range_set(o, tsn, 1, 800, 50), ==, 0x0C);
    g_assert_cmpuint(range_set(o, tsn, 3, 450, 100), ==, 0x0C);
    g_assert_cmpuint(range_set(o, tsn, 1, 400, 100), ==, 0);
    g_assert_cmpuint(range_set(o, tsn, 3, 0, 100), ==, 0);
    eos(o, tsn);
    femu_opal_cleanup(o);
    g_free(o);
}

/* a Hardware Reset keeps locks and Tries; Block SID clears on request */
static void test_s3_hw_reset(void)
{
    static const int lor03[] = { 0, 3, -1 };
    uint32_t tsn;
    FemuOpal *o = s3_init(&tsn);
    FemuOpal *b = g_new(FemuOpal, 1);
    uint8_t hw[2] = { 1, 0 };
    uint8_t keep[2] = { 0, 0 };

    g_assert_cmpuint(range_set(o, tsn, 1, 100, 50), ==, 0);
    g_assert_cmpuint(range_lock(o, tsn, 1, false), ==, 0);
    g_assert_cmpuint(resets_set(o, tsn, U_LOCK(1), 9, lor03), ==, 0);
    femu_opal_hw_reset(o);
    g_assert(session_gone(o, tsn));
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_MEDIA);
    o->tries[FEMU_OPAL_AU_LSP_ADMIN1] = 2;
    femu_opal_hw_reset(o);
    g_assert_cmpuint(o->tries[FEMU_OPAL_AU_LSP_ADMIN1], ==, 2);
    femu_opal_power_cycle(o);
    g_assert_cmpuint(o->tries[FEMU_OPAL_AU_LSP_ADMIN1], ==, 0);
    g_assert_cmpint(check(o, FEMU_OPAL_OP_READ, 100, 1), ==, FEMU_OPAL_DENY);
    femu_opal_cleanup(o);
    g_free(o);

    /* Block SID needs the MSID PIN in C_PIN_SID */
    s2_init(b);
    g_assert_cmpint(femu_opal_send(b, 2, 5, keep, 2), ==, FEMU_OPAL_IF_GOOD);
    femu_opal_hw_reset(b);
    g_assert_cmpuint(l0_block_sid(b, 4), ==, 0x02);
    femu_opal_power_cycle(b);
    g_assert_cmpuint(l0_block_sid(b, 4), ==, 0);
    g_assert_cmpint(femu_opal_send(b, 2, 5, hw, 2), ==, FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(l0_block_sid(b, 4), ==, 0x02);
    femu_opal_hw_reset(b);
    g_assert_cmpuint(l0_block_sid(b, 4), ==, 0);
    femu_opal_cleanup(b);
    g_free(b);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/opal/decode-fixtures", test_decode_fixtures);
    g_test_add_func("/femu/opal/decode-errors", test_decode_errors);
    g_test_add_func("/femu/opal/decode-wide", test_decode_wide);
    g_test_add_func("/femu/opal/properties-abort", test_properties_abort);
    g_test_add_func("/femu/opal/properties-count", test_properties_count);
    g_test_add_func("/femu/opal/encode", test_encode);
    g_test_add_func("/femu/opal/level0", test_level0);
    g_test_add_func("/femu/opal/protocol-list", test_protocol_list);
    g_test_add_func("/femu/opal/comid-state", test_comid_state);
    g_test_add_func("/femu/opal/properties-host", test_properties_host);
    g_test_add_func("/femu/opal/bad-frames", test_bad_frames);
    g_test_add_func("/femu/opal/stack-reset", test_stack_reset);
    g_test_add_func("/femu/opal/s2-ownership", test_s2_ownership);
    g_test_add_func("/femu/opal/s2-sessions", test_s2_sessions);
    g_test_add_func("/femu/opal/s2-activate-revert",
                    test_s2_activate_revert);
    g_test_add_func("/femu/opal/s2-psid", test_s2_psid);
    g_test_add_func("/femu/opal/s2-transactions", test_s2_transactions);
    g_test_add_func("/femu/opal/s2-block-sid", test_s2_block_sid);
    g_test_add_func("/femu/opal/s2-tper-reset", test_s2_tper_reset);
    g_test_add_func("/femu/opal/s2-methods", test_s2_methods);
    g_test_add_func("/femu/opal/s2-txn-isolation", test_s2_txn_isolation);
    g_test_add_func("/femu/opal/s2-aborts", test_s2_aborts);
    g_test_add_func("/femu/opal/s2-authenticate", test_s2_authenticate);
    g_test_add_func("/femu/opal/s2-tables", test_s2_tables);
    g_test_add_func("/femu/opal/s2-getacl", test_s2_getacl);
    g_test_add_func("/femu/opal/s2-interface", test_s2_interface);
    g_test_add_func("/femu/opal/s3-ranges", test_s3_ranges);
    g_test_add_func("/femu/opal/s3-locks", test_s3_locks);
    g_test_add_func("/femu/opal/s3-genkey", test_s3_genkey);
    g_test_add_func("/femu/opal/s3-users", test_s3_users);
    g_test_add_func("/femu/opal/s3-mbr", test_s3_mbr);
    g_test_add_func("/femu/opal/s3-txn", test_s3_txn);
    g_test_add_func("/femu/opal/s3-revertsp", test_s3_revertsp);
    g_test_add_func("/femu/opal/s3-tables", test_s3_tables);
    g_test_add_func("/femu/opal/s3-check", test_s3_check);
    g_test_add_func("/femu/opal/s3-ace-set", test_s3_ace_set);
    g_test_add_func("/femu/opal/s3-expr-encoding", test_s3_expr_encoding);
    g_test_add_func("/femu/opal/s3-discovery", test_s3_discovery);
    g_test_add_func("/femu/opal/s3-mbr-reader", test_s3_mbr_reader);
    g_test_add_func("/femu/opal/s3-undo-budget", test_s3_undo_budget);
    g_test_add_func("/femu/opal/s3-resets", test_s3_resets);
    g_test_add_func("/femu/opal/s3-edges", test_s3_edges);
    g_test_add_func("/femu/opal/s3-far-ranges", test_s3_far_ranges);
    g_test_add_func("/femu/opal/s3-hw-reset", test_s3_hw_reset);
    return g_test_run();
}
