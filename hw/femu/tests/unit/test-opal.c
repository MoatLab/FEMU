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
        { 148, 0x0404, 0x20, 0x20 },
    };
    int i;

    femu_opal_init(o, &cfg);
    g_assert_cmpint(femu_opal_recv(o, 1, 1, b, sizeof(b)), ==,
                    FEMU_OPAL_IF_GOOD);
    g_assert_cmpuint(be32(b), ==, 184 - 4);
    g_assert_cmpuint(be32(b + 4), ==, 1);
    for (i = 0; i < ARRAY_SIZE(d); i++) {
        g_assert_cmpuint(be16(b + d[i].off), ==, d[i].code);
        g_assert_cmpuint(b[d[i].off + 2], ==, d[i].ver);
        g_assert_cmpuint(b[d[i].off + 3], ==, d[i].len);
    }
    g_assert_cmpuint(b[52], ==, 0x11);          /* Sync, Streaming */
    g_assert_cmpuint(b[68], ==, 0x08);          /* not Locking Supported */
    g_assert_cmpuint(be32(b + 92), ==, 4096);   /* LogicalBlockSize */
    g_assert_cmpuint(b[116], ==, 0x20);         /* SIIS 1.20 */
    g_assert_cmpuint(be16(b + 132), ==, FEMU_OPAL_COMID);
    g_assert_cmpuint(be16(b + 134), ==, 1);
    g_assert_cmpuint(be16(b + 137), ==, 4);
    g_assert_cmpuint(be16(b + 139), ==, 8);
    g_assert_cmpuint(b[154], ==, 0);            /* no erase in S1 */
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
    return g_test_run();
}
