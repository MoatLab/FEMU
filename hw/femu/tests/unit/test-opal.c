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
    g_assert_cmpuint(b[68], ==, 0x08);          /* not Locking Supported */
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

/* StartSession to @sp as @auth (0: Anybody); sets *tsn, returns status */
static uint64_t start(FemuOpal *o, uint64_t sp, uint64_t auth,
                      const char *pin, uint32_t *tsn)
{
    Tb t = { .n = 0 };
    int n;

    tb_call(&t, U_SMUID, U_START);
    tb_u(&t, HSN);
    tb_uid(&t, sp);
    tb_u(&t, 1);
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
    return g_test_run();
}
