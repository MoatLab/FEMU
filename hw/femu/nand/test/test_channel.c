/* Host unit tests for the NAND media timing model's channel stage.
 *
 * bbssd hardcodes channel_mode = NAND_CH_OFF (ftl-media.c:129), so pg_xfer_lat is
 * copied into the config and never read. Before enabling NAND_CH_STAGED we need
 * to know (a) that OFF is unchanged, and (b) that STAGED does what the analytical
 * channel model assumed. Neither needs QEMU, a guest, or KVM: nand_media_op() is
 * pure timing arithmetic over a caller-supplied timeline.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "nand-media.h"

#define QLC 4
static const int64_t QLC_RD[4] = {47900, 76200, 134600, 228100};  /* measured */
static const int64_t XFER = 52433;      /* QLC_CHNL_PAGE_TRANSFER_LATENCY_NS */
#define MAXCH 8
#define MAXLUN 16

typedef struct { uint64_t ch[MAXCH]; uint64_t lun[MAXCH][MAXLUN]; uint64_t pl[MAXCH][MAXLUN]; } State;
static State ST;
static uint64_t *t_ch(void *o, uint32_t c)              { (void)o; return &ST.ch[c]; }
static uint64_t *t_lun(void *o, const NandLoc *l)       { (void)o; return &ST.lun[l->ch][l->lun]; }
static uint64_t *t_pl(void *o, const NandLoc *l)        { (void)o; return &ST.pl[l->ch][l->lun]; }
static const NandTimelineOps OPS = { .ch_avail=t_ch, .lun_avail=t_lun, .plane_avail=t_pl };

static void setup(NandMedia *m, uint32_t nch, uint32_t luns, NandChannelMode mode, bool bus)
{
    NandMediaConfig c;
    memset(&c, 0, sizeof c);
    memset(&ST, 0, sizeof ST);
    c.nchs = nch; c.luns_per_ch = luns; c.planes_per_lun = 1;
    for (int p = 0; p < 4; p++) c.timing.rd_table_ns[QLC][p] = QLC_RD[p];
    c.timing.wr_table_ns[QLC][0] = 1000000;
    c.timing.er_table_ns[QLC] = 3000000;
    if (bus) c.timing.page_xfer_ns = XFER;      /* cmd_addr / status left 0 */
    c.policy.use_flat_timing = false;
    c.policy.array_gate = NAND_GATE_LUN_ONLY;
    c.policy.channel_mode = mode;
    c.timeline = &OPS; c.timeline_opaque = NULL;
    nand_media_init(m, &c);
}

static uint64_t rd(NandMedia *m, uint32_t ch, uint32_t lun, int ptype, uint64_t at)
{
    NandLoc l; memset(&l, 0, sizeof l);
    l.ch = ch; l.lun = lun; l.flash_type = QLC; l.page_type = ptype;
    return nand_media_op(m, &l, NAND_MEDIA_READ, at).done_ns;
}

static int fails;
static void ck(int ok, const char *what, const char *detail)
{
    printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", what,
           detail && *detail ? " — " : "", detail ? detail : "");
    if (!ok) fails++;
}

/* ---- 1. OFF must be untouched, and STAGED with a zero bus must equal it ---- */
static void t_compat(void)
{
    printf("[1] 하위호환: OFF, 그리고 bus=0 인 STAGED\n");
    uint64_t off[64], staged0[64];
    NandMedia m;
    setup(&m, 1, 4, NAND_CH_OFF, false);
    for (int i = 0; i < 64; i++) off[i] = rd(&m, 0, i % 4, i % 4, 0);
    setup(&m, 1, 4, NAND_CH_STAGED, false);
    for (int i = 0; i < 64; i++) staged0[i] = rd(&m, 0, i % 4, i % 4, 0);
    /* Documents the opposite of what one would hope: enabling the channel stage
     * changes timing even with every bus phase at zero, because the channel
     * timeline is advanced to each op's data-out and the next command is clamped
     * to it. This is why a channel_model option has to default to off. */
    ck(memcmp(off, staged0, sizeof off) != 0,
       "STAGED 는 bus=0 이어도 OFF 와 다름",
       "channel_model 옵션은 반드시 off 를 기본값으로 해야 함");

    /* OFF must ignore the bus entirely, even when pg_xfer_lat is set */
    uint64_t offbus[64];
    setup(&m, 1, 4, NAND_CH_OFF, true);
    for (int i = 0; i < 64; i++) offbus[i] = rd(&m, 0, i % 4, i % 4, 0);
    ck(!memcmp(off, offbus, sizeof off), "OFF 는 pg_xfer_lat 를 무시",
       "오늘의 동작 — 값을 줘도 타이밍에 반영 안 됨");
}

/* ---- 2. one LUN: array read then data-out, serialised ---- */
static void t_single(void)
{
    printf("[2] LUN 1개: array read 후 data-out 직렬화\n");
    NandMedia m; char b[160];
    setup(&m, 1, 1, NAND_CH_STAGED, true);
    uint64_t d = rd(&m, 0, 0, 0, 0);
    snprintf(b, sizeof b, "관측 %.1f us = array %.1f + xfer %.1f",
             d/1000.0, QLC_RD[0]/1000.0, XFER/1000.0);
    ck(d == (uint64_t)(QLC_RD[0] + XFER), "1회 읽기 = array + xfer", b);

    setup(&m, 1, 1, NAND_CH_STAGED, true);
    uint64_t a = rd(&m, 0, 0, 0, 0), c = rd(&m, 0, 0, 0, 0);
    snprintf(b, sizeof b, "1번째 %.1f us, 2번째 %.1f us", a/1000.0, c/1000.0);
    ck(c >= a + QLC_RD[0], "같은 LUN 연속 읽기는 array 시간만큼 직렬화", b);
}

/* ---- 3. two LUNs on one channel: sensing overlaps, data-out does not ---- */
static void t_overlap(void)
{
    printf("[3] 한 채널의 LUN 2개: sensing 겹침, data-out 직렬화\n");
    NandMedia m; char b[160];
    setup(&m, 1, 2, NAND_CH_STAGED, true);
    uint64_t a = rd(&m, 0, 0, 3, 0);   /* slow page on LUN0 */
    uint64_t c = rd(&m, 0, 1, 3, 0);   /* slow page on LUN1, same instant */
    snprintf(b, sizeof b, "LUN0 %.1f us, LUN1 %.1f us (직렬이면 %.1f)",
             a/1000.0, c/1000.0, (QLC_RD[3]*2 + XFER*2)/1000.0);
    /* Physical NAND would overlap here. This model does not: reservations are made
     * in submission order, so LUN1's command waits for LUN0's data-out. */
    ck(c == (uint64_t)(QLC_RD[3] * 2 + XFER * 2),
       "두 LUN 이 완전히 직렬화됨 (실제 NAND 와 다름)", b);
    snprintf(b, sizeof b, "두 완료 간격 %.1f us, xfer %.1f us", (c-a)/1000.0, XFER/1000.0);
    ck(c - a >= (uint64_t)XFER, "data-out 은 채널에서 직렬화", b);
}

/* ---- 4. saturation: does the channel erase the page-type advantage? ---- */
static void t_saturation(void)
{
    printf("[4] 포화: LUN/채널 수에 따라 page mapping 이득이 남는가\n");
    /* traffic shares by plane index, 2-tier unified-lru @1.8GB */
    const double w[4] = {0.381, 0.381, 0.119, 0.119};
    const int N = 4000;
    /* The analytical channel model predicted 1.346 / 1.161 / 1.000 / 1.000 as LUNs
     * per channel grow, assuming extra LUNs overlap sensing with another LUN's
     * data burst. This model never overlaps them, so the gain is flat at
     * (mean_array + xfer) / (aware_array + xfer). */
    const double pred[] = {1.219, 1.219, 1.219, 1.219};
    printf("      %-8s %10s %10s %8s   %s\n", "LUN/ch", "oblivious", "aware", "gain", "모델 예상");
    int pi = 0;
    for (uint32_t luns = 1; luns <= 8; luns *= 2, pi++) {
        uint64_t mk[2];
        for (int arm = 0; arm < 2; arm++) {
            NandMedia m; setup(&m, 1, luns, NAND_CH_STAGED, true);
            uint64_t last = 0; int k = 0;
            for (int i = 0; i < N; i++) {
                /* pick a plane index by traffic share */
                double u = (double)(i % 1000) / 1000.0, acc = 0; int plane = 3;
                for (int j = 0; j < 4; j++) { acc += w[j]; if (u < acc) { plane = j; break; } }
                /* oblivious: traffic spread evenly over the four page classes.
                   aware: plane index maps one-to-one onto page class. */
                int ptype = arm == 0 ? (k++ % 4) : plane;
                uint64_t d = rd(&m, 0, i % luns, ptype, 0);
                if (d > last) last = d;
            }
            mk[arm] = last;
        }
        double gain = (double)mk[0] / (double)mk[1];
        char note[64];
        snprintf(note, sizeof note, "%.3fx", pred[pi]);
        printf("      %-8u %9.2fms %9.2fms %7.3fx   %s\n",
               luns, mk[0]/1e6, mk[1]/1e6, gain, note);
        if (fabs(gain - pred[pi]) > 0.05) {
            printf("        ^ 예측에서 벗어남\n"); fails++;
        }
    }
}

int main(void)
{
    printf("NAND media 채널 스테이지 단위 테스트 (QEMU/게스트/KVM 불필요)\n");
    printf("QLC read %.1f/%.1f/%.1f/%.1f us, channel page xfer %.2f us\n\n",
           QLC_RD[0]/1000.0, QLC_RD[1]/1000.0, QLC_RD[2]/1000.0, QLC_RD[3]/1000.0, XFER/1000.0);
    t_compat(); printf("\n");
    t_single(); printf("\n");
    t_overlap(); printf("\n");
    t_saturation(); printf("\n");
    printf(fails ? "실패 %d 건\n" : "전부 통과\n", fails);
    return fails ? 1 : 0;
}
