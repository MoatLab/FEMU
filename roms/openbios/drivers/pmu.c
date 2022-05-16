/*
 * Device driver for the via-pmu on Apple Powermacs.
 *
 * The VIA (versatile interface adapter) interfaces to the PMU,
 * a 6805 microprocessor core whose primary function is to control
 * battery charging and system power on the PowerBook 3400 and 2400.
 * The PMU also controls the ADB (Apple Desktop Bus) which connects
 * to the keyboard and mouse, as well as the non-volatile RAM
 * and the RTC (real time clock) chip.
 *
 * Copyright (C) 1998 Paul Mackerras and Fabio Riccardi.
 * Copyright (C) 2001-2002 Benjamin Herrenschmidt
 * Copyright (C) 2006-2007 Johannes Berg
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "drivers/drivers.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"

#include "macio.h"
#include "pmu.h"

#undef DEBUG_PMU
#ifdef DEBUG_PMU
#define PMU_DPRINTF(fmt, args...) \
	do { printk("PMU - %s: " fmt, __func__ , ##args); } while (0)
#else
#define PMU_DPRINTF(fmt, args...) do { } while (0)
#endif

#define IO_PMU_OFFSET	0x00016000
#define IO_PMU_SIZE	0x00002000

/* VIA registers - spaced 0x200 bytes apart */
#define RS              0x200           /* skip between registers */
#define B               0               /* B-side data */
#define A               RS              /* A-side data */
#define DIRB            (2*RS)          /* B-side direction (1=output) */
#define DIRA            (3*RS)          /* A-side direction (1=output) */
#define T1CL            (4*RS)          /* Timer 1 ctr/latch (low 8 bits) */
#define T1CH            (5*RS)          /* Timer 1 counter (high 8 bits) */
#define T1LL            (6*RS)          /* Timer 1 latch (low 8 bits) */
#define T1LH            (7*RS)          /* Timer 1 latch (high 8 bits) */
#define T2CL            (8*RS)          /* Timer 2 ctr/latch (low 8 bits) */
#define T2CH            (9*RS)          /* Timer 2 counter (high 8 bits) */
#define SR              (10*RS)         /* Shift register */
#define ACR             (11*RS)         /* Auxiliary control register */
#define PCR             (12*RS)         /* Peripheral control register */
#define IFR             (13*RS)         /* Interrupt flag register */
#define IER             (14*RS)         /* Interrupt enable register */
#define ANH             (15*RS)         /* A-side data, no handshake */

/* Bits in B data register: all active low */
#define TACK		0x08		/* Transfer request (input) */
#define TREQ		0x10		/* Transfer acknowledge (output) */

/* Bits in ACR */
#define SR_CTRL         0x1c            /* Shift register control bits */
#define SR_EXT          0x0c            /* Shift on external clock */
#define SR_OUT          0x10            /* Shift out if 1 */

/* Bits in IFR and IER */
#define IER_SET         0x80            /* set bits in IER */
#define IER_CLR         0               /* clear bits in IER */
#define SR_INT          0x04            /* Shift register full/empty */

/*
 * This table indicates for each PMU opcode:
 * - the number of data bytes to be sent with the command, or -1
 *   if a length byte should be sent,
 * - the number of response bytes which the PMU will return, or
 *   -1 if it will send a length byte.
 */
static const int8_t pmu_data_len[256][2] = {
/*	   0	   1	   2	   3	   4	   5	   6	   7  */
/*00*/  {-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*08*/  {-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*10*/  { 1, 0},{ 1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*18*/  { 0, 1},{ 0, 1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{ 0, 0},
/*20*/  {-1, 0},{ 0, 0},{ 2, 0},{ 1, 0},{ 1, 0},{-1, 0},{-1, 0},{-1, 0},
/*28*/  { 0,-1},{ 0,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{ 0,-1},
/*30*/  { 4, 0},{20, 0},{-1, 0},{ 3, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*38*/  { 0, 4},{ 0,20},{ 2,-1},{ 2, 1},{ 3,-1},{-1,-1},{-1,-1},{ 4, 0},
/*40*/  { 1, 0},{ 1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*48*/  { 0, 1},{ 0, 1},{-1,-1},{ 1, 0},{ 1, 0},{-1,-1},{-1,-1},{-1,-1},
/*50*/  { 1, 0},{ 0, 0},{ 2, 0},{ 2, 0},{-1, 0},{ 1, 0},{ 3, 0},{ 1, 0},
/*58*/  { 0, 1},{ 1, 0},{ 0, 2},{ 0, 2},{ 0,-1},{-1,-1},{-1,-1},{-1,-1},
/*60*/  { 2, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*68*/  { 0, 3},{ 0, 3},{ 0, 2},{ 0, 8},{ 0,-1},{ 0,-1},{-1,-1},{-1,-1},
/*70*/  { 1, 0},{ 1, 0},{ 1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*78*/  { 0,-1},{ 0,-1},{-1,-1},{-1,-1},{-1,-1},{ 5, 1},{ 4, 1},{ 4, 1},
/*80*/  { 4, 0},{-1, 0},{ 0, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*88*/  { 0, 5},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*90*/  { 1, 0},{ 2, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*98*/  { 0, 1},{ 0, 1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*a0*/  { 2, 0},{ 2, 0},{ 2, 0},{ 4, 0},{-1, 0},{ 0, 0},{-1, 0},{-1, 0},
/*a8*/  { 1, 1},{ 1, 0},{ 3, 0},{ 2, 0},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*b0*/  {-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*b8*/  {-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*c0*/  {-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*c8*/  {-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
/*d0*/  { 0, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*d8*/  { 1, 1},{ 1, 1},{-1,-1},{-1,-1},{ 0, 1},{ 0,-1},{-1,-1},{-1,-1},
/*e0*/  {-1, 0},{ 4, 0},{ 0, 1},{-1, 0},{-1, 0},{ 4, 0},{-1, 0},{-1, 0},
/*e8*/  { 3,-1},{-1,-1},{ 0, 1},{-1,-1},{ 0,-1},{-1,-1},{-1,-1},{ 0, 0},
/*f0*/  {-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},{-1, 0},
/*f8*/  {-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},{-1,-1},
};

/*
 * PMU commands
 */
#define PMU_POWER_CTRL0            0x10  /* control power of some devices */
#define PMU_POWER_CTRL             0x11  /* control power of some devices */
#define PMU_ADB_CMD                0x20  /* send ADB packet */
#define PMU_ADB_POLL_OFF           0x21  /* disable ADB auto-poll */
#define PMU_WRITE_NVRAM            0x33  /* write non-volatile RAM */
#define PMU_READ_NVRAM             0x3b  /* read non-volatile RAM */
#define PMU_SET_RTC                0x30  /* set real-time clock */
#define PMU_READ_RTC               0x38  /* read real-time clock */
#define PMU_SET_VOLBUTTON          0x40  /* set volume up/down position */
#define PMU_BACKLIGHT_BRIGHT       0x41  /* set backlight brightness */
#define PMU_GET_VOLBUTTON          0x48  /* get volume up/down position */
#define PMU_PCEJECT                0x4c  /* eject PC-card from slot */
#define PMU_BATTERY_STATE          0x6b  /* report battery state etc. */
#define PMU_SMART_BATTERY_STATE    0x6f  /* report battery state (new way) */
#define PMU_SET_INTR_MASK          0x70  /* set PMU interrupt mask */
#define PMU_INT_ACK                0x78  /* read interrupt bits */
#define PMU_SHUTDOWN               0x7e  /* turn power off */
#define PMU_CPU_SPEED              0x7d  /* control CPU speed on some models */
#define PMU_SLEEP                  0x7f  /* put CPU to sleep */
#define PMU_POWER_EVENTS           0x8f  /* Send power-event commands to PMU */
#define PMU_I2C_CMD                0x9a  /* I2C operations */
#define PMU_RESET                  0xd0  /* reset CPU */
#define PMU_GET_BRIGHTBUTTON       0xd9  /* report brightness up/down pos */
#define PMU_GET_COVER              0xdc  /* report cover open/closed */
#define PMU_SYSTEM_READY           0xdf  /* tell PMU we are awake */
#define PMU_GET_VERSION            0xea  /* read the PMU version */

/* Bits to use with the PMU_POWER_CTRL0 command */
#define PMU_POW0_ON                0x80  /* OR this to power ON the device */
#define PMU_POW0_OFF               0x00  /* leave bit 7 to 0 to power it OFF */
#define PMU_POW0_HARD_DRIVE        0x04  /* Hard drive power (on wallstreet/lombard ?) */

/* Bits to use with the PMU_POWER_CTRL command */
#define PMU_POW_ON                 0x80  /* OR this to power ON the device */
#define PMU_POW_OFF                0x00  /* leave bit 7 to 0 to power it OFF */
#define PMU_POW_BACKLIGHT          0x01  /* backlight power */
#define PMU_POW_CHARGER            0x02  /* battery charger power */
#define PMU_POW_IRLED              0x04  /* IR led power (on wallstreet) */
#define PMU_POW_MEDIABAY           0x08  /* media bay power (wallstreet/lombard ?) */

/* Bits in PMU interrupt and interrupt mask bytes */
#define PMU_INT_PCEJECT            0x04  /* PC-card eject buttons */
#define PMU_INT_SNDBRT             0x08  /* sound/brightness up/down buttons */
#define PMU_INT_ADB                0x10  /* ADB autopoll or reply data */
#define PMU_INT_BATTERY            0x20  /* Battery state change */
#define PMU_INT_ENVIRONMENT        0x40  /* Environment interrupts */
#define PMU_INT_TICK               0x80  /* 1-second tick interrupt */

/* Other bits in PMU interrupt valid when PMU_INT_ADB is set */
#define PMU_INT_ADB_AUTO           0x04  /* ADB autopoll, when PMU_INT_ADB */
#define PMU_INT_WAITING_CHARGER    0x01  /* ??? */
#define PMU_INT_AUTO_SRQ_POLL      0x02  /* ??? */

/* Bits in the environement message (either obtained via PMU_GET_COVER,
 * or via PMU_INT_ENVIRONMENT on core99 */
#define PMU_ENV_LID_CLOSED         0x01  /* The lid is closed */

/* I2C related definitions */
#define PMU_I2C_MODE_SIMPLE    0
#define PMU_I2C_MODE_STDSUB    1
#define PMU_I2C_MODE_COMBINED  2

#define PMU_I2C_BUS_STATUS     0
#define PMU_I2C_BUS_SYSCLK     1
#define PMU_I2C_BUS_POWER      2

#define PMU_I2C_STATUS_OK          0
#define PMU_I2C_STATUS_DATAREAD    1
#define PMU_I2C_STATUS_BUSY        0xfe

/* PMU PMU_POWER_EVENTS commands */
enum {
    PMU_PWR_GET_POWERUP_EVENTS = 0x00,
    PMU_PWR_SET_POWERUP_EVENTS = 0x01,
    PMU_PWR_CLR_POWERUP_EVENTS = 0x02,
    PMU_PWR_GET_WAKEUP_EVENTS  = 0x03,
    PMU_PWR_SET_WAKEUP_EVENTS  = 0x04,
    PMU_PWR_CLR_WAKEUP_EVENTS  = 0x05,
};

/* Power events wakeup bits */
enum {
    PMU_PWR_WAKEUP_KEY       = 0x01,  /* Wake on key press */
    PMU_PWR_WAKEUP_AC_INSERT = 0x02,  /* Wake on AC adapter plug */
    PMU_PWR_WAKEUP_AC_CHANGE = 0x04,
    PMU_PWR_WAKEUP_LID_OPEN  = 0x08,
    PMU_PWR_WAKEUP_RING      = 0x10,
};

static uint8_t pmu_readb(pmu_t *dev, int reg)
{
    return *(volatile uint8_t *)(dev->base + reg);
    asm volatile("eieio" : : : "memory");
}

static void pmu_writeb(pmu_t *dev, int reg, uint8_t val)
{
    *(volatile uint8_t *)(dev->base + reg) = val;
    asm volatile("eieio" : : : "memory");
}

static void pmu_handshake(pmu_t *dev)
{
    pmu_writeb(dev, B, pmu_readb(dev, B) & ~TREQ);
    while ((pmu_readb(dev, B) & TACK) != 0);

    pmu_writeb(dev, B, pmu_readb(dev, B) | TREQ);
    while ((pmu_readb(dev, B) & TACK) == 0);
}

static void pmu_send_byte(pmu_t *dev, uint8_t val)
{
    pmu_writeb(dev, ACR, pmu_readb(dev, ACR) | SR_OUT | SR_EXT);
    pmu_writeb(dev, SR, val);
    pmu_handshake(dev);
}

static uint8_t pmu_recv_byte(pmu_t *dev)
{
    pmu_writeb(dev, ACR, (pmu_readb(dev, ACR) & ~SR_OUT) | SR_EXT);
    pmu_readb(dev, SR);
    pmu_handshake(dev);

    return pmu_readb(dev, SR);
}

int pmu_request(pmu_t *dev, uint8_t cmd,
                uint8_t in_len, uint8_t *in_data,
                uint8_t *out_len, uint8_t *out_data)
{
    int i, l, out_sz;
    uint8_t d;

    /* Check command data size */
    l = pmu_data_len[cmd][0];
    if (l >= 0 && in_len != l) {
        printk("PMU: Error, request %02x wants %d args, got %d\n",
               cmd, l, in_len);
        return -1;
    }

    /* Make sure PMU is idle */
    while ((pmu_readb(dev, B) & TACK) == 0);

    /* Send command */
    pmu_send_byte(dev, cmd);

    /* Optionally send data length */
    if (l < 0) {
        pmu_send_byte(dev, in_len);
        /* Send data */
    }

    for (i = 0; i < in_len; i++) {
        pmu_send_byte(dev, in_data[i]);
    }

    /* Check response size */
    l = pmu_data_len[cmd][1];
    if (l < 0) {
        l = pmu_recv_byte(dev);
    }

    if (out_len) {
        out_sz = *out_len;
        *out_len = 0;
    } else {
        out_sz = 0;
    }

    if (l > out_sz) {
        printk("PMU: Error, request %02x returns %d bytes"
               ", room for %d\n", cmd, l, out_sz);
    }

    for (i = 0; i < l; i++) {
        d = pmu_recv_byte(dev);
        if (i < out_sz) {
            out_data[i] = d;
            (*out_len)++;
        }
    }

    return 0;
}

#define MAX_REQ_SIZE     128

#ifdef CONFIG_DRIVER_ADB
static int pmu_adb_req(void *host, const uint8_t *snd_buf, int len,
                       uint8_t *rcv_buf)
{
    uint8_t buffer[MAX_REQ_SIZE], *pos, olen;
    int rc;

    PMU_DPRINTF("pmu_adb_req: len=%d: %02x %02x %02x...\n",
                len, snd_buf[0], snd_buf[1], snd_buf[2]);

    if (len >= (MAX_REQ_SIZE - 1)) {
        printk("pmu_adb_req: too big ! (%d)\n", len);
        return -1;
    }

    buffer[0] = snd_buf[0];
    buffer[1] = 0; /* We don't do autopoll */
    buffer[2] = len - 1;

    if (len > 1) {
        memcpy(&buffer[3], &snd_buf[1], len - 1);
    }
    rc = pmu_request(host, PMU_ADB_CMD, len + 2, buffer, NULL, NULL);
    if (rc) {
        printk("PMU adb request failure %d\n", rc);
        return 0;
    }
    olen = MAX_REQ_SIZE;
    rc = pmu_request(host, PMU_INT_ACK, 0, NULL, &olen, buffer);
    if (rc) {
        printk("PMU intack request failure %d\n", rc);
        return 0;
    }
    PMU_DPRINTF("pmu_resp=%d int=0x%02x\n", olen, buffer[0]);
    if (olen <= 2) {
        return 0;
    } else {
        pos = &buffer[3];
        olen -= 3;
        PMU_DPRINTF("ADB resp: 0x%02x 0x%02x\n", buffer[3], buffer[4]);
    }
    memcpy(rcv_buf, pos, olen);

    return olen;
}
#endif

DECLARE_UNNAMED_NODE(ob_pmu, 0, sizeof(int));

static pmu_t *main_pmu;

static void pmu_reset_all(void)
{
    pmu_request(main_pmu, PMU_RESET, 0, NULL, NULL, NULL);
}

static void pmu_poweroff(void)
{
    uint8_t params[] = "MATT";

    pmu_request(main_pmu, PMU_SHUTDOWN, 4, params, NULL, NULL);
}

static void ob_pmu_open(int *idx)
{
    RET(-1);
}

static void ob_pmu_close(int *idx)
{
}

NODE_METHODS(ob_pmu) = {
    { "open",      ob_pmu_open },
    { "close",     ob_pmu_close },
};

DECLARE_UNNAMED_NODE(rtc, 0, sizeof(int));

static void rtc_open(int *idx)
{
    RET(-1);
}

static void rtc_close(int *idx)
{
}

/*
 * get-time ( -- second minute hour day month year )
 *
 */

static const int days_month[12] =
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static const int days_month_leap[12] =
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

static inline int is_leap(int year)
{
    return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

static void rtc_get_time(int *idx)
{
    uint8_t obuf[4], olen;
    ucell second, minute, hour, day, month, year;
    uint32_t now;
    int current;
    const int *days;

    olen = 4;
    pmu_request(main_pmu, PMU_READ_RTC, 0, NULL, &olen, obuf);

    /* seconds since 01/01/1904 */
    now = (obuf[0] << 24) + (obuf[1] << 16) + (obuf[2] << 8) + obuf[3];

    second =  now % 60;
    now /= 60;

    minute = now % 60;
    now /= 60;

    hour = now % 24;
    now /= 24;

    year = now * 100 / 36525;
    now -= year * 36525 / 100;
    year += 1904;

    days = is_leap(year) ?  days_month_leap : days_month;

    current = 0;
    month = 0;
    while (month < 12) {
        if (now <= current + days[month]) {
            break;
        }

        current += days[month];
        month++;
    }
    month++;

    day = now - current;

    PUSH(second);
    PUSH(minute);
    PUSH(hour);
    PUSH(day);
    PUSH(month);
    PUSH(year);
}

/*
 * set-time ( second minute hour day month year -- )
 *
 */

static  void rtc_set_time(int *idx)
{
    uint8_t ibuf[4];
    ucell second, minute, hour, day, month, year;
    const int *days;
    uint32_t now;
    unsigned int nb_days;
    int i;

    year = POP();
    month = POP();
    day = POP();
    hour = POP();
    minute = POP();
    second = POP();

    days = is_leap(year) ?  days_month_leap : days_month;
    nb_days = (year - 1904) * 36525 / 100 + day;
    for (i = 0; i < month - 1; i++) {
        nb_days += days[i];
    }

    now = (((nb_days * 24) + hour) * 60 + minute) * 60 + second;

    ibuf[0] = now >> 24;
    ibuf[1] = now >> 16;
    ibuf[2] = now >> 8;
    ibuf[3] = now;
    pmu_request(main_pmu, PMU_SET_RTC, 4, ibuf, NULL, NULL);
}

NODE_METHODS(rtc) = {
    { "open",      rtc_open },
    { "close",      rtc_close },
    { "get-time",  rtc_get_time },
    { "set-time",  rtc_set_time },
};

static void rtc_init(char *path)
{
    phandle_t aliases;
    char buf[128];

    push_str(path);
    fword("find-device");

    fword("new-device");

    push_str("rtc");
    fword("device-name");

    push_str("rtc");
    fword("device-type");

    push_str("rtc,via-pmu");
    fword("encode-string");
    push_str("compatible");
    fword("property");

    BIND_NODE_METHODS(get_cur_dev(), rtc);
    fword("finish-device");

    aliases = find_dev("/aliases");
    snprintf(buf, sizeof(buf), "%s/rtc", path);
    set_property(aliases, "rtc", buf, strlen(buf) + 1);
}

static void powermgt_init(char *path)
{
    phandle_t ph;

    push_str(path);
    fword("find-device");

    fword("new-device");

    push_str("power-mgt");
    fword("device-name");

    push_str("power-mgt");
    fword("device-type");

    push_str("via-pmu-99");
    fword("encode-string");
    push_str("compatible");
    fword("property");

    push_str("extint-gpio1");
    fword("encode-string");
    push_str("registry-name");
    fword("property");

    /* This is a bunch of magic "Feature" bits for which we only have
     * partial definitions from Darwin. These are taken from a
     * PowerMac3,1 device-tree. They are also identical in a
     * PowerMac5,1 "Cube". Note that more recent machines such as
     * the MacMini (PowerMac10,1) do not have this property, however
     * MacOS 9 seems to require it (it hangs during boot otherwise).
     */
    const char prim[] = { 0x00, 0x00, 0x00, 0xff,
                          0x00, 0x00, 0x00, 0x2c,
                          0x00, 0x03, 0x0d, 0x40,
                          /* Public PM features */
                          /* 0x00000001 : Wake timer supported */
                          /* 0x00000004 : Processor cycling supported */
                          /* 0x00000100 : Can wake on modem ring */
                          /* 0x00000200 : Has monitor dimming support */
                          /* 0x00000400 : Can program startup timer */
                          /* 0x00002000 : Supports wake on LAN */
                          /* 0x00004000 : Can wake on LID/case open */
                          /* 0x00008000 : Can power off PCI on sleep */
                          /* 0x00010000 : Supports deep sleep */
                          0x00, 0x01, 0xe7, 0x05,
                          /* Private PM features */
                          /* 0x00000400 : Supports ICT control */
                          /* 0x00001000 : Supports Idle2 in hardware */
                          /* 0x00002000 : Open case prevents sleep */
                          0x00, 0x00, 0x34, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, /* # of batteries supported */
                          0x26, 0x0d,
                          0x46, 0x00, 0x02, 0x78,
                          0x78, 0x3c, 0x00 };

    ph = get_cur_dev();
    BIND_NODE_METHODS(ph, rtc);

    set_property(ph, "prim-info", prim, sizeof(prim));

    fword("finish-device");
}

pmu_t *pmu_init(const char *path, phys_addr_t base)
{
    pmu_t *pmu;
    char buf[64];
    phandle_t aliases;

    base += IO_PMU_OFFSET;
    PMU_DPRINTF(" base=" FMT_plx "\n", base);

    pmu = malloc(sizeof(pmu_t));
    if (pmu == NULL) {
        return NULL;
    }

    fword("new-device");

    push_str("via-pmu");
    fword("device-name");

    push_str("via-pmu");
    fword("device-type");

    push_str("pmu");
    fword("encode-string");
    push_str("compatible");
    fword("property");

    PUSH(1);
    fword("encode-int");
    push_str("#address-cells");
    fword("property");

    PUSH(0);
    fword("encode-int");
    push_str("#size-cells");
    fword("property");

    PUSH(IO_PMU_OFFSET);
    fword("encode-int");
    PUSH(IO_PMU_SIZE);
    fword("encode-int");
    fword("encode+");
    push_str("reg");
    fword("property");

    /* On newworld machines the PMU is on interrupt 0x19 */
    PUSH(0x19);
    fword("encode-int");
    PUSH(1);
    fword("encode-int");
    fword("encode+");
    push_str("interrupts");
    fword("property");

    PUSH(0xd0330c);
    fword("encode-int");
    push_str("pmu-version");
    fword("property");

    BIND_NODE_METHODS(get_cur_dev(), ob_pmu);

    aliases = find_dev("/aliases");
    snprintf(buf, sizeof(buf), "%s/via-pmu", path);
    set_property(aliases, "via-pmu", buf, strlen(buf) + 1);
    pmu->base = base;

#ifdef CONFIG_DRIVER_ADB
    if (has_adb()) {
       pmu->adb_bus = adb_bus_new(pmu, &pmu_adb_req);
       adb_bus_init(buf, pmu->adb_bus);
    }
#endif

    rtc_init(buf);
    powermgt_init(buf);

    main_pmu = pmu;

    fword("finish-device");

    bind_func("pmu-power-off", pmu_poweroff);
    feval("['] pmu-power-off to power-off");
    bind_func("pmu-reset-all", pmu_reset_all);
    feval("['] pmu-reset-all to reset-all");

    return pmu;
}
