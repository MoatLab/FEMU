// 16bit code to handle keyboard requests.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_BDA
#include "bregs.h" // struct bregs
#include "config.h" // CONFIG_*
#include "hw/ps2port.h" // ps2_kbd_command
#include "hw/usb-hid.h" // usb_kbd_command
#include "output.h" // debug_enter
#include "stacks.h" // yield
#include "string.h" // memset
#include "util.h" // kbd_init

void
kbd_init(void)
{
    dprintf(3, "init keyboard\n");
    u16 x = offsetof(struct bios_data_area_s, kbd_buf);
    SET_BDA(kbd_flag1, KF1_101KBD);
    SET_BDA(kbd_buf_head, x);
    SET_BDA(kbd_buf_tail, x);
    SET_BDA(kbd_buf_start_offset, x);

    SET_BDA(kbd_buf_end_offset
            , x + FIELD_SIZEOF(struct bios_data_area_s, kbd_buf));
}

u8
enqueue_key(u16 keycode)
{
    u16 buffer_start = GET_BDA(kbd_buf_start_offset);
    u16 buffer_end   = GET_BDA(kbd_buf_end_offset);

    u16 buffer_head = GET_BDA(kbd_buf_head);
    u16 buffer_tail = GET_BDA(kbd_buf_tail);

    u16 temp_tail = buffer_tail;
    buffer_tail += 2;
    if (buffer_tail >= buffer_end)
        buffer_tail = buffer_start;

    if (buffer_tail == buffer_head)
        return 0;

    SET_FARVAR(SEG_BDA, *(u16*)(temp_tail+0), keycode);
    SET_BDA(kbd_buf_tail, buffer_tail);
    return 1;
}

static void
dequeue_key(struct bregs *regs, int incr, int extended)
{
    yield();
    u16 buffer_head;
    u16 buffer_tail;
    for (;;) {
        buffer_head = GET_BDA(kbd_buf_head);
        buffer_tail = GET_BDA(kbd_buf_tail);

        if (buffer_head != buffer_tail)
            break;
        if (!incr) {
            regs->flags |= F_ZF;
            return;
        }
        yield_toirq();
    }

    u16 keycode = GET_FARVAR(SEG_BDA, *(u16*)(buffer_head+0));
    u8 ascii = keycode & 0xff;
    if (!extended) {
        // Translate extended keys
        if (ascii == 0xe0 && keycode & 0xff00)
            keycode &= 0xff00;
        else if (keycode == 0xe00d || keycode == 0xe00a)
            // Extended enter key
            keycode = 0x1c00 | ascii;
        else if (keycode == 0xe02f)
            // Extended '/' key
            keycode = 0x352f;
        // Technically, if the ascii value is 0xf0 or if the
        // 'scancode' is greater than 0x84 then the key should be
        // discarded.  However, there seems no harm in passing on the
        // extended values in these cases.
    }
    if (ascii == 0xf0 && keycode & 0xff00)
        keycode &= 0xff00;
    regs->ax = keycode;

    if (!incr) {
        regs->flags &= ~F_ZF;
        return;
    }
    u16 buffer_start = GET_BDA(kbd_buf_start_offset);
    u16 buffer_end   = GET_BDA(kbd_buf_end_offset);

    buffer_head += 2;
    if (buffer_head >= buffer_end)
        buffer_head = buffer_start;
    SET_BDA(kbd_buf_head, buffer_head);
}

static int
kbd_command(int command, u8 *param)
{
    if (usb_kbd_active())
        return usb_kbd_command(command, param);
    return ps2_kbd_command(command, param);
}

// read keyboard input
static void
handle_1600(struct bregs *regs)
{
    dequeue_key(regs, 1, 0);
}

// check keyboard status
static void
handle_1601(struct bregs *regs)
{
    dequeue_key(regs, 0, 0);
}

// get shift flag status
static void
handle_1602(struct bregs *regs)
{
    yield();
    regs->al = GET_BDA(kbd_flag0);
}

// store key-stroke into buffer
static void
handle_1605(struct bregs *regs)
{
    regs->al = !enqueue_key(regs->cx);
}

// GET KEYBOARD FUNCTIONALITY
static void
handle_1609(struct bregs *regs)
{
    // bit Bochs Description
    //  7    0   reserved
    //  6    0   INT 16/AH=20h-22h supported (122-key keyboard support)
    //  5    1   INT 16/AH=10h-12h supported (enhanced keyboard support)
    //  4    1   INT 16/AH=0Ah supported
    //  3    0   INT 16/AX=0306h supported
    //  2    0   INT 16/AX=0305h supported
    //  1    0   INT 16/AX=0304h supported
    //  0    0   INT 16/AX=0300h supported
    //
    regs->al = 0x30;
}

// GET KEYBOARD ID
static void noinline
handle_160a(struct bregs *regs)
{
    u8 param[2];
    int ret = kbd_command(ATKBD_CMD_GETID, param);
    if (ret) {
        regs->bx = 0;
        return;
    }
    regs->bx = (param[1] << 8) | param[0];
}

// read MF-II keyboard input
static void
handle_1610(struct bregs *regs)
{
    dequeue_key(regs, 1, 1);
}

// check MF-II keyboard status
static void
handle_1611(struct bregs *regs)
{
    dequeue_key(regs, 0, 1);
}

// get extended keyboard status
static void
handle_1612(struct bregs *regs)
{
    yield();
    regs->ax = ((GET_BDA(kbd_flag0) & ~((KF1_RCTRL|KF1_RALT) << 8))
                | ((GET_BDA(kbd_flag1) & (KF1_RCTRL|KF1_RALT)) << 8));
    //BX_DEBUG_INT16("int16: func 12 sending %04x\n",AX);
}

static void
handle_166f(struct bregs *regs)
{
    if (regs->al == 0x08)
        // unsupported, aka normal keyboard
        regs->ah = 2;
}

// keyboard capability check called by DOS 5.0+ keyb
static void
handle_1692(struct bregs *regs)
{
    // function int16 ah=0x10-0x12 supported
    regs->ah = 0x80;
}

// 122 keys capability check called by DOS 5.0+ keyb
static void
handle_16a2(struct bregs *regs)
{
    // don't change AH : function int16 ah=0x20-0x22 NOT supported
}

static void
handle_16XX(struct bregs *regs)
{
    warn_unimplemented(regs);
}

static void noinline
set_leds(void)
{
    u8 shift_flags = (GET_BDA(kbd_flag0) >> 4) & 0x07;
    u8 kbd_led = GET_BDA(kbd_led);
    u8 led_flags = kbd_led & 0x07;
    if (shift_flags == led_flags)
        return;

    int ret = kbd_command(ATKBD_CMD_SETLEDS, &shift_flags);
    if (ret)
        // Error
        return;
    kbd_led = (kbd_led & ~0x07) | shift_flags;
    SET_BDA(kbd_led, kbd_led);
}

// INT 16h Keyboard Service Entry Point
void VISIBLE16
handle_16(struct bregs *regs)
{
    debug_enter(regs, DEBUG_HDL_16);
    if (! CONFIG_KEYBOARD)
        return;

    // XXX - set_leds should be called from irq handler
    set_leds();

    switch (regs->ah) {
    case 0x00: handle_1600(regs); break;
    case 0x01: handle_1601(regs); break;
    case 0x02: handle_1602(regs); break;
    case 0x05: handle_1605(regs); break;
    case 0x09: handle_1609(regs); break;
    case 0x0a: handle_160a(regs); break;
    case 0x10: handle_1610(regs); break;
    case 0x11: handle_1611(regs); break;
    case 0x12: handle_1612(regs); break;
    case 0x92: handle_1692(regs); break;
    case 0xa2: handle_16a2(regs); break;
    case 0x6f: handle_166f(regs); break;
    default:   handle_16XX(regs); break;
    }
}

#define none 0

static struct scaninfo {
    u16 normal;
    u16 shift;
    u16 control;
    u16 alt;
} scan_to_keycode[] VAR16 = {
    {   none,   none,   none,   none },
    { 0x011b, 0x011b, 0x011b, 0x01f0 }, /* escape */
    { 0x0231, 0x0221,   none, 0x7800 }, /* 1! */
    { 0x0332, 0x0340, 0x0300, 0x7900 }, /* 2@ */
    { 0x0433, 0x0423,   none, 0x7a00 }, /* 3# */
    { 0x0534, 0x0524,   none, 0x7b00 }, /* 4$ */
    { 0x0635, 0x0625,   none, 0x7c00 }, /* 5% */
    { 0x0736, 0x075e, 0x071e, 0x7d00 }, /* 6^ */
    { 0x0837, 0x0826,   none, 0x7e00 }, /* 7& */
    { 0x0938, 0x092a,   none, 0x7f00 }, /* 8* */
    { 0x0a39, 0x0a28,   none, 0x8000 }, /* 9( */
    { 0x0b30, 0x0b29,   none, 0x8100 }, /* 0) */
    { 0x0c2d, 0x0c5f, 0x0c1f, 0x8200 }, /* -_ */
    { 0x0d3d, 0x0d2b,   none, 0x8300 }, /* =+ */
    { 0x0e08, 0x0e08, 0x0e7f, 0x0ef0 }, /* backspace */
    { 0x0f09, 0x0f00, 0x9400, 0xa5f0 }, /* tab */
    { 0x1071, 0x1051, 0x1011, 0x1000 }, /* Q */
    { 0x1177, 0x1157, 0x1117, 0x1100 }, /* W */
    { 0x1265, 0x1245, 0x1205, 0x1200 }, /* E */
    { 0x1372, 0x1352, 0x1312, 0x1300 }, /* R */
    { 0x1474, 0x1454, 0x1414, 0x1400 }, /* T */
    { 0x1579, 0x1559, 0x1519, 0x1500 }, /* Y */
    { 0x1675, 0x1655, 0x1615, 0x1600 }, /* U */
    { 0x1769, 0x1749, 0x1709, 0x1700 }, /* I */
    { 0x186f, 0x184f, 0x180f, 0x1800 }, /* O */
    { 0x1970, 0x1950, 0x1910, 0x1900 }, /* P */
    { 0x1a5b, 0x1a7b, 0x1a1b, 0x1af0 }, /* [{ */
    { 0x1b5d, 0x1b7d, 0x1b1d, 0x1bf0 }, /* ]} */
    { 0x1c0d, 0x1c0d, 0x1c0a, 0x1cf0 }, /* Enter */
    {   none,   none,   none,   none }, /* L Ctrl */
    { 0x1e61, 0x1e41, 0x1e01, 0x1e00 }, /* A */
    { 0x1f73, 0x1f53, 0x1f13, 0x1f00 }, /* S */
    { 0x2064, 0x2044, 0x2004, 0x2000 }, /* D */
    { 0x2166, 0x2146, 0x2106, 0x2100 }, /* F */
    { 0x2267, 0x2247, 0x2207, 0x2200 }, /* G */
    { 0x2368, 0x2348, 0x2308, 0x2300 }, /* H */
    { 0x246a, 0x244a, 0x240a, 0x2400 }, /* J */
    { 0x256b, 0x254b, 0x250b, 0x2500 }, /* K */
    { 0x266c, 0x264c, 0x260c, 0x2600 }, /* L */
    { 0x273b, 0x273a,   none, 0x27f0 }, /* ;: */
    { 0x2827, 0x2822,   none, 0x28f0 }, /* '" */
    { 0x2960, 0x297e,   none, 0x29f0 }, /* `~ */
    {   none,   none,   none,   none }, /* L shift */
    { 0x2b5c, 0x2b7c, 0x2b1c, 0x2bf0 }, /* |\ */
    { 0x2c7a, 0x2c5a, 0x2c1a, 0x2c00 }, /* Z */
    { 0x2d78, 0x2d58, 0x2d18, 0x2d00 }, /* X */
    { 0x2e63, 0x2e43, 0x2e03, 0x2e00 }, /* C */
    { 0x2f76, 0x2f56, 0x2f16, 0x2f00 }, /* V */
    { 0x3062, 0x3042, 0x3002, 0x3000 }, /* B */
    { 0x316e, 0x314e, 0x310e, 0x3100 }, /* N */
    { 0x326d, 0x324d, 0x320d, 0x3200 }, /* M */
    { 0x332c, 0x333c,   none, 0x33f0 }, /* ,< */
    { 0x342e, 0x343e,   none, 0x34f0 }, /* .> */
    { 0x352f, 0x353f,   none, 0x35f0 }, /* /? */
    {   none,   none,   none,   none }, /* R Shift */
    { 0x372a, 0x372a, 0x9600, 0x37f0 }, /* * */
    {   none,   none,   none,   none }, /* L Alt */
    { 0x3920, 0x3920, 0x3920, 0x3920 }, /* space */
    {   none,   none,   none,   none }, /* caps lock */
    { 0x3b00, 0x5400, 0x5e00, 0x6800 }, /* F1 */
    { 0x3c00, 0x5500, 0x5f00, 0x6900 }, /* F2 */
    { 0x3d00, 0x5600, 0x6000, 0x6a00 }, /* F3 */
    { 0x3e00, 0x5700, 0x6100, 0x6b00 }, /* F4 */
    { 0x3f00, 0x5800, 0x6200, 0x6c00 }, /* F5 */
    { 0x4000, 0x5900, 0x6300, 0x6d00 }, /* F6 */
    { 0x4100, 0x5a00, 0x6400, 0x6e00 }, /* F7 */
    { 0x4200, 0x5b00, 0x6500, 0x6f00 }, /* F8 */
    { 0x4300, 0x5c00, 0x6600, 0x7000 }, /* F9 */
    { 0x4400, 0x5d00, 0x6700, 0x7100 }, /* F10 */
    {   none,   none,   none,   none }, /* Num Lock */
    {   none,   none,   none,   none }, /* Scroll Lock */
    { 0x4700, 0x4737, 0x7700,   none }, /* 7 Home */
    { 0x4800, 0x4838, 0x8d00,   none }, /* 8 UP */
    { 0x4900, 0x4939, 0x8400,   none }, /* 9 PgUp */
    { 0x4a2d, 0x4a2d, 0x8e00, 0x4af0 }, /* - */
    { 0x4b00, 0x4b34, 0x7300,   none }, /* 4 Left */
    { 0x4c00, 0x4c35, 0x8f00,   none }, /* 5 */
    { 0x4d00, 0x4d36, 0x7400,   none }, /* 6 Right */
    { 0x4e2b, 0x4e2b, 0x9000, 0x4ef0 }, /* + */
    { 0x4f00, 0x4f31, 0x7500,   none }, /* 1 End */
    { 0x5000, 0x5032, 0x9100,   none }, /* 2 Down */
    { 0x5100, 0x5133, 0x7600,   none }, /* 3 PgDn */
    { 0x5200, 0x5230, 0x9200,   none }, /* 0 Ins */
    { 0x5300, 0x532e, 0x9300,   none }, /* Del */
    {   none,   none,   none,   none }, /* SysReq */
    {   none,   none,   none,   none },
    { 0x565c, 0x567c,   none,   none }, /* \| */
    { 0x8500, 0x8700, 0x8900, 0x8b00 }, /* F11 */
    { 0x8600, 0x8800, 0x8a00, 0x8c00 }, /* F12 */
};

struct scaninfo key_ext_enter VAR16 = {
    0xe00d, 0xe00d, 0xe00a, 0xa600
};
struct scaninfo key_ext_slash VAR16 = {
    0xe02f, 0xe02f, 0x9500, 0xa400
};

u16 ascii_to_keycode(u8 ascii)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(scan_to_keycode); i++) {
        if ((GET_GLOBAL(scan_to_keycode[i].normal) & 0xff) == ascii)
            return GET_GLOBAL(scan_to_keycode[i].normal);
        if ((GET_GLOBAL(scan_to_keycode[i].shift) & 0xff) == ascii)
            return GET_GLOBAL(scan_to_keycode[i].shift);
        if ((GET_GLOBAL(scan_to_keycode[i].control) & 0xff) == ascii)
            return GET_GLOBAL(scan_to_keycode[i].control);
    }
    return 0;
}

// Handle a ps2 style scancode read from the keyboard.
static void
kbd_set_flag(int key_release, u16 set_bit0, u8 set_bit1, u16 toggle_bit)
{
    u16 flags0 = GET_BDA(kbd_flag0);
    u8 flags1 = GET_BDA(kbd_flag1);
    if (key_release) {
        flags0 &= ~set_bit0;
        flags1 &= ~set_bit1;
    } else {
        flags0 ^= toggle_bit;
        flags0 |= set_bit0;
        flags1 |= set_bit1;
    }
    SET_BDA(kbd_flag0, flags0);
    SET_BDA(kbd_flag1, flags1);
}

static void
kbd_ctrl_break(int key_release)
{
    if (!key_release)
        return;
    // Clear keyboard buffer and place 0x0000 in buffer
    u16 buffer_start = GET_BDA(kbd_buf_start_offset);
    SET_BDA(kbd_buf_head, buffer_start);
    SET_BDA(kbd_buf_tail, buffer_start+2);
    SET_FARVAR(SEG_BDA, *(u16*)(buffer_start+0), 0x0000);
    // Set break flag
    SET_BDA(break_flag, 0x80);
    // Generate int 0x1b
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    call16_int(0x1b, &br);
}

static void
kbd_sysreq(int key_release)
{
    // SysReq generates int 0x15/0x85
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.ah = 0x85;
    br.al = key_release ? 0x01 : 0x00;
    br.flags = F_IF;
    call16_int(0x15, &br);
}

static void
kbd_prtscr(int key_release)
{
    if (key_release)
        return;
    // PrtScr generates int 0x05 (ctrl-prtscr has keycode 0x7200?)
    struct bregs br;
    memset(&br, 0, sizeof(br));
    br.flags = F_IF;
    call16_int(0x05, &br);
}

// Handle a ps2 style scancode read from the keyboard.
static void
__process_key(u8 scancode)
{
    // Check for multi-scancode key sequences
    u8 flags1 = GET_BDA(kbd_flag1);
    if (scancode == 0xe0 || scancode == 0xe1) {
        // Start of two byte extended (e0) or three byte pause key (e1) sequence
        u8 eflag = scancode == 0xe0 ? KF1_LAST_E0 : KF1_LAST_E1;
        SET_BDA(kbd_flag1, flags1 | eflag);
        return;
    }
    int key_release = scancode & 0x80;
    scancode &= ~0x80;
    if (flags1 & (KF1_LAST_E0|KF1_LAST_E1)) {
        if (flags1 & KF1_LAST_E1 && scancode == 0x1d)
            // Ignore second byte of pause key (e1 1d 45 / e1 9d c5)
            return;
        // Clear E0/E1 flag in memory for next key event
        SET_BDA(kbd_flag1, flags1 & ~(KF1_LAST_E0|KF1_LAST_E1));
    }

    // Check for special keys
    switch (scancode) {
    case 0x3a: /* Caps Lock */
        kbd_set_flag(key_release, KF0_CAPS, 0, KF0_CAPSACTIVE);
        return;
    case 0x2a: /* L Shift */
        if (flags1 & KF1_LAST_E0)
            // Ignore fake shifts
            return;
        kbd_set_flag(key_release, KF0_LSHIFT, 0, 0);
        return;
    case 0x36: /* R Shift */
        if (flags1 & KF1_LAST_E0)
            // Ignore fake shifts
            return;
        kbd_set_flag(key_release, KF0_RSHIFT, 0, 0);
        return;
    case 0x1d: /* Ctrl */
        if (flags1 & KF1_LAST_E0)
            kbd_set_flag(key_release, KF0_CTRLACTIVE, KF1_RCTRL, 0);
        else
            kbd_set_flag(key_release, KF0_CTRLACTIVE | KF0_LCTRL, 0, 0);
        return;
    case 0x38: /* Alt */
        if (flags1 & KF1_LAST_E0)
            kbd_set_flag(key_release, KF0_ALTACTIVE, KF1_RALT, 0);
        else
            kbd_set_flag(key_release, KF0_ALTACTIVE | KF0_LALT, 0, 0);
        return;
    case 0x45: /* Num Lock */
        if (flags1 & KF1_LAST_E1)
            // XXX - pause key.
            return;
        kbd_set_flag(key_release, KF0_NUM, 0, KF0_NUMACTIVE);
        return;
    case 0x46: /* Scroll Lock */
        if (flags1 & KF1_LAST_E0) {
            kbd_ctrl_break(key_release);
            return;
        }
        kbd_set_flag(key_release, KF0_SCROLL, 0, KF0_SCROLLACTIVE);
        return;

    case 0x37: /* * */
        if (flags1 & KF1_LAST_E0) {
            kbd_prtscr(key_release);
            return;
        }
        break;
    case 0x54: /* SysReq */
        kbd_sysreq(key_release);
        return;
    case 0x53: /* Del */
        if ((GET_BDA(kbd_flag0) & (KF0_CTRLACTIVE|KF0_ALTACTIVE))
            == (KF0_CTRLACTIVE|KF0_ALTACTIVE) && !key_release) {
            // Ctrl+alt+del - reset machine.
            SET_BDA(soft_reset_flag, 0x1234);
            reset();
        }
        break;

    default:
        break;
    }

    // Handle generic keys
    if (key_release)
        // ignore key releases
        return;
    if (!scancode || scancode >= ARRAY_SIZE(scan_to_keycode)) {
        dprintf(1, "__process_key unknown scancode read: 0x%02x!\n", scancode);
        return;
    }
    struct scaninfo *info = &scan_to_keycode[scancode];
    if (flags1 & KF1_LAST_E0 && (scancode == 0x1c || scancode == 0x35))
        info = (scancode == 0x1c ? &key_ext_enter : &key_ext_slash);
    u16 flags0 = GET_BDA(kbd_flag0);
    u16 keycode;
    if (flags0 & KF0_ALTACTIVE) {
        keycode = GET_GLOBAL(info->alt);
    } else if (flags0 & KF0_CTRLACTIVE) {
        keycode = GET_GLOBAL(info->control);
    } else {
        u8 useshift = flags0 & (KF0_RSHIFT|KF0_LSHIFT) ? 1 : 0;
        u8 ascii = GET_GLOBAL(info->normal) & 0xff;
        if ((flags0 & KF0_NUMACTIVE && scancode >= 0x47 && scancode <= 0x53)
            || (flags0 & KF0_CAPSACTIVE && ascii >= 'a' && ascii <= 'z'))
            // Numlock/capslock toggles shift on certain keys
            useshift ^= 1;
        if (useshift)
            keycode = GET_GLOBAL(info->shift);
        else
            keycode = GET_GLOBAL(info->normal);
    }
    if (flags1 & KF1_LAST_E0 && scancode >= 0x47 && scancode <= 0x53) {
        /* extended keys handling */
        if (flags0 & KF0_ALTACTIVE)
            keycode = (scancode + 0x50) << 8;
        else
            keycode = (keycode & 0xff00) | 0xe0;
    }
    if (keycode)
        enqueue_key(keycode);
}

void
process_key(u8 key)
{
    if (!CONFIG_KEYBOARD)
        return;

    if (CONFIG_KBD_CALL_INT15_4F) {
        // allow for keyboard intercept
        struct bregs br;
        memset(&br, 0, sizeof(br));
        br.eax = (0x4f << 8) | key;
        br.flags = F_IF|F_CF;
        call16_int(0x15, &br);
        if (!(br.flags & F_CF))
            return;
        key = br.eax;
    }
    __process_key(key);
}
