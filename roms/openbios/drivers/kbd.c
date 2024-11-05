/*
 * <kbd.c>
 *
 * Open Hack'Ware BIOS generic keyboard input translation.
 *
 *  Copyright (c) 2005 Jocelyn Mayer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 */

#include "config.h"
#include "libc/string.h"
#include "asm/types.h"
#include "kbd.h"

//#define DEBUG_KBD
#ifdef DEBUG_KBD
#define KBD_DPRINTF(fmt, args...) \
do { printk("KBD - %s: " fmt, __func__ , ##args); } while (0)
#else
#define KBD_DPRINTF(fmt, args...) do { } while (0)
#endif

int kbd_set_keymap (kbd_t *kbd, int nb_keys, const keymap_t *keymap, const char **sequences)
{
    kbd->nb_keys = nb_keys;
    kbd->keymap = keymap;
    kbd->sequences = sequences;

    return 0;
}

int kbd_translate_key (kbd_t *kbd, int keycode, int up_down, char *sequence)
{
    const keymap_t *keyt;
    int mod_state, key, type;
    int ret;

    ret = -1;
    /* Get key table */
    if (keycode < kbd->nb_keys) {
        keyt = &kbd->keymap[keycode];
        /* Get modifier state */
        mod_state = (kbd->mod_state | (kbd->mod_state >> 8)) & 0xFF;
        /* Adjust with lock */
        if (keyt->lck_shift >= 0) {
            if ((kbd->mod_state >> (16 + keyt->lck_shift)) & 0x01) {
                KBD_DPRINTF("adjust with lock %02x => %02x (%d %08x)\n",
                            mod_state,
                            mod_state ^ ((kbd->mod_state >>
                                          (16 + keyt->lck_shift)) &
                                         0x01),
                            keyt->lck_shift, kbd->mod_state);
            }
            mod_state ^= (kbd->mod_state >> (16 + keyt->lck_shift)) & 0x01;
        }
        key = keyt->trans[mod_state];
        type = key & 0xFF000000;
        key &= ~0xFF000000;
        switch (type) {
        case KBD_TYPE_REGULAR:
            if (!up_down) {
                /* We don't care about up events on "normal" keys */
		*sequence = key;
                ret = 1;
            }
            break;
        case KBD_TYPE_SEQUENCE:
            if (!up_down) {
                /* We don't care about up events on "normal" keys */
                ret = strlen(kbd->sequences[key]);
		memcpy(sequence, kbd->sequences[key], ret);
            }
            break;
        case KBD_TYPE_LOCK:
            if (!up_down) {
                kbd->mod_state ^= key;
                ret = -2;
                KBD_DPRINTF("Change modifier type %d key %04x %s => %08x\n",
                            type, key, up_down ? "up" : "down",
                            kbd->mod_state);
            }
            break;
        case KBD_TYPE_LMOD:
        case KBD_TYPE_RMOD:
            if (up_down)
                kbd->mod_state &= ~key;
            else
                kbd->mod_state |= key;
            KBD_DPRINTF("Change modifier type %d key %04x %s => %08x\n",
                        type, key, up_down ? "up" : "down", kbd->mod_state);
            ret = -2; /* The caller may know the key was a modifier */
            break;
        default:
            KBD_DPRINTF("Unknown key: keycode=%02x mod_state=%02x (%08x)\n",
                        keycode, mod_state, kbd->mod_state);
            break;
        }
    } else {
        KBD_DPRINTF("Unmanaged key: keycode=%02x mod_state %08x\n",
                    keycode, kbd->mod_state);
    }

    return ret;
}
