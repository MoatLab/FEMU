#ifndef PARISC_LASIPS2_H
#define PARISC_LASIPS2_H

void ps2port_setup(void);

int lasips2_kbd_in(char *c, int max);

#define LASIPS2_KBD_RESET   ((void *)(LASI_PS2KBD_HPA+0x00))
#define LASIPS2_KBD_DATA    ((void *)(LASI_PS2KBD_HPA+0x04))
#define LASIPS2_KBD_CONTROL ((void *)(LASI_PS2KBD_HPA+0x08))
#define LASIPS2_KBD_STATUS  ((void *)(LASI_PS2KBD_HPA+0x0c))

#define LASIPS2_KBD_CONTROL_EN 0x01
#define LASIPS2_KBD_STATUS_RBNE 0x01
#define LASIPS2_KBD_STATUS_TBNE 0x02

#endif
