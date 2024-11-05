#ifndef VESA_H
#define VESA_H

extern void *DoVesa(int argc, char *argv[]);
extern void *set_vesa_mode(int mode);

struct FrameBufferInfo
{
        void *BaseAddress;
        unsigned long XSize;
        unsigned long YSize;
        unsigned long BitsPerPixel;
        unsigned long Modulo;
        unsigned short RedMask;
        short RedShift;
        unsigned short GreenMask;
        short GreenShift;
        unsigned short BlueMask;
        short BlueShift;
} *fbi;

#endif //VESA_H
