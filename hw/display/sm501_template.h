/*
 * Pixel drawing function templates for QEMU SM501 Device
 *
 * Copyright (c) 2008 Shin-ichiro KAWASAKI
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#if DEPTH == 8
#define BPP 1
#define PIXEL_TYPE uint8_t
#elif DEPTH == 15 || DEPTH == 16
#define BPP 2
#define PIXEL_TYPE uint16_t
#elif DEPTH == 32
#define BPP 4
#define PIXEL_TYPE uint32_t
#else
#error unsupport depth
#endif

#ifdef BGR_FORMAT
#define PIXEL_NAME glue(DEPTH, bgr)
#else
#define PIXEL_NAME DEPTH
#endif /* BGR_FORMAT */


static void glue(draw_line8_, PIXEL_NAME)(
                 uint8_t *d, const uint8_t *s, int width, const uint32_t *pal)
{
    uint8_t v, r, g, b;
    do {
        v = ldub_p(s);
        r = (pal[v] >> 16) & 0xff;
        g = (pal[v] >>  8) & 0xff;
        b = (pal[v] >>  0) & 0xff;
        *(PIXEL_TYPE *)d = glue(rgb_to_pixel, PIXEL_NAME)(r, g, b);
        s++;
        d += BPP;
    } while (--width != 0);
}

static void glue(draw_line16_, PIXEL_NAME)(
                 uint8_t *d, const uint8_t *s, int width, const uint32_t *pal)
{
    uint16_t rgb565;
    uint8_t r, g, b;

    do {
        rgb565 = lduw_le_p(s);
        r = (rgb565 >> 8) & 0xf8;
        g = (rgb565 >> 3) & 0xfc;
        b = (rgb565 << 3) & 0xf8;
        *(PIXEL_TYPE *)d = glue(rgb_to_pixel, PIXEL_NAME)(r, g, b);
        s += 2;
        d += BPP;
    } while (--width != 0);
}

static void glue(draw_line32_, PIXEL_NAME)(
                 uint8_t *d, const uint8_t *s, int width, const uint32_t *pal)
{
    uint8_t r, g, b;

    do {
        r = s[2];
        g = s[1];
        b = s[0];
        *(PIXEL_TYPE *)d = glue(rgb_to_pixel, PIXEL_NAME)(r, g, b);
        s += 4;
        d += BPP;
    } while (--width != 0);
}

/**
 * Draw hardware cursor image on the given line.
 */
static void glue(draw_hwc_line_, PIXEL_NAME)(uint8_t *d, const uint8_t *s,
                 int width, const uint8_t *palette, int c_x, int c_y)
{
    int i;
    uint8_t r, g, b, v, bitset = 0;

    /* get cursor position */
    assert(0 <= c_y && c_y < SM501_HWC_HEIGHT);
    s += SM501_HWC_WIDTH * c_y / 4;  /* 4 pixels per byte */
    d += c_x * BPP;

    for (i = 0; i < SM501_HWC_WIDTH && c_x + i < width; i++) {
        /* get pixel value */
        if (i % 4 == 0) {
            bitset = ldub_p(s);
            s++;
        }
        v = bitset & 3;
        bitset >>= 2;

        /* write pixel */
        if (v) {
            v--;
            r = palette[v * 3 + 0];
            g = palette[v * 3 + 1];
            b = palette[v * 3 + 2];
            *(PIXEL_TYPE *)d = glue(rgb_to_pixel, PIXEL_NAME)(r, g, b);
        }
        d += BPP;
    }
}

#undef DEPTH
#undef BPP
#undef PIXEL_TYPE
#undef PIXEL_NAME
#undef BGR_FORMAT
