/*
 * modified 2008-2009 by
 * Max Tretene, ACube Systems Srl. mtretene@acube-systems.com.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

//-----------------------------------------------------------------------------
// SAM440EP extensions to support SLB - to be moved outside cfb_console.c
//-----------------------------------------------------------------------------
 
#include <common.h>
#include <stdio_dev.h>
#include <part.h>
#include "../menu/menu.h"
#include "vesa.h"
#include <malloc.h>
#include <video_fb.h>
#include <video_font.h>
#include "radeon.h"
#include <asm/io.h>

#undef DEBUG

#ifdef DEBUG
#define PRINTF(format, args...) _printf(format , ## args)
#else
#define PRINTF(format, argc...)
#endif

#define VIDEO_NAME "vga"

#define VIDEO_VISIBLE_COLS	(fbi->XSize)
#define VIDEO_VISIBLE_ROWS	(fbi->YSize)
#define VIDEO_PIXEL_SIZE	(fbi->BitsPerPixel/8)
#define VIDEO_DATA_FORMAT	GDF__8BIT_INDEX //(pGD->gdfIndex)
#define VIDEO_FB_ADRS		(fbi->BaseAddress)

#define VIDEO_COLS			VIDEO_VISIBLE_COLS
#define VIDEO_ROWS			VIDEO_VISIBLE_ROWS
#define VIDEO_SIZE			(VIDEO_ROWS*VIDEO_COLS*VIDEO_PIXEL_SIZE)
#define VIDEO_PIX_BLOCKS	(VIDEO_SIZE >> 2)
#define VIDEO_LINE_LEN		(VIDEO_COLS*VIDEO_PIXEL_SIZE)
#define VIDEO_BURST_LEN		(VIDEO_COLS/8)

#define CONSOLE_ROWS		(VIDEO_ROWS / VIDEO_FONT_HEIGHT)
#define CONSOLE_COLS		(VIDEO_COLS / VIDEO_FONT_WIDTH)
#define CONSOLE_ROW_SIZE	(VIDEO_FONT_HEIGHT * VIDEO_LINE_LEN)
#define CONSOLE_ROW_FIRST	(video_console_address)
#define CONSOLE_ROW_SECOND	(video_console_address + CONSOLE_ROW_SIZE)
#define CONSOLE_ROW_LAST	(video_console_address + CONSOLE_SIZE - CONSOLE_ROW_SIZE)
#define CONSOLE_SIZE		(CONSOLE_ROW_SIZE * CONSOLE_ROWS)
#define CONSOLE_SCROLL_SIZE	(CONSOLE_SIZE - CONSOLE_ROW_SIZE)

#define CURSOR_ON
#define CURSOR_OFF video_putchar(console_col * VIDEO_FONT_WIDTH,\
				 console_row * VIDEO_FONT_HEIGHT, ' ');
#define CURSOR_SET video_set_cursor();

#define SWAP32(x)	 ((((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8)|\
			  (((x) & 0x00ff0000) >>  8) | (((x) & 0xff000000) >> 24) )
#define SHORTSWAP32(x)	 ((((x) & 0x000000ff) <<  8) | (((x) & 0x0000ff00) >> 8)|\
			  (((x) & 0x00ff0000) <<  8) | (((x) & 0xff000000) >> 8) )
			  
#ifdef CONFIG_VIDEO_SM502
extern unsigned char SM502;
extern unsigned char SM502INIT;
#endif
extern int onbus;
extern u32 mmio_base_phys;
extern u32 io_base_phys;
extern struct FrameBufferInfo *fbi;
			  
#define OUTREG(addr,val)	writel(val, mmio_base_phys + addr)

const int video_font_draw_table8[] = {
	    0x00000000, 0x000000ff, 0x0000ff00, 0x0000ffff,
	    0x00ff0000, 0x00ff00ff, 0x00ffff00, 0x00ffffff,
	    0xff000000, 0xff0000ff, 0xff00ff00, 0xff00ffff,
	    0xffff0000, 0xffff00ff, 0xffffff00, 0xffffffff };

void *video_fb_address;		    /* frame buffer address */
void *video_console_address;	/* console buffer start address */

int console_col; /* cursor col */
int console_row; /* cursor row */

u32 eorx, fgx, bgx;  /* color pats */

#define DC_LUT_RW_SELECT                0x6480
#define DC_LUT_RW_MODE                  0x6484
#define DC_LUT_RW_INDEX                 0x6488
#define DC_LUT_30_COLOR                 0x6494
#define DC_LUT_WRITE_EN_MASK            0x649C
#define DC_LUTA_CONTROL                 0x64C0
#define DC_LUTA_BLACK_OFFSET_BLUE       0x64C4
#define DC_LUTA_BLACK_OFFSET_GREEN      0x64C8
#define DC_LUTA_BLACK_OFFSET_RED        0x64CC
#define DC_LUTA_WHITE_OFFSET_BLUE       0x64D0
#define DC_LUTA_WHITE_OFFSET_GREEN      0x64D4
#define DC_LUTA_WHITE_OFFSET_RED        0x64D8

//***************************************************************************

void video_set_lut2 (unsigned int index,	/* color number */
	       unsigned int rr,	/* red */
	       unsigned int gg,	/* green */
	       unsigned int bb	/* blue */
	       )
{
#ifdef CONFIG_VIDEO_SM502
	if (SM502 && SM502INIT)
	{
		video_set_lut(index, rr, gg, bb);
	}
	else
#endif
	{
	    if (onbus >= 2) {
	        /* RadeonHD on PCI-E */
	        OUTREG(DC_LUT_30_COLOR, (rr << 20) | (gg << 10) | bb);
	    }
	    else {
	        /* Radeon or RadeonHD on PCI */
    		OUTREG(PALETTE_INDEX, index | index << 16);
	    	OUTREG(PALETTE_DATA, (rr << 16) | (gg << 8) | bb);
	    }
	}
}

void memsetl (int *p, int c, int v)
{
	while (c--)
		*(p++) = v;
}

static void memcpyl (int *d, int *s, int c)
{
	while (c--)
		*(d++) = *(s++);
}

/******************************************************************************/

static void console_scrollup (void)
{
	/* copy up rows ignoring the first one */

	memcpyl (CONSOLE_ROW_FIRST, CONSOLE_ROW_SECOND, (CONSOLE_SCROLL_SIZE >> 2));

	memsetl (CONSOLE_ROW_LAST, (CONSOLE_ROW_SIZE >> 2), CONSOLE_BG_COL);
}

static void video_drawchars (int xx, int yy, unsigned char *s, int count)
{
	u8 *cdat, *dest, *dest0;
	int rows, offset, c;

	offset = yy * VIDEO_LINE_LEN + xx * VIDEO_PIXEL_SIZE;
	dest0 = video_fb_address + offset;

	switch (VIDEO_DATA_FORMAT) {
	case GDF__8BIT_INDEX:
	case GDF__8BIT_332RGB:
		while (count--) {
			c = *s;
			cdat = video_fontdata + c * VIDEO_FONT_HEIGHT;
			for (rows = VIDEO_FONT_HEIGHT, dest = dest0;
			     rows--;
			     dest += VIDEO_LINE_LEN) {
				u8 bits = *cdat++;

				((u32 *) dest)[0] = (video_font_draw_table8[bits >> 4] & eorx) ^ bgx;
				((u32 *) dest)[1] = (video_font_draw_table8[bits & 15] & eorx) ^ bgx;
			}
			dest0 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
			s++;
		}
		break;
	}
}

static void video_putchar (int xx, int yy, unsigned char c)
{
	video_drawchars (xx, yy, &c, 1);
}

static void console_back (void)
{
	CURSOR_OFF 
	console_col--;

	if (console_col < 0) {
		console_col = CONSOLE_COLS - 1;
		console_row--;
		if (console_row < 0)
			console_row = 0;
	}
	video_putchar (console_col * VIDEO_FONT_WIDTH,
		       console_row * VIDEO_FONT_HEIGHT,
		       ' ');
}

static void console_newline (void)
{
	CURSOR_OFF 
	console_row++;
	console_col = 0;

	/* Check if we need to scroll the terminal */
	if (console_row >= CONSOLE_ROWS) {
		/* Scroll everything up */
		console_scrollup ();

		/* Decrement row number */
		console_row--;
	}
}

static void video_set_cursor (void)
{
	/* swap drawing colors */
	eorx = fgx;
	fgx = bgx;
	bgx = eorx;
	eorx = fgx ^ bgx;
	/* draw cursor */
	CURSOR_OFF
	/* restore drawing colors */
	eorx = fgx;
	fgx = bgx;
	bgx = eorx;
	eorx = fgx ^ bgx;
}

unsigned short set_partial_scroll_limits(const short start, const short end)
{
/*
	if(!PARTIAL_SCROLL_ACTIVE(start, end))
	{
		// Deactivates the partial scroll
		partial_scroll_start=-1;
		partial_scroll_end=-1;
	
		return 1;
	}

	if(	(start < end) &&
		((start >= 0) && (start <= video_numrows-1)) &&
		((end >= 1) && (end <= video_numrows)))
	{
		partial_scroll_start = start;
		partial_scroll_end = end;

		cursor_row = start;
		cursor_col = 0;
		video_set_cursor(start,0);

		return 1;
	}
*/
	return 0;	
}

void get_partial_scroll_limits(short * const start, short * const end)
{
/*
	*start = partial_scroll_start;
	*end = partial_scroll_end;
*/	
}

// used in menu
int video_get_key(void)
{
	int c = getc();
	
	switch(c)
	{
		case 0x1B:
			return KEY_ABORT;
		case 0x0D:
			return KEY_ACTIVATE;
		case 0x08:
			return KEY_DELETE;
	}
	
	return c;
}

unsigned char video_single_box[] =
{
    218, 196, 191,
    179,      179,
    192, 196, 217
};

unsigned char video_single_title[] =
{
    195, 196, 180, 180, 195
};

void video_clear(void)
{
	memsetl (CONSOLE_ROW_FIRST, CONSOLE_SIZE >> 2, CONSOLE_BG_COL);
}

void video_set_color(unsigned char attr)
{
	memsetl (CONSOLE_ROW_FIRST, CONSOLE_SIZE >> 2, attr);	
}

static void video_drawchars_color (int xx, int yy, unsigned char *s, int count, int attr)
{
	u8 *cdat, *dest, *dest0;
	u32 oldfgx, oldbgx;
	int rows, offset, c;

	offset = yy * VIDEO_LINE_LEN + xx * VIDEO_PIXEL_SIZE;
	dest0 = video_fb_address + offset;

	/* change drawing colors */
	oldfgx = fgx;
	oldbgx = bgx;
	
	switch (attr) {
	case 0:
	case 4:
		fgx = 0xffffffff;	// White on Black
		bgx = 0x00000000;
		break;
	case 1:
		fgx = 0xC0C0C0C0;	// Red on Black
		bgx = 0x00000000;
		break;
	case 2:
		fgx = 0xffffffff;	// White on Blue
		bgx = 0x80808080;
		break;
	case 3:
		fgx = 0x80808080;	// Dark Gray on Black
		bgx = 0x00000000;
		break;
	}

	eorx = fgx ^ bgx;
	
	switch (VIDEO_DATA_FORMAT) {
	case GDF__8BIT_INDEX:
	case GDF__8BIT_332RGB:
		while (count--) {
			c = *s;
			cdat = video_fontdata + c * VIDEO_FONT_HEIGHT;
			for (rows = VIDEO_FONT_HEIGHT, dest = dest0;
			     rows--;
			     dest += VIDEO_LINE_LEN) {
				u8 bits = *cdat++;

				((u32 *) dest)[0] = (video_font_draw_table8[bits >> 4] & eorx) ^ bgx;
				((u32 *) dest)[1] = (video_font_draw_table8[bits & 15] & eorx) ^ bgx;
			}
			dest0 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
			s++;
		}
		break;
	}
	
   	/* restore drawing colors */
	fgx = oldfgx;
	bgx = oldbgx;
	eorx = fgx ^ bgx;
}

void video_clear_attr(void)
{
  video_set_color(0); //current_attr);
}

void video_attr(int which, int color)
{
/*
	if (which > 4)
		return;
		
	int back = (color & 0x70) >> 4;
	color = color & 0x0f;
	
	color *= 3;
	back *= 3;
	
	video_fore[which] = pack_color(vga_color_table[color], vga_color_table[color+1], vga_color_table[color+2]);
	video_back[which] = pack_color(vga_color_table[back], vga_color_table[back+1], vga_color_table[back+2]);
*/
}

void video_clear_box(int x, int y, int w, int h, int clearchar, int attr)
{
    int line, col;
	unsigned char c = (unsigned char)clearchar;

    for (line=y; line<y+h; line++)
    {
		for (col=x; col<x+w; col++)
		{
	    	video_drawchars_color(col*VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE, 
	    						  line*VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE, 
	    						  &c, 1, attr);
		}
    }
}

void video_draw_text(int x, int y, int attr, char *text, int field)
{
	x *= VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
	y *= VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
	
    while (*text)
    {
     	video_drawchars_color(x, y, (uchar *)text, 1, attr);
		x += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
	
		if (field != -1) field--;
		if (field == 0) break;

		text++;
    }
    
    while (field > 0)
    {
     	video_drawchars_color(x, y, (uchar *)" ", 1, attr);
		x += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		field--;
    }
}

void video_repeat_char(int x, int y, int repcnt, int repchar, int attr)
{
	unsigned char c = (unsigned char)repchar;

	x *= VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
	y *= VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;

    while (repcnt--)
    {
    	video_drawchars_color(x, y, &c, 1, attr);
    	x += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
    }
}

void video_draw_box(int style, int attr, char *title, int separate, 
	int xp, int yp, int w, int h)
{
    unsigned char *st = video_single_box;
    unsigned char *ti = video_single_title;
       
    int i;
    int x1, y1;
    int x2, y2;

    xp *= VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
    yp *= VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;

    x1 = xp;
    y1 = yp;
    x2 = xp;
    y2 = yp + ((h - 1) * VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE);
    
    video_drawchars_color(x1, y1, &st[0], 1, attr);
    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;

    video_drawchars_color(x2, y2, &st[5], 1, attr);
    x2 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
    
    for (i=0; i<w-2;i++)
    {
    	video_drawchars_color(x1, y1, &st[1], 1, attr);
    	x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
	
		video_drawchars_color(x2, y2, &st[6], 1, attr);
		x2 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
    }
    
    video_drawchars_color(x1, y1, &st[2], 1, attr);
    video_drawchars_color(x2, y2, &st[7], 1, attr);

    x1 = xp;
    y1 = yp + VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
    x2 = xp + (w - 1) * VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
    y2 = yp + VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
    
    for (i=0; i<h-2; i++)
    {
    	video_drawchars_color(x1, y1, &st[3], 1, attr);
		y1 += VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
		video_drawchars_color(x2, y2, &st[4], 1, attr);
		y2 += VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
    }

    // Draw title
    if (title)
    {
		if (separate == 0)
		{
		    x1 = xp + VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    y1 = yp;
		    video_drawchars_color(x1, y1, &ti[3], 1, attr);
		    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    video_drawchars_color(x1, y1, (uchar *)" ", 1, attr);
		    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    
		    //while (*title)
		    {
		    	video_drawchars_color(x1, y1, (uchar *)title, strlen(title), attr);
		    	x1 += strlen(title) * VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    	//title++;
		    }
		    
		    video_drawchars_color(x1, y1, (uchar *)" ", 1, attr);
		    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    video_drawchars_color(x1, y1, &ti[4], 1, attr);
		    
		}
		else
		{
		    x1 = xp;
		    y1 = yp + 2 * VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
		    video_drawchars_color(x1, y1, &ti[0], 1, attr);
		    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    
		    for (i=0; i<w-2; i++)
		    {
		    	video_drawchars_color(x1, y1, &ti[1], 1, attr);
				x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    }
		    
		    video_drawchars_color(x1, y1, &ti[2], 1, attr);
		    
		    x1 = xp + VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    y1 = yp + VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
		    
		    for (i=0; i<w-2; i++)
		    {
		    	video_drawchars_color(x1, y1, (uchar *)" ", 1, attr);
				x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    }
		    
			x1 = xp + 2 * VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    y1 = yp + VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
	
	    	video_drawchars_color(x1, y1, (uchar *)title, strlen(title), attr);;
		}		
    }   
}

void video_putc (const char c)
{
    static char oldc=0;
    
	switch (c) {
	case '\r':
	//	console_col = 0;
		break;

	case '\n':		/* next line */
		console_newline ();
		break;

	case 9:		/* tab 8 */
		CURSOR_OFF 
		console_col |= 0x0008;
		console_col &= ~0x0007;

		if (console_col >= CONSOLE_COLS)
			console_newline ();
		break;

	case 8:		/* backspace */
		console_back ();
		break;

	default:		/* draw the char */
	    if (oldc == '\r') 
	    {
	        CURSOR_OFF
	        console_col = 0;
	    }
		video_putchar (console_col * VIDEO_FONT_WIDTH,
			       console_row * VIDEO_FONT_HEIGHT,
			       c);
		console_col++;

		/* check for newline */
		if (console_col >= CONSOLE_COLS)
			console_newline ();
	}
	
	CURSOR_SET
	
	oldc = c;
}

void video_puts (const char *s)
{
	int count = strlen (s);

	while (count--)
		video_putc (*s++);
}

static int video_init (void)
{
	int ii;
	unsigned char color8;

	video_fb_address = (void *) VIDEO_FB_ADRS;

	/* Init drawing pats */
	switch (VIDEO_DATA_FORMAT) {
	case GDF__8BIT_INDEX:
	    if (onbus >= 2) {
	        /* RadeonHD on PCI-E */
            OUTREG(DC_LUTA_CONTROL, 0);
        
            OUTREG(DC_LUTA_BLACK_OFFSET_BLUE, 0);
            OUTREG(DC_LUTA_BLACK_OFFSET_GREEN, 0);
            OUTREG(DC_LUTA_BLACK_OFFSET_RED, 0);
        
            OUTREG(DC_LUTA_WHITE_OFFSET_BLUE, 0x0000FFFF);
            OUTREG(DC_LUTA_WHITE_OFFSET_GREEN, 0x0000FFFF);
            OUTREG(DC_LUTA_WHITE_OFFSET_RED, 0x0000FFFF);
        
            OUTREG(DC_LUT_RW_SELECT, 0);
        
            OUTREG(DC_LUT_RW_MODE, 0); /* table */
            OUTREG(DC_LUT_WRITE_EN_MASK, 0x0000003F);
        
            OUTREG(DC_LUT_RW_INDEX, 0);	 
            
            for (ii=0;ii<256;ii++)
    			video_set_lut2 (ii, ii<<2, ii<<2, ii<<2);   
	    }
	    else {
	        /* Radeon or RadeonHD on PCI */
    		for (ii=0;ii<256;ii++)
    			video_set_lut2 (ii, ii, ii, ii);
    	}		

		fgx = 0xffffffff;
		bgx = 0x00000000;
		break;
	case GDF__8BIT_332RGB:
		color8 = ((CONSOLE_FG_COL & 0xe0) |
			  ((CONSOLE_FG_COL >> 3) & 0x1c) | CONSOLE_FG_COL >> 6);
		fgx = (color8 << 24) | (color8 << 16) | (color8 << 8) | color8;
		color8 = ((CONSOLE_BG_COL & 0xe0) |
			  ((CONSOLE_BG_COL >> 3) & 0x1c) | CONSOLE_BG_COL >> 6);
		bgx = (color8 << 24) | (color8 << 16) | (color8 << 8) | color8;
		break;		
	}
	eorx = fgx ^ bgx;

	video_console_address = video_fb_address;

	/* Initialize the console */
	console_col = 0;
	console_row = 0;

	return 0;
}

int overwrite_console(void)
{
    return 0;
}

/*****************************************************************************/

int drv_video_init (void)
{
	int skip_dev_init;
	struct stdio_dev console_dev;
	
	skip_dev_init = 0;

	/* Init video chip - returns with framebuffer cleared */
	if (video_init () == -1)
		skip_dev_init = 1;		

	/* Devices VGA and Keyboard will be assigned seperately */
	/* Init vga device */
	if (!skip_dev_init) {
		memset (&console_dev, 0, sizeof (console_dev));
		strcpy (console_dev.name, "vga");
		console_dev.ext = DEV_EXT_VIDEO;	/* Video extensions */
		console_dev.flags = DEV_FLAGS_OUTPUT | DEV_FLAGS_SYSTEM;
		console_dev.putc = video_putc;	/* 'putc' function */
		console_dev.puts = video_puts;	/* 'puts' function */
		console_dev.tstc = NULL;	/* 'tstc' function */
		console_dev.getc = NULL;	/* 'getc' function */
		
	    int error = stdio_register (&console_dev);

	    if (error == 0)
	    {
			char *s = getenv("stdout");
			if (s && strcmp(s, "vga")==0)
			{
			    if (overwrite_console()) return 1;
			    error = console_assign(stdout, "vga");
		    	if (error == 0) 
		    		return 1;
		    	else 
		    		return error;
			}
			return 1;
	    }
	
	    return error;		
	}

	/* No console dev available */
	return 0;
}
