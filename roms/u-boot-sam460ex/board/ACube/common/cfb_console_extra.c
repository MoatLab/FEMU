/*
 * modified 2008 by
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
#include <devices.h>
#include "memio.h"
#include <part.h>
#include "../menu/menu.h"
#include "hvideo.h"
#include <malloc.h>
#include <video_fb.h>
#include <video_font.h>


#undef DEBUG

#ifdef DEBUG
#define PRINTF(format, args...) _printf(format , ## args)
#else
#define PRINTF(format, argc...)
#endif

#define VIDEO_VISIBLE_COLS	(pGD->winSizeX)
#define VIDEO_VISIBLE_ROWS	(pGD->winSizeY)
#define VIDEO_PIXEL_SIZE	(pGD->gdfBytesPP)
#define VIDEO_DATA_FORMAT	(pGD->gdfIndex)
#define VIDEO_FB_ADRS		(pGD->frameAdrs)

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
#define CONSOLE_SCROLL_SIZE	(CONSOLE_SIZE - CONSOLE_ROW_SIZE

extern GraphicDevice *pGD;	/* Pointer to Graphic array */

extern const int video_font_draw_table8[];
extern const int video_font_draw_table15[];
extern const int video_font_draw_table16[];
extern const int video_font_draw_table24[16][3];
extern const int video_font_draw_table32[16][4];

extern void *video_fb_address;		/* frame buffer address */
extern void *video_console_address;	/* console buffer start address */

extern int console_col; /* cursor col */
extern int console_row; /* cursor row */

extern u32 eorx, fgx, bgx;  /* color pats */

extern void memsetl (int *p, int c, int v);

int overwrite_console(void)
{
    return 0;
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
		fgx = 0x01010101;	// White on Black
		bgx = 0x00000000;
		break;
	case 1:
		fgx = 0x04040404;	// Red on Black
		bgx = 0x00000000;
		break;
	case 2:
		fgx = 0x01010101;	// White on Blue
		bgx = 0x08080808;
		break;
	case 3:
		fgx = 0x07070707;	// Dark Gray on Black
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
     	video_drawchars_color(x, y, text, 1, attr);
		x += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
	
		if (field != -1) field--;
		if (field == 0) break;

		text++;
    }
    
    while (field > 0)
    {
     	video_drawchars_color(x, y, " ", 1, attr);
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
		    video_drawchars_color(x1, y1, " ", 1, attr);
		    x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    
		    //while (*title)
		    {
		    	video_drawchars_color(x1, y1, title, strlen(title), attr);
		    	x1 += strlen(title) * VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    	//title++;
		    }
		    
		    video_drawchars_color(x1, y1, " ", 1, attr);
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
		    	video_drawchars_color(x1, y1, " ", 1, attr);
				x1 += VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    }
		    
			x1 = xp + 2 * VIDEO_FONT_WIDTH * VIDEO_PIXEL_SIZE;
		    y1 = yp + VIDEO_FONT_HEIGHT * VIDEO_PIXEL_SIZE;
	
	    	video_drawchars_color(x1, y1, title, strlen(title), attr);;
		}		
    }   
}
