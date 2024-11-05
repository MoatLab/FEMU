#ifndef A1_VIDEO_H
#define A1_VIDEO_H

void video_clear_attr(void);
void video_clear(void);
void video_draw_box(int style, int attr, char *title, int separate, int x, int y, int w, int h);

void video_draw_text(int x, int y, int attr, char *text, int field);
/* Ok, I'm not the author of this madness but it looks like it works like this:
x and y are the coordinates,
attr is the "style"
text is the text to be displayed
field is the length of the field to write. If shorter than the text length, the text
will be truncated. If longer, padding spaces will be added to erase the remaining field
*/

void video_push(int x, int y, int w, int h, int clearchar, int clearattr);
void video_pop(void);
void video_clear_box(int x, int y, int w, int h, int clearchar, int clearattr);
int  video_rows(void);
int  video_cols(void);
void get_partial_scroll_limits(short * const start, short * const end);
unsigned short set_partial_scroll_limits(const short start, const short end);

int video_get_key(void);
int  video_init(void);
extern int drv_video_init(void);
extern void video_set_cursor(int line, int column);
extern void video_attr(int which, int color);
extern void video_repeat_char(int x, int y, int repcnt, int repchar, int attr);

void set_current_display(void *);

#define SINGLE_BOX 0
#define DOUBLE_BOX 1

#define PARTIAL_SCROLL_ACTIVE(s, e) ((s != -1) && (e != -1))

#endif /* A1_VIDEO_H */
