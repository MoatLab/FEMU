#include "menu.h"
#include "string_edit.h"

//static int num_lines = 0;
static int x_pos=0, y_pos=0;
static int width = 0, height = 0;
static int cursor_pos = 0;
static char *buffer;
static char *prompt;
static int buffer_length;
static char backup[1024];

#define STRINGBOX_WIDTH       70
#define STRINGBOX_HEIGHT      4
#define STRINGBOX_X           5
#define STRINGBOX_Y           5

static void string_edit_draw(void)
{
    int 
	i,j,
	length = buffer_length,
	attr = MENUATTR_NORMAL;

    char
	c;

    //int cursor_x = 0, cursor_y = 0;

    for (i=0; i<height; i++)
    {
	for (j=0; j<width; j++)
	{
	    int 
		offset = j+i*width;
	    
	    if (offset > length) 
		c = ' ';
	    else
		c = buffer[offset];

	    if (offset == cursor_pos)
#if 1 //def SIM
		attr = MENUATTR_HILITE;
	    else
		attr = MENUATTR_NORMAL;
#else
	    {
		cursor_x = x_pos+j;
		cursor_y = y_pos+i;
	    }
#endif
	    video_draw_text(x_pos + j, y_pos + i, attr, &c, 1);
	}
    }
#if 0 //ndef SIM
    video_set_cursor(cursor_y, cursor_y); 
#endif
}

static void string_clear_frame(void)
{
    video_clear_box(STRINGBOX_X-2, STRINGBOX_Y-2,
		    STRINGBOX_WIDTH+4, STRINGBOX_HEIGHT+4,
		    ' ', MENUATTR_NORMAL);
}

static void string_draw_frame(void)
{
    string_clear_frame();
    video_draw_box(SINGLE_BOX, MENUATTR_NORMAL, prompt, 0, 
		   STRINGBOX_X-2, STRINGBOX_Y-2,
		   STRINGBOX_WIDTH+4, STRINGBOX_HEIGHT+4);
}

static void backspace(void)
{
    int
	i;
    
    char 
	*s;

    if (cursor_pos == 0) return;
    if (cursor_pos == buffer_length)
    {
	buffer_length--;
	cursor_pos--;
	buffer[buffer_length] = 0;
    }
    else
    {
	s = buffer+cursor_pos-1;
	for (i = 0; i < buffer_length - cursor_pos + 1; i++)
	{
	    *s = *(s+1);
	    s++;
	}
	cursor_pos--;
	buffer_length--;
    }
}

static void insert(int key)
{
    int
	i;

    char
	*s;

    s = buffer + buffer_length;
    for (i = 0; i < buffer_length - cursor_pos + 1; i++)
    {
	*(s+1) = *s;
	s--;
    }
    *(buffer + cursor_pos) = (char)key;
    cursor_pos++;
    buffer_length++;
}

bool menu_string_edit(char *_prompt, char *string, int buffersize)
{
    int 
	key;

    prompt = _prompt;
    x_pos  = STRINGBOX_X;
    y_pos  = STRINGBOX_Y;
    width  = STRINGBOX_WIDTH;
    height = STRINGBOX_HEIGHT;

    buffer = string;
    strcpy(backup, string);

    buffer_length = cursor_pos = strlen(buffer);

    string_draw_frame();
    do
    {
	string_edit_draw();
	key = video_get_key();
	switch(key)
	{
	case KEY_ABORT:
	    strcpy(string, backup);
	    string_clear_frame();
	    menu_draw_current_form();
	    return false;
	case KEY_ACTIVATE:
	    string_clear_frame();
	    menu_draw_current_form();
	    return true;
	case KEY_NEXT_OPTION:
	    cursor_pos++;
	    if (cursor_pos > buffer_length) cursor_pos = buffer_length;
	    break;
	case KEY_PREV_OPTION:
	    cursor_pos--;
	    if (cursor_pos < 0) cursor_pos = 0;
	    break;
	case KEY_DELETE:
	    /* Backspace */
	    backspace();
	    break;
	default:
	    if (key >= 32 && key <= 127)
	    {
		insert(key);
	    }
	    break;
	}
    } while (1);
    
    return false;
}
