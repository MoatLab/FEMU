#include "menu.h"
#include <stdarg.h>
#include "string_items.h"
#include "string_edit.h"
#include "creation.h"

#define MAX_DISPLAY_WIDTH 40

void itemtype_string_cvar_save(menu_t *menu, item_t *item);
void itemtype_string_cvar_load(menu_t *menu, item_t *item);

struct string_cvar_item
{
    item_t item;
    char *display_text;
    char *var_name;
    char  value[512];
    char *def_value;
    int  base;
};

void itemtype_string_cvar_render(menu_t *menu, item_t *item, int state)
{
    struct string_cvar_item 
	*it = (struct string_cvar_item *)item;

    int 
	x = menu->x + item->x,
	y = menu->y + item->y,
	difference = 0;

    char 
	*buffer = it->value + it->base;

    video_draw_text(x,y, MENUATTR_NORMAL, it->display_text, -1);
    video_draw_text(x+item->front_width,y,  MENUATTR_NORMAL, ":", -1);

    x +=item->front_width+1;

    if (it->base)
	difference ++;

    if (strlen(it->value + it->base) >= MAX_DISPLAY_WIDTH)
	difference ++;

    if (it->base) 
    {
	video_draw_text(x,y,state, "<", 1);
	x++;
    }

    video_draw_text(x,y,state, buffer, item->back_width - difference);
    x += item->back_width - difference;

    if (strlen(it->value + it->base) >= MAX_DISPLAY_WIDTH)
    {
	video_draw_text(x, y, state, ">", 1);
    }
}

void itemtype_string_cvar_invoke(menu_t *menu, item_t *item, int key)
{
    struct string_cvar_item *it = (struct string_cvar_item *)item;
    switch(key)
    {
    case KEY_ACTIVATE:
	menu_string_edit(it->display_text, it->value, 512);
	break;
    case KEY_PREV_OPTION:
	if (it->base > 0) it->base--;
	if (it->base == 1) it->base = 0;
	itemtype_string_cvar_render(menu, item, MENUATTR_HILITE);
	break;
    case KEY_NEXT_OPTION:
	if (strlen(it->value) < MAX_DISPLAY_WIDTH) break;
	if (it->base <= (strlen(it->value) - MAX_DISPLAY_WIDTH))
	{
	    if (it->base == 0) it->base = 1;
	    it->base++;
	    itemtype_string_cvar_render(menu, item, MENUATTR_HILITE);
	}
	break;
    }
}

void itemtype_string_cvar_load(menu_t *menu, item_t *item)
{
    struct string_cvar_item *it = (struct string_cvar_item *)item;
    char *s;
    s = GETENV(it->var_name); 
    if (s)
    {
	strcpy(it->value, s);
    }
    else strcpy(it->value, it->def_value);
    item->f_save = itemtype_string_cvar_save;
    item->f_load = 0;
}

void itemtype_string_cvar_save(menu_t *menu, item_t *item)
{
    struct string_cvar_item *it = (struct string_cvar_item *)item;

    SETENV(it->var_name, it->value);
}

item_t *itemtype_string_cvar_alloc(menu_t *menu, va_list args)
{
    //int a,b;
    struct string_cvar_item *item = (struct string_cvar_item *)malloc(sizeof(struct string_cvar_item));
    if (!item) return NULL;

    menu_item_init(&item->item);

    item->display_text = va_arg(args, char *);
    item->var_name     = va_arg(args, char *);
    item->def_value    = va_arg(args, char *);
    item->value[0]     = 0;
    item->base         = 0;

    item->item.f_render = itemtype_string_cvar_render;
    item->item.f_save   = 0;
    item->item.f_invoke = itemtype_string_cvar_invoke;
    item->item.f_load   = itemtype_string_cvar_load;

    item->item.front_width  = strlen(item->display_text);
    item->item.back_width   = MAX_DISPLAY_WIDTH;

    item->item.w = item->item.back_width + item->item.front_width + 1;
    item->item.h = 1;

    return (item_t *)item;
}
