#include "menu.h"
#include "func_items.h"
#include <stdarg.h>
#include "creation.h"

struct func_item
{
    item_t item;
    char *display_text;
    void *param1;
    int param2;
    void (*func)(item_t *,void *, int);
};

void itemtype_func_render(menu_t *menu, item_t *item, int state)
{
    struct func_item *it = (struct func_item *)item;
    int x,y;
    x = menu->x + item->x;
    y = menu->y + item->y;

    video_draw_text(x,y, state, it->display_text, item->w);
}

void itemtype_func_invoke(menu_t *menu, item_t *item, int key)
{
    struct func_item *it = (struct func_item *)item;
    switch(key)
    {
    case KEY_ACTIVATE:
	if (it->func)
	{
	    it->func(item, it->param1, it->param2);
	}
	break;
    }
}

item_t *itemtype_func_alloc(menu_t *menu, va_list args)
{
    //char *s;
    struct func_item *item = (struct func_item *)malloc(sizeof(struct func_item));
    if (!item) return NULL;
    menu_item_init(&item->item);

    item->display_text = va_arg(args, char *);
    item->func         = va_arg(args, void *);
    item->param1       = va_arg(args, void *);
    item->param2       = va_arg(args, int);

    item->item.f_render = itemtype_func_render;
    item->item.f_save   = NULL;
    item->item.f_invoke = itemtype_func_invoke;
    item->item.f_load   = NULL;

    item->item.w = item->item.front_width = strlen(item->display_text);
    item->item.back_width  = 0;
    item->item.h = 1;
    item->item.disabled     = false;

    return (item_t *)item;
}

struct submenu_item
{
    item_t item;
    char *display_text;
    char *menu;
};

void itemtype_submenu_render(menu_t *menu, item_t *item, int state)
{
    struct func_item *it = (struct func_item *)item;
    int x,y;
    x = menu->x + item->x;
    y = menu->y + item->y;

    video_draw_text(x,y, state, it->display_text, item->w);
}

void itemtype_submenu_invoke(menu_t *menu, item_t *item, int key)
{
    char *men_name;
    switch(key)
    {
    case KEY_ACTIVATE:
    case KEY_NEXT_OPTION:
    case KEY_PREV_OPTION:
	break;
    default:
	return;
    }

    men_name = ((struct submenu_item *)item)->menu;
    menu_form_switch_menu(menu->parent_form, men_name);
}

item_t *itemtype_submenu_alloc(menu_t *menu, va_list args)
{
    struct submenu_item *item = (struct submenu_item *)malloc(sizeof(struct submenu_item));
    if (!item) return NULL;
    menu_item_init(&item->item);

    item->display_text = va_arg(args, char *);
    item->menu         = va_arg(args, char *);

    item->item.f_render = itemtype_submenu_render;
    item->item.f_save   = NULL;
    item->item.f_invoke = itemtype_submenu_invoke;
    item->item.f_load   = NULL;

    item->item.w = item->item.front_width = strlen(item->display_text);
    item->item.back_width  = 0;
    item->item.h = 1;
    item->item.disabled     = false;

    return (item_t *)item;
}
