#include "menu.h"
#include <stdarg.h>
#include "label_items.h"
#include "creation.h"

struct label_item
{
    item_t item;
    char *display_text;
};

void itemtype_label_render(menu_t *menu, item_t *item, int state)
{
    struct label_item *it = (struct label_item *)item;
    int x,y;
    x = menu->x + item->x;
    y = menu->y + item->y;

    video_draw_text(x,y, state, it->display_text, item->w);
}

void itemtype_label_invoke(menu_t *menu, item_t *item, int key)
{
}

item_t *itemtype_label_alloc(menu_t *menu, va_list args)
{
    //char *s;
    struct label_item *item = (struct label_item *)malloc(sizeof(struct label_item));
    if (!item) return NULL;
    menu_item_init(&item->item);

    item->display_text = va_arg(args, char *);

    item->item.f_render = itemtype_label_render;
    item->item.f_save   = NULL;
    item->item.f_invoke = itemtype_label_invoke;
    item->item.f_load   = NULL;

    item->item.w            = strlen(item->display_text);
    item->item.front_width  = item->item.w/2;
    item->item.back_width   = item->item.w - item->item.front_width;
    item->item.h            = 1;
    item->item.disabled     = true;

    return (item_t *)item;
}
