#include "menu.h"
#include "layout.h"

#define MENU_FIRST_COLUMN      3
#define MENU_SECOND_COLUMN     44
#define MENU_TOP               4
#define MENU_BOTTOM            16

void menu_layout(menu_t *menu)
{
    int 
	x=MENU_FIRST_COLUMN,
	y=MENU_TOP,

	max_width = 0,
	max_front_width = 0,
	max_back_width = 0;

    int
	height = 0,
	//temp_h,
	temp_l;

    item_t*
	item;

    if (menu->type == MENUTYPE_POPUP)
    {
	x = 0;
	y = 0;
    }

    /* Find size maximums */
    item = (item_t *)(menu->item_list.first);
    while (item)
    {
	if (item->w > max_width)
	    max_width = item->w;
	if (item->front_width > max_front_width)
	    max_front_width = item->front_width;
	if (item->back_width > max_back_width)
	    max_back_width = item->back_width;

	item = (item_t *)(item->link.next);
    }

    /* Layout phase */
    item = (item_t *)(menu->item_list.first);
    while (item)
    {
	item->x = x;
	item->y = y;
	temp_l = menu->item_spacing + item->h - 1;
	y += temp_l;
	if (y > MENU_BOTTOM || item->break_after == true)
	{
	    y = MENU_TOP;
	    x = MENU_SECOND_COLUMN;
	}
	height += temp_l;
	item->w = max_width;
	item->front_width = max_front_width;
	item->back_width = max_back_width;
	item = (item_t *)(item->link.next);
    }

    height -= menu->item_spacing;

    /* Set the first item to be the acrive one */
    if (menu->current_item == NULL) 
    {
	menu->current_item = (item_t *)(menu->item_list.first);
	while (menu->current_item && menu->current_item->disabled == true)
	{
	    menu->current_item = (item_t *)(menu->current_item->link.next);
	}
    }
    
    menu->w = max_width;
    menu->h = height;
}
