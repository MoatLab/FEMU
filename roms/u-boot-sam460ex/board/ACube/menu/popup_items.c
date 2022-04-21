#include "menu.h"
#include <stdarg.h>
#include "popup_items.h"
#include "creation.h"

#define MAX_POPUP_SIZE 12
#define MAX_POPUP_STRING 20

struct popup_item
{
    item_t item;
    char *display_text;
    menu_t *menu_handle;
    int  choice;
    int max_choice;
    void (*save_hook)(void *, popup_entry_t *entry);
    int (*load_hook)(void *, popup_entry_t *);
    void *hook_user_data;
    popup_entry_t *entries;
};

void itemtype_popup_render(menu_t *menu, item_t *item, int state)
{
    struct popup_item *it = (struct popup_item *)item;
    int x,y;
    x = menu->x + item->x;
    y = menu->y + item->y;

    video_draw_text(x,y, MENUATTR_NORMAL, it->display_text, item->w);
    video_draw_text(x+item->front_width,y,  MENUATTR_NORMAL, ":", -1);
    video_draw_text(x+item->front_width+1,y,state,
		    it->choice >= 0 ? it->entries[it->choice].display_text : "<none>",
		    item->back_width);
}

void itemtype_popup_invoke(menu_t *menu, item_t *item, int key)
{
    struct popup_item
	*it = (struct popup_item *)item;

    switch(key)
    {
    case KEY_ACTIVATE:
	menu_set_active_item(it->menu_handle, it->choice);
	menu_set_position(it->menu_handle,
		      menu->y+item->y, menu->x+item->x+item->front_width+1);
	menu_form_popup(menu->parent_form, it->menu_handle);
	break;
    case KEY_NEXT_OPTION:
	if (it->choice < it->max_choice)
	{
	    itemtype_popup_render(menu, item, MENUATTR_HILITE);
	    it->choice++;
	    itemtype_popup_render(menu, item, MENUATTR_HILITE);
	}
	break;	    
    case KEY_PREV_OPTION:
	if (it->choice > 0)
	{
	    itemtype_popup_render(menu, item, MENUATTR_HILITE);
	    it->choice--;
	    itemtype_popup_render(menu, item, MENUATTR_HILITE);
	}
	break;	    
    default:
	return;
    }
}

void itemtype_popup_save(menu_t *menu, item_t *item)
{
    struct popup_item *it = (struct popup_item *)item;
    if (it->save_hook)
	it->save_hook(it->hook_user_data, &it->entries[it->choice]);
}

void itemtype_popup_load(menu_t *menu, item_t *item)
{
    struct popup_item *it = (struct popup_item *)item;
    if (it->load_hook)
    {
	int i = it->load_hook(it->hook_user_data, it->entries);
	if (i != -1) it->choice = i;
    }
    item->f_save = itemtype_popup_save;
    item->f_load = 0;
}


static void item_func(item_t *item, void *param1, int param2)
{
    *(int *)param1 = param2;
}

item_t *itemtype_popup_alloc(menu_t *menu, va_list args)
{
    menu_t
	*popup;
    item_t
	*newitem;
    popup_entry_t
	*e;
    int 
	i,
	maximum_width = 0,
	m;
	
    struct popup_item 
	*item = (struct popup_item *)malloc(sizeof(struct popup_item) + MAX_POPUP_STRING * MAX_POPUP_SIZE );
    
    if (!item) return NULL;
    menu_item_init(&item->item);

    item->display_text   = va_arg(args, char *);
    item->choice         = va_arg(args, int);
    item->hook_user_data = va_arg(args, void *);
    item->save_hook      = va_arg(args, void *);
    item->load_hook      = va_arg(args, void *);
    item->entries        = va_arg(args, popup_entry_t*);
    
    popup =  new_menu(MENUTYPE_POPUP, NULL, menu->parent_form, NULL);

    i=0;
    e = item->entries;
    do
    {
	if (e->display_text == NULL) break;
	m = strlen(e->display_text);
	if (m > maximum_width) maximum_width = m;
	newitem = menu_item_create(ITEMTYPE_FUNC, popup, e->display_text, item_func, &(item->choice),i);
	i++;
	e++;
    } while (1);
    
    item->max_choice    = i-1;

    item->menu_handle   = popup;

    item->item.f_render = itemtype_popup_render;
    item->item.f_save   = 0;
    item->item.f_invoke = itemtype_popup_invoke;
    item->item.f_load   = itemtype_popup_load;

    item->item.w            = item->item.front_width = strlen(item->display_text);
    item->item.back_width   = maximum_width;
    item->item.h            = 1;
    item->item.disabled     = false;

    return (item_t *)item;
}
