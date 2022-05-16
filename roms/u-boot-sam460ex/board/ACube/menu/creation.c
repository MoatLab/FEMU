#include "menu.h"
#include <stdarg.h>
#include <malloc.h>
#include "func_items.h"
#include "popup_items.h"
#include "string_items.h"
#include "label_items.h"

#define SINGLE_BOX 0
#define DOUBLE_BOX 1

/* -- Forms -- */
form_t *new_form(char *title)
{
	form_t *form = (form_t *)malloc(sizeof(form_t));
	if (form)
	{
		memset(form, 0, sizeof(form_t));
		form->form_title = title;
		list_init(& form->menu_list);
	}
	return form;
}

void menu_form_set_menu(form_t *form, menu_t *menu)
{
	item_t *item = (item_t *)(menu->item_list.first);
	while (item)
	{
		if (item->f_load) item->f_load(menu, item);
		item = (item_t *)(item->link.next);
	}

	form->current_menu = menu;
	menu_draw_form(form);
}

void menu_form_add_menu(form_t *form, menu_t *menu)
{
	list_add(&(form->menu_list), (node_t *)menu);
}

menu_t* menu_form_find_menu(form_t *form, char *name)
{
	node_t *n;
	n = form->menu_list.first;
	while (n)
	{
		if (strcmp(name, ((menu_t *)n)->menu_title) == 0)
			return (menu_t *)n;
		n = n->next;
	}
	return NULL;
}

/* -- Menus -- */
menu_t *new_menu(int type, char *title, form_t *parent, char *parent_menu)
{
	menu_t *menu = (menu_t *)malloc(sizeof(menu_t));
	if (menu)
	{
		menu->type         = type;
		menu->menu_title   = title;
		menu->parent_form  = parent;
		menu->x = menu->y  = 0;
		menu->w = menu->h  = 0;
		menu->needs_layout = true;
		menu->item_spacing = 1;
		menu->parent_menu  = parent_menu;
		menu->current_item = NULL;
		list_init(&(menu->item_list));
	}
	return menu;
}

void menu_set_position(menu_t *menu, int line, int col)
{
	if (menu)
	{
		menu->x = col;
		menu->y = line;
	}
}

void menu_add_item(menu_t *menu, item_t *item)
{
	list_add(&(menu->item_list), (node_t *)item);
	menu->needs_layout = true;
}

/* Items */

typedef struct
{
	int type;
	item_t * (*create)(menu_t *, va_list);
} itemtype_t;


itemtype_t item_types_templates[] =
{
	//{ ITEMTYPE_BOOL_CVAR, itemtype_bool_cvar_alloc },
	{ ITEMTYPE_FUNC, itemtype_func_alloc },
	{ ITEMTYPE_SUBMENU, itemtype_submenu_alloc },
	{ ITEMTYPE_POPUP, itemtype_popup_alloc },
	{ ITEMTYPE_STRING_CVAR, itemtype_string_cvar_alloc },
	{ ITEMTYPE_LABEL, itemtype_label_alloc },
	//{ ITEMTYPE_NUMERIC, itemtype_numeric_alloc },
	//{ ITEMTYPE_REGISTER, itemtype_register_alloc },
};

itemtype_t item_types[10];


#define NUM_ITEMTYPES (sizeof(item_types) / sizeof(itemtype_t))

void menu_item_relocate(unsigned long offset)
{
	int i;
	for (i=0; i<NUM_ITEMTYPES; i++)
	{
		item_types[i].type = item_types_templates[i].type;
		item_types[i].create =
			(item_t * (*)(menu_t *, va_list)) ((unsigned char *)item_types_templates[i].create); // - offset);
	}
}

item_t *menu_item_create(int type, menu_t *menu, ...)
{
	va_list args;
	int i;
	item_t *new_item;

	for (i=0; i<NUM_ITEMTYPES; i++)
	{
		if (item_types[i].type == type)
		{
			va_start(args, menu);
			new_item = item_types[i].create(menu, args);
			va_end(args);
			if (menu)
			{
				menu_add_item(menu, new_item);
			}
			return new_item;
		}
	}

	return NULL;
}

void menu_item_init(item_t *item)
{
	item->disabled = false;
	item->break_after = false;
	item->help_text = NULL;
}

void menu_item_break_after(item_t *item)
{
	if (item) item->break_after = true;
}

void menu_item_set_help(item_t *item, char *help_string)
{
	if (item)
		item->help_text = help_string;
}
