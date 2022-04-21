#include "menu.h"
#include "creation.h"
#include "layout.h"
#include "list.h"

form_t *root_form = 0;

void menu_set_form(form_t *form)
{
	root_form = form;
}

void menu_draw_help(item_t *item)
{
	char
		buffer[80*4],
		*p_text,
		*p_break,
		*p_start;

	int
		line = 20;

	bool in_word=true;

	if (!item) return;

	video_clear_box(1,20,78,4,' ',MENUATTR_NORMAL);

	if (item->help_text)
	{
		/* Reformat help so that it word-wraps */
		buffer[0] = 0;

		strcpy(buffer, item->help_text);

		p_text  = p_break = p_start = buffer;
		in_word = true;

		for (;;) 
		{
			if (*p_text == ' ' && in_word == true)
			{
				in_word = false;
				p_break = p_text;
			}
			else if (*p_text != ' ')
			{
				in_word = true;
			}
			if ((p_text - p_start >= 72) || *p_text == 0) // flush
			{
				if (*p_text == '\0') p_break = p_text;
				*p_break = 0;
				video_draw_text(2,line++, MENUATTR_NORMAL, p_start, -1);
				if (*p_text == '\0') return;
				p_break++;
				while (p_break < p_text && *p_break == ' ')
				{
					p_break++;
				}
				p_start = p_break;
				if (*p_break == '\0') return;
			}
			else p_text++;
		}
	}
}

void menu_draw(menu_t *menu)
{
	if (menu && menu->needs_layout)
	{
		menu_layout(menu);
	}
	if (menu)
	{
		item_t *item = (item_t *)(menu->item_list.first);

		if (menu->type == MENUTYPE_POPUP)
		{
			video_clear_box(menu->x-1, menu->y-1, menu->w, menu->h, ' ', MENUATTR_NORMAL);
		}

		while (item)
		{
			item->f_render(menu, item,
						   (item->disabled==true)?MENUATTR_DISABLED:
						   (item == menu->current_item)?MENUATTR_HILITE : MENUATTR_ITEM);
			item = (item_t *)(item->link.next);
		}
		if (menu->type == MENUTYPE_FORM)
		{
			menu_draw_help(menu->current_item);
		}
		else
		{
			video_draw_box(SINGLE_BOX, MENUATTR_NORMAL, NULL, 0, menu->x-1, menu->y-1,
						   menu->w+2, menu->h+3);
		}
	}
}

void menu_draw_form(form_t *form)
{
	char 
		*title;
	menu_t 
		*menu = form->current_menu;

	/* Prefer current menu title if set, otherwise use the form title */
	if (menu && menu->menu_title) title = menu->menu_title;
	else if (form->form_title) title = form->form_title;
	else title = NULL; //"Untitled";

	video_draw_box(SINGLE_BOX, MENUATTR_NORMAL, title, 1, 0,0, 80, 19);
	video_draw_box(SINGLE_BOX, MENUATTR_NORMAL, NULL, 0, 0, 19, 80, 6);

	/* If we have a menu, draw it too */
	if (menu)
	{
		video_clear_box(1, 3, 78, 15, ' ', MENUATTR_NORMAL);
		menu_draw(menu);
	}
}

void menu_draw_current_form(void)
{
	menu_draw_form(root_form);
}

void menu_form_switch_menu(form_t *form, char *name)
{
	menu_t *menu = menu_form_find_menu(form, name);
	if (!menu) 
		return;
	menu_form_set_menu(form, menu);
}

void menu_form_popup(form_t *form, menu_t* menu)
{
	if (menu && MENUTYPE_POPUP == menu->type)
	{
		form->popup_save = form->current_menu;
		form->popup_item_save = form->current_menu->current_item;
		form->current_menu = menu;
		menu_draw(menu);
	}
}

void menu_form_popup_name(form_t *form, char *name)
{
	menu_t *menu = menu_form_find_menu(form, name);
	if (!menu) 
		return;
	menu_form_popup(form, menu);
}

void menu_form_popdown(form_t *form)
{
	if (form->current_menu && form->current_menu->type == MENUTYPE_POPUP)
	{
		form->current_menu = form->popup_save;
		if (form->current_menu)
			form->current_menu->current_item = form->popup_item_save;
		video_clear_box(1, 3, 78, 15, ' ', MENUATTR_NORMAL);
		if (form->current_menu) 
			menu_draw(form->current_menu);
	}
}

void menu_set_active_item(menu_t *menu, int nr)
{
	item_t
		*item = (item_t *)(menu->item_list.first);
		
	while (item && nr > 0)
	{
		nr--;
		item = (item_t *)(item->link.next);
	}
	if (nr == 0)  
	{
		menu->current_item = item;
	}
}

static void menu_perform_save(form_t *form)
{
	menu_t
		*menu;

	menu = (menu_t *)(form->menu_list.first);
	while (menu)
	{
		item_t
			*item;

		item = (item_t *)(menu->item_list.first);
		while (item)
		{
			if (item->f_save) item->f_save(menu, item);
			item = (item_t *)(item->link.next);
		}
		menu = (menu_t *)(menu->link.next);
	}
}

static int leave_select = -1;

void leave_func(item_t *item, void *dummy, int arg)
{
	leave_select = arg;
}

menu_t *make_leave_menu(form_t *form)
{
	menu_t
		*menu = new_menu(MENUTYPE_POPUP, "Exit Menu", form, NULL);

	if (menu)
	{
		item_t
			*item;
		item = menu_item_create(ITEMTYPE_FUNC, menu, "Save settings and exit", leave_func, NULL, EXIT_SAVE_PERMANENT);
		item = menu_item_create(ITEMTYPE_FUNC, menu, "Use settings for this session only", leave_func, NULL, EXIT_AND_SAVE);
		item = menu_item_create(ITEMTYPE_FUNC, menu, "Leave without saving", leave_func, NULL, EXIT_AND_NO_SAVE);
		//item = menu_item_create(ITEMTYPE_FUNC, menu, "Return to menu", leave_func, NULL, EXIT_NOT);
		item = menu_item_create(ITEMTYPE_FUNC, menu, "Abort boot and enter U-Boot shell", leave_func, NULL, EXIT_TO_SHELL);
	}

	menu_form_add_menu(form, menu);

	menu_set_position(menu, 6, 6);

	return menu;
}
		

bool menu_handle_single_key(form_t *form, int key)
{
	/* 
	   Keys below 10 or so are specially mapped by us to mean one of the functions
	   of the menu system (like next item, prev item etc). All other keys are verbatim
	   keypresses that might be needed for e.g. string entry 
	*/
	item_t 
				*c_item,
				*n_item;
	menu_t
				*menu = form->current_menu;

	switch(key)
	{
		case KEY_NEXT_ITEM:
			/* Move one item forward */
			c_item = menu->current_item;
			n_item = (item_t *)(c_item->link.next);
			while (n_item && n_item->disabled == true)
			{
				n_item = (item_t *)(n_item->link.next);
			}

			if (n_item)
			{
				/* redraw the old item un-highlit */
				c_item->f_render(menu, c_item, MENUATTR_ITEM);
				n_item->f_render(menu, n_item, MENUATTR_HILITE);
				menu_draw_help(n_item);
				menu->current_item = n_item;
			}
			break;
		case KEY_PREV_ITEM:
			/* Move one item backward */
			c_item = menu->current_item;
			n_item = (item_t *)(c_item->link.prev);
			while (n_item && n_item->disabled == true)
			{
				n_item = (item_t *)(n_item->link.prev);
			}
			if (n_item)
			{
				/* redraw the old item un-highlit */
				c_item->f_render(menu, c_item, MENUATTR_ITEM);
				n_item->f_render(menu, n_item, MENUATTR_HILITE);
				menu_draw_help(n_item);
				menu->current_item = n_item;
			}
			break;
		case KEY_ABORT:
			if (menu->type == MENUTYPE_POPUP)
			{
				menu_form_popdown(form);
			}
			else
			{
				if (menu->parent_menu)
				{
					menu_form_switch_menu(menu->parent_form, menu->parent_menu);
				}
				else
				{
					/* TODO: Implement exit from menu */
					menu_form_popup_name(root_form, "Exit Menu");
					return true;
				}
			}
			break;
		default:
			if (menu->current_item)
			{
				menu->current_item->f_invoke(menu, menu->current_item, key);
			}
			if (key == KEY_ACTIVATE && menu->type == MENUTYPE_POPUP)
			{
				menu_form_popdown(form);
				/* Check if we want to exit */
				if (leave_select != -1)
				{
					switch(leave_select)
					{
						case EXIT_AND_NO_SAVE:
							return false;
						case EXIT_SAVE_PERMANENT:
							menu_perform_save(form);
#ifndef SIM
							saveenv();
#endif
							return false;
						case EXIT_AND_SAVE:
							menu_perform_save(form);
							return false;
						case EXIT_NOT:
							return true;
						case EXIT_TO_SHELL:
							{
								char *mboot = getenv("menuboot_cmd");
								if ((mboot) && (strlen(mboot)>2)) SETENV("menuboot_cmd", "noboot");
								else SETENV("menuboot_cmd", "boota");
								return false;
							}
					}
				}
			}
			break;
	}

	return true;
}


void menu_do(bool do_leave_menu)
{
	bool running=true;
	int key;

	running = true;
	leave_select = -1;

	if (do_leave_menu)
		make_leave_menu(root_form);

	if (root_form)
	{
		menu_draw_form(root_form);

		while (running)
		{
			key = video_get_key();
			running = menu_handle_single_key(root_form, key);
		}
	}
}

