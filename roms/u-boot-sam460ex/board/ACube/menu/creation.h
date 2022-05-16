#ifndef CREATION_H
#define CREATION_H

form_t *new_form(char *title);
void menu_form_set_menu(form_t *form, menu_t *menu);
void menu_item_relocate(unsigned long offset);
void menu_form_add_menu(form_t *form, menu_t *menu);
menu_t* menu_form_find_menu(form_t *form, char *name);
menu_t *new_menu(int type, char *title, form_t *parent, char *parent_menu);
void menu_set_position(menu_t *menu, int line, int col);
void menu_add_item(menu_t *menu, item_t *item);

item_t* menu_item_create(int type, menu_t *menu, ...);
void menu_item_set_help(item_t *item, char *help_string);
void menu_item_init(item_t *item);
void menu_item_break_after(item_t *item);
void *mymalloc(size_t size);

#endif // CREATION_H

