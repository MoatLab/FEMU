#ifndef MENU_H
#define MENU_H

#ifdef SIM
#include <stdlib.h>
#else
#include <common.h>
#endif

#include "list.h"

#ifdef SIM
#define GETENV(x) getenv(x)
#define SETENV(x,y) setenv(x,y,1)
#else
#define GETENV(x) getenv(x)
#define SETENV(x,y) setenv(x,y)
#endif

#ifndef NULL
#define NULL ((void *)0L)
#endif

/* Menu attributes */
#define MENUATTR_NORMAL   0     /* Attribute used by standard menus */
#define MENUATTR_ITEM     1     /* Attribute for menu items (normal) */
#define MENUATTR_HILITE   2     /* Attribute for highlighted menu items */
#define MENUATTR_DISABLED 3     /* Attribute for disabled menu items */

#ifndef bool_defined
#define bool_defined
typedef int bool;
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define MAX_MENUS 30

#define KEY_NONE        0      /* No or false key pressed */
#define KEY_NEXT_OPTION 1      /* Page Down, Arrow right */
#define KEY_PREV_OPTION 2      /* Page Up, Arrow left */
#define KEY_NEXT_ITEM   3      /* Arrow down */
#define KEY_PREV_ITEM   4      /* Arrow up */
#define KEY_ABORT       5      /* ESC */
#define KEY_ACTIVATE    6      /* Return */
#define KEY_DELETE      7      /* Backspace */
#define KEY_F1			8

#define EXIT_AND_SAVE     0
#define EXIT_AND_NO_SAVE  1
#define EXIT_NOT          2
#define EXIT_SAVE_PERMANENT 3
#define EXIT_TO_SHELL		4


#define SINGLE_BOX 0
#define DOUBLE_BOX 1

#ifdef SIM
#include "sim.h"
#endif

struct item_s;
struct menu_s;

typedef void (*load_func)(struct menu_s *menu, struct item_s *item);
typedef void (*save_func)(struct menu_s *menu, struct item_s *item);
typedef void (*render_func)(struct menu_s *menu, struct item_s *item, int state);
typedef void (*invoke_func)(struct menu_s *menu, struct item_s *item, int key);

typedef struct item_s
{
    node_t link;                  /* Link for chaining */
    int x,y;                      /* Position */
    int w,h;                      /* Size */
    char *help_text;              /* Help text do display */
    int front_width;              /* Width of front display matter */
    int back_width;               /* Width of option data or 0 */
    bool disabled;                /* Wether this item is active or disabled */
    bool break_after;             /* After this item break to next column */
    load_func   f_load;           /* Functio to load the setting */
    render_func f_render;         /* Function to render contents */
    save_func   f_save;           /* Function to save the setting */
    invoke_func f_invoke;         /* Function to handle key event */
} item_t;


#define MENUTYPE_FORM  1            /* Form-integrated menu */
#define MENUTYPE_POPUP 2            /* Popup menu (drawing differs) */

typedef struct menu_s
{
    node_t link;
    char *menu_title;             /* Title of the menu */
    int type;                     /* Type of menu */
    bool two_colums;              /* True for two-column menus */
    int x,y,w,h;                  /* Coordinates and extends */
    void *user_data;              /* User data of menu */
    bool needs_layout;
    int item_spacing;
    item_t *current_item;         /* current item */
    mylist_t item_list;

    char *parent_menu;            /* Where to return when ESC is pressed */
    struct form_s *parent_form;   /* Form where this is currently being displayed */
} menu_t;

typedef struct form_s
{
    char *form_title;             /* Title of the form */
    menu_t *current_menu;         /* Menu that is active */
    menu_t *popup_save;           /* Backup when popup is active */
    item_t *popup_item_save;      /* Backup which item was active */

    int menu_stack_ptr;           /* Stack pointer */
    menu_t *menu_stack[MAX_MENUS];/* Previous menus */

    mylist_t menu_list;
} form_t;

void menu_draw_current_form(void);
void menu_init(void);
void menu_set_active_item(menu_t *menu, int nr);
void menu_draw_form(form_t *form);
void menu_form_switch_menu(form_t *form, char *name);
void menu_form_popup(form_t *form, menu_t* menu);

/* Utility functions */


void leave_func(item_t *item, void *dummy, int arg);
void menu_draw_help(item_t *item);
void menu_set_form(form_t *form);
void menu_do(bool do_leave_menu);


/* Item types */

/*
 * Item: Boolean from a console var
 * Creation args:
 *   (char *)   display name
 *   (char *)   variable name
 *   (char *)   positive text ("yes", "true", "enabled", "on")
 *   (char *)   negative text ("no", "false", "disabled", "off")
 *   int        default if unset (0=negative, !0=positive)
 */
//#define ITEMTYPE_BOOL_CVAR    0

/*
 * Item: Invoke-a-function item
 * Creation args:
 *   (char *)               display name
 *   (void *)(item_t *, void *, int)
 *                          Function to invoke
 *   (void *)               First parameter to be passed
 *   int                    Second parameter to be passed
 */
#define ITEMTYPE_FUNC         1

/*
 * Item: Submenu
 * Creation args:
 *   (char *)              display name
 *   (char *)              menu to change to
 */
#define ITEMTYPE_SUBMENU      2

/*
 * Item: Popup Choice
 * Creation args:
 *    (char *)             display name
 *    int                  default choice
 *    (void *)             hook user data.
 *    (void *)             Save hook. See below
 *    (void *)             Load hook. See below
 *    (popup_entry_t *)    pointer to an array of popup_entry structures.
 *                         Terminate with all entries set to NULL.
 *
 * Save/Load hook:
 * Thes functions are called whenever the item needs to be loaded or saved.
 * The prototypes are:
 *
 * int  load(void *user_data, popup_entry_t *entries);
 * void save(void *user_data, popup_entry_t *selected);
 *
 * Load: The function is invoked with the third creation argument (user data) and
 * a pointer to the popup_entry** specified as the sixth argument. It should
 * return the index of the entry that would become the selected/active entry.
 *
 * Save: The function is invoked with the user data and a pointer to the selected
 * entry in the popup. It should save the value to an appropriate place, e.g.
 * an environment variable.
 *
 */
#define ITEMTYPE_POPUP        3

typedef struct _popup_entry
{
    char *display_text;           /* What the entry should display */
    char *value_text;             /* What the entry should represent. For the hooks only */
    void *user_data;              /* Additional hook user data. Use as you wish */
} popup_entry_t;


/*
 * Item: String from a console variable
 * Creation args:
 *    (char *)              display name
 *    (char *)              variable name
 *    (char *)              default if unset
 */
#define ITEMTYPE_STRING_CVAR  4

/*
 * Item: Unselectable label
 * Creatation args:
 *    (char *)              display name
 */
#define ITEMTYPE_LABEL        5

/*
 * Item: Numerical value editor
 * Creation args:
 *    (char *)              display name
 *    (int)                 default value
 *    (int)                 stepping rate
 *    (int)                 lower bound
 *    (int)                 upper bound
 *    (int)                 0=decimal, 1=hex
 *    (void *)              load hook (see below)
 *    (void *)              save hook (see below)
 *    (void *)              param 1 for hooks
 *    int                   param 2 for hooks
 *
 * Hooks work similar to popup types. The prototype for the hooks is
 * int load(void *param1, int param2, int default);
 * void save(void *param1, int param2, int value);
 * If load is unable to load, it should return default.
 */
//#define ITEMTYPE_NUMERIC      6

/*
 * Item: Configuration register editor
 * Creation args:
 *    (char *)              Display name
 *    (void *)              register descriptor pointer (see below)
 */
//#define ITEMTYPE_REGISTER       7
/*
typedef struct
{
    char *register_name;
    int config_offset;
    int config_type;
    int value_type;
    int bus;
    int devfn;
    void *menu_page;
} articia_register_t;

typedef struct
{
    char *title;
    articia_register_t *registers;
} articia_menu_page_t;

enum
{
    CONFIG_DWORD = 0, CONFIG_WORD = 1, CONFIG_BYTE = 2, TYPE_HEX = 0, TYPE_DEC = 1
};
*/
#endif
