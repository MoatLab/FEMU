#include "menu.h"
#include "bios_menu.h" //For boot_seq.
#include "bootselect_menu.h"
#include "creation.h"

int return_value = 0;

int cvar_numeric_load(void *user_data, int param2, int def_val);
void cvar_popup_save(void *user_data, popup_entry_t *entry);
int cvar_popup_load(void *user_data, popup_entry_t *entries);

#define LABEL(x) menu_item_create(ITEMTYPE_LABEL, menu, #x)
#define SPACER menu_item_create(ITEMTYPE_LABEL, menu, " ")

#define BOOT_MENU_NAME "U-Boot Boot Select"
#define EXIT_MENU_NAME "Exit Menu"

#define EXIT_BOOT_CONFIG 	0
#define EXIT_BOOT_NOCONFIG  1
#define EXIT_GO_MENU		2

void my_leave_func(item_t *item, void *dummy, int arg)
{
	setenv("boot2", "");
	setenv("boot3", "");

	switch (arg)
	{
		case EXIT_BOOT_CONFIG:
			return_value = 0;
			leave_func(item, dummy, EXIT_AND_SAVE);
			break;
		case EXIT_BOOT_NOCONFIG:
			return_value = 0;
			leave_func(item, dummy, EXIT_AND_NO_SAVE);
			break;
		case EXIT_GO_MENU:
			return_value = 1;
			leave_func(item, dummy, EXIT_AND_NO_SAVE);
			break;
	}
}

void make_bootselect_menu(form_t *form)
{
	item_t *item;
	menu_t *menu;

	// Boot Select //

	menu = new_menu(MENUTYPE_FORM, BOOT_MENU_NAME, form, 0);

	item = menu_item_create(ITEMTYPE_POPUP, menu,
				"Boot Device", 0, "boot1",
				cvar_popup_save, cvar_popup_load, boot_seq); //TEST_ITEM();

	menu_item_set_help(item, "Choose which boot device should be attempted first");

	SPACER;
	item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
							"Boot arguments for AOS", "os4_commandline", "debuglevel=0"); //TEST_ITEM();
	menu_item_set_help(item, "Argument string to be passed to AOS");
		
	item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
							"Boot arguments for Linux", "bootargs", "root=/dev/Sda3"); //TEST_ITEM();
	menu_item_set_help(item, "Argument string to be passed to Linux");

	SPACER;
	
	menu_form_add_menu(form, menu);

	// Exit //
	menu = new_menu(MENUTYPE_POPUP, EXIT_MENU_NAME, form, 0);

	item = menu_item_create(ITEMTYPE_FUNC, menu, "Boot this configuration", my_leave_func, NULL, EXIT_BOOT_CONFIG);
	menu_item_set_help(item, "Temporarily boot this configuration");
	item = menu_item_create(ITEMTYPE_FUNC, menu, "Go to preferences menu", my_leave_func, NULL, EXIT_GO_MENU);
	menu_item_set_help(item, "Abort the changes and go to the preferences menu");
	item = menu_item_create(ITEMTYPE_FUNC, menu, "Continue normal boot", my_leave_func, NULL, EXIT_BOOT_NOCONFIG);
	menu_item_set_help(item, "Abort the changes and continue booting the normal configuration");
    menu_set_position(menu, 6, 6);

	menu_form_add_menu(form, menu);
}

void boot_establish(void)
{
	char *bootfinal = "";
	char *b1 = "boota";
	char *mboot = getenv("menuboot_cmd");
	char *method = getenv("boot_method");
	char *bootcommand = getenv("boot_command");
	
	if (method == NULL) method="boota";

	if (mboot && strncmp(mboot, "noboot", 6) == 0)
	{
		setenv("menuboot_cmd", " ");
		return;
	}
	
	if (strcmp(method, "boota") == 0)
	{
		bootfinal = b1;
	}
	else
	{
		bootfinal = bootcommand;
	}

	setenv("menuboot_cmd", bootfinal);	
}
