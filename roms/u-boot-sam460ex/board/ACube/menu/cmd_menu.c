#include <common.h>
#include <command.h>
#include "menu.h"
#include "bootselect_menu.h"
#include "creation.h"
#include "bios_menu.h"
#include <asm/processor.h>

static form_t *root = 0;
static form_t *bootselect = 0;

#define MAIN_MENU_NAME "U-BOOT Preferences Menu"
#define BOOT_MENU_NAME "U-Boot Boot Select"

static void establish_menu_settings(void);
static int do_menu_countdown(void);
static int fromsilent = 0;

DECLARE_GLOBAL_DATA_PTR;

int show_and_do_boot_select(void)
{
	unsigned long delta = TEXT_BASE - gd->relocaddr;
	
	menu_item_relocate(delta); 

	bootselect = new_form(BOOT_MENU_NAME);
	if (!bootselect) return 0;

	make_bootselect_menu(bootselect);
	menu_set_form(bootselect);
	menu_form_switch_menu(bootselect, BOOT_MENU_NAME);
	menu_do(false);

   	return return_value;
}

void show_and_do_bios_menu(void)
{
	unsigned long delta = TEXT_BASE - gd->relocaddr;
	
	menu_item_relocate(delta);
    
    root = new_form("U-BOOT Setup Menu");  
    if (!root) return;
	
	make_menus(root);
    menu_set_form(root);
    menu_form_switch_menu(root, MAIN_MENU_NAME);
    menu_do(true);
}

static int do_menu_countdown(void)
{
	int bootdelay;
	int current;
	char *s, c;

	bootdelay = 0;
	s = GETENV("menuboot_delay");

	if (s) bootdelay = atoi(s);

	if (bootdelay == 0)
	{
		if (tstc() != -1) return 1;
		else return 0;
	}

    putc('\n');
    if (fromsilent) puts("                ");
	puts("Press SPACE for prefs, ENTER for boot select, ESC for prompt\n");
	if (fromsilent) puts("                ");
	puts("Booting...   ");

	current = 0;
	while (current < bootdelay)
	{
		int i;

		printf("\b\b\b%2d ", bootdelay - current);

		for (i=0; i<1000; i++)
		{
			if (tstc())
			{
				c = getc();
				
				// ESC
				if ((c == 5) || (c == 113)) return -10;
				
				// ENTER
				if (c == 13) return show_and_do_boot_select();
				
				// SPACE
				if (c == 32) return 1;
			}
			udelay(1000);
		}
		current++;
	}

	return 0;
}

extern u32 *fb_base_phys;
extern u32 *fb_base_phys_sm502;

int do_menu( cmd_tbl_t *cmdtp, int flag, int argc, char *argv[] )
{
	int ret = 0;

    // if console was silent, revert it back
	if (gd->flags & GD_FLG_SILENT) {
	    fromsilent = 1;
	    gd->flags &= ~GD_FLG_SILENT;
	}
	
	// only if there is an active vga -------------------------------
#ifdef CONFIG_SAM440EP
	if (fb_base_phys)
#else
	if ((fb_base_phys) || (fb_base_phys_sm502))
#endif
	{
		if (flag==0)
		{
			video_set_color(0);
	  		show_and_do_bios_menu();
		    puts("\n");
		    video_set_color(0);  		
	  		return 0;	
		}
		else
		{
			ret = do_menu_countdown();
			
			if (ret == -10) 
			{
			    puts("\b\b\b break..\n");
			    setenv("menuboot_cmd", " ");
				return 0;
			}
				
			if (ret == 1)
			{
				video_set_color(0);
		  		show_and_do_bios_menu();
			}
		
			video_clear_attr();
		    establish_menu_settings();
		    puts("\n");
		    video_set_color(0);
		    return 0;
	    }
    }
    else return -1;
}

/*
 * This routine establishes all settings from the menu that aren't already done
 * by the standard setup.
 */

static void establish_menu_settings(void)
{
	boot_establish();
	
}
	   
U_BOOT_CMD(
	   menu,    1,    1,     do_menu,
	   "Show preferences menu",
	   "Show the preferences menu that is used to boot an OS\n"
	   );
