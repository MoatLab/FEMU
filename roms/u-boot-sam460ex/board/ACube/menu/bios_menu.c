#include "menu.h"
#include "bios_menu.h"
#include "creation.h"

/*
 * These hooks are for usage with popup menus. Assumes that user_data is the name of
 * the variable to save to / load from.
 *
 * entries is the array of entries that may fit. This function returns -1 if none
 * of the entries fits, indicating that the default should be considered.
 */

int cvar_popup_load(void *user_data, popup_entry_t *entries)
{
	char
		*var = GETENV((char *)user_data);
	int
		i=0;

	while (var && entries->value_text)
	{
		if (entries->value_text != (char *)(~0) && (strcmp(var, entries->value_text) == 0))
		{
			return i;
		}
		i++;
		entries++;
	}

	return -1;
}

void cvar_popup_save(void *user_data, popup_entry_t *entry)
{
	SETENV((char *)user_data, entry->value_text);
}

int cvar_numeric_load(void *user_data, int param2, int def_val)
{
	char *var = GETENV((char *)user_data);
	
	if (var) return atoi(var);
	else return def_val;
}

static void cvar_numeric_save(void *user_data, int param2, int value)
{
	char buffer[30];
	sprintf(buffer, "%d", value);
	SETENV((char *)user_data, buffer);
}

#define TABLE_END {NULL, NULL, NULL}
#define LABEL(x) menu_item_create(ITEMTYPE_LABEL, menu, #x)
#define SPACER menu_item_create(ITEMTYPE_LABEL, menu, " ")

#define MAIN_MENU_NAME 		"U-BOOT Preferences Menu"
#ifdef CONFIG_SAM460EX
#define PCIE_SATA_NAME		"PCI-E 1x / SATA-2"
#endif
#define BOOTSEQ_NAME 		"Boot Sequence"
#define NETBOOT_NAME 		"Network Boot Options"
#define SYSTEM_INFO_NAME 	"System Information"
#define AMIGABOOT_NAME 		"OS MultiBoot Options"
#define VIDEO_NAME			"Video Options"


/**************************************************************************************
			  MAIN MENU
 *************************************************************************************/

menu_t *make_main_menu(form_t *form)
{
	menu_t
		*menu = new_menu(MENUTYPE_FORM, MAIN_MENU_NAME, form, NULL);

	if (menu)
	{
		item_t *item;

		item = menu_item_create(ITEMTYPE_SUBMENU, menu,
			"Video Options", VIDEO_NAME); //TEST_ITEM();
		menu_item_set_help(item, "Select the current video card");

#ifdef CONFIG_SAM460EX
		item = menu_item_create(ITEMTYPE_SUBMENU, menu, 
			"PCI-E 1x / SATA-2", PCIE_SATA_NAME); //TEST_ITEM();
		menu_item_set_help(item, "Select PCI-E 1x / SATA-2");
#endif

		item = menu_item_create(ITEMTYPE_SUBMENU, menu, 
			"Boot Sequence", BOOTSEQ_NAME); //TEST_ITEM();
		menu_item_set_help(item, "Adjust parameters for booting an OS");

		item = menu_item_create(ITEMTYPE_SUBMENU, menu, 
			"System Information", SYSTEM_INFO_NAME); //TEST_ITEM();
		menu_item_set_help(item, "Information about the hardware installed on this machine");
		
	}
	menu_form_add_menu(form, menu);
	return menu;
}

/**************************************************************************************
			  PCI-E/SATA Menu
 *************************************************************************************/
#ifdef CONFIG_SAM460EX
popup_entry_t pcie_sata_select_entries[] =
{
	{"SATA-2",   "sata2", NULL},
	{"PCI-E 1x", "pci-e", NULL},	
	TABLE_END,
};

menu_t *make_pcie_sata_menu(form_t *form)
{
	menu_t *menu = new_menu(MENUTYPE_FORM, PCIE_SATA_NAME, form, MAIN_MENU_NAME);

	item_t
		*item;
		
	if (menu)
	{
		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Select PCI-E 1x / SATA-2", 0, "serdes",
								cvar_popup_save, cvar_popup_load,
								pcie_sata_select_entries); 
		menu_item_set_help(item, "Choose to acticate PCI-E 1x slot or the onchip "\
							     "SATA-2 port (requires reboot and changing J16 on motherboard)");
	}

	menu_form_add_menu(form, menu);
	return menu;
}
#endif

/**************************************************************************************
			  Video Menu
 *************************************************************************************/

popup_entry_t video_select_entries[] =
{
#if defined(CONFIG_SAM440EP_FLEX)
	{"PCI",       "pci",     NULL},
	{"SM502",     "sm502",   NULL},
#elif defined(CONFIG_SAM460EX)
	{"Onboard",   "sm502",   NULL},
	{"PCI/PCI-E", "pci",     NULL},
#else
	{"Internal", "internal", NULL},
	{"PCI", "pci", NULL},
#endif	
	TABLE_END,
};

popup_entry_t silent_select_entries[] =
{
	{"Verbose", "0", NULL},
	{"Silent",  "1", NULL},
	TABLE_END,
};

menu_t *make_video_menu(form_t *form)
{
	menu_t *menu = new_menu(MENUTYPE_FORM, VIDEO_NAME, form, MAIN_MENU_NAME);

	item_t
		*item;
		
	if (menu)
	{
		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Boot from graphics card", 0, "video_activate",
								cvar_popup_save, cvar_popup_load,
								video_select_entries); //TEST_ITEM();

#if defined(CONFIG_SAM440EP_FLEX)
		menu_item_set_help(item, "Choose whether the PCI ATI or the SM502 "\
							     "graphics card is activated (requires reboot)");
#elif defined(CONFIG_SAM460EX)								
		menu_item_set_help(item, "Choose whether the PCI/PCI-E or the onboard "\
							     "graphics card is activated (requires reboot)");
#else
		menu_item_set_help(item, "Choose whether the internal ATI M9 or a PCI "\
							     "graphics card is activated (requires reboot)");
#endif

		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Console", 2, "hush",
								cvar_popup_save, cvar_popup_load,
								silent_select_entries); 
		menu_item_set_help(item, "Suppress most console messages on the screen while booting");
	}

	menu_form_add_menu(form, menu);
	return menu;
}

/**************************************************************************************
			  Boot Sequence
 *************************************************************************************/

popup_entry_t boot_seq[] =
{
	{"0680 PATA HD",    "psii",       NULL},
	{"0680 PATA DVD",   "psiicdrom",  NULL},			
	{"3x12 SATA HD",    "ssii",       NULL},
	{"3x12 SATA DVD",   "ssiicdrom",  NULL},
	{"3114 SATA HD",    "s4sii",      NULL},
	{"3114 SATA DVD",   "s4siicdrom", NULL},
#ifdef CONFIG_SAM460EX
	{"460  SATA2 HD",   "sata2-460",  NULL},
#endif
	{"USB DVD",         "ucdrom", NULL},
	{"USB HD",          "usb",    NULL},
	{"Network",         "net",    NULL},
	{"none",            "",       NULL},
	TABLE_END,
};

menu_t *make_netboot_menu(form_t *form)
{
	menu_t
		*menu = new_menu(MENUTYPE_FORM, NETBOOT_NAME, form, BOOTSEQ_NAME);

	item_t
		*item;

	if (menu)
	{
		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"Local TCP/IP Address", "ipaddr", ""); //TEST_ITEM();
		menu_item_set_help(item, "Local TCP/IP address for network boot");

		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"Server TCP/IP Address", "serverip", ""); //TEST_ITEM();
		menu_item_set_help(item, "Server IP address. Server must be running a supported networking boot service");
	}

	menu_form_add_menu(form, menu);
	return menu;
}

menu_t *make_amigaboot_menu(form_t *form)
{
	menu_t
		*menu = new_menu(MENUTYPE_FORM, AMIGABOOT_NAME, form, BOOTSEQ_NAME);

	item_t
		*item;
	
	if (menu)
	{
		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Boot Device 1", 0, "boot1",
								cvar_popup_save, cvar_popup_load, boot_seq); //TEST_ITEM();
		menu_item_set_help(item, "Select first boot device");
		
		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Boot Device 2", 2, "boot2",
								cvar_popup_save, cvar_popup_load, boot_seq); //TEST_ITEM();
		menu_item_set_help(item, "Select second boot device");

		item = menu_item_create(ITEMTYPE_POPUP, menu,
								"Boot Device 3", 4, "boot3",
								cvar_popup_save, cvar_popup_load, boot_seq); //TEST_ITEM();
		menu_item_set_help(item, "Select third boot device");

		SPACER;

		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"OS Selection timeout", "boota_timeout", "3"); //TEST_ITEM();
		menu_item_set_help(item, "The amount of time the OS selection menu waits before booting");	

	}
	
	menu_form_add_menu(form, menu);
	return menu;
}

menu_t *make_boot_menu(form_t *form)
{
	menu_t 
		*menu = new_menu(MENUTYPE_FORM, BOOTSEQ_NAME, form, MAIN_MENU_NAME);

	item_t
		*item;

	if (menu)
	{
		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"Menu Boot delay", "menuboot_delay", "3");
		menu_item_set_help(item, "The amount of time the menu waits before continuing to boot");
		SPACER;
		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"Boot arguments for AOS", "os4_commandline", "debuglevel=0"); //TEST_ITEM();
		menu_item_set_help(item, "Argument string passed to AOS");
		
		item = menu_item_create(ITEMTYPE_STRING_CVAR, menu,
								"Boot arguments for Linux", "bootargs", "root=/dev/sda3"); //TEST_ITEM();
		menu_item_set_help(item, "Argument string passed to Linux");

		SPACER;
		item = menu_item_create(ITEMTYPE_SUBMENU, menu, 
			"Network Boot Options", NETBOOT_NAME); //TEST_ITEM();
		item = menu_item_create(ITEMTYPE_SUBMENU, menu, 
			"OS Multiboot Options", AMIGABOOT_NAME);	
	}

	menu_form_add_menu(form, menu);
	return menu;
}

/**************************************************************************************
			  System Information
 *************************************************************************************/
static void dummy(void)
{
}

char *mystrdup(char *src)
{
	int
		i = strlen(src)+1;
	
	char 
		*s = malloc(i);

	if (s)
	{
		strcpy(s, src);
	}

	return s;
}

menu_t *make_sysinfo_menu(form_t *form)
{
	char buffer[64];

	menu_t
		* menu = new_menu(MENUTYPE_FORM, SYSTEM_INFO_NAME, form, MAIN_MENU_NAME);

	item_t
		* item;

	int	cpu_pvr;


	sys_info_t
	        sysinfo;

	get_sys_info(&sysinfo);

	if (menu)
	{
		{
			DECLARE_GLOBAL_DATA_PTR;
			cpu_pvr  = get_pvr();

			switch((cpu_pvr&0xffff0000)>>16)
			{
#ifdef CONFIG_SAM460EX			
			case 0x1302:
			  sprintf (buffer, "CPU Type  : AMCC PowerPC 460ex Rev ");
			  switch (cpu_pvr&0xffff)
			    {
			    case 0x18a3:
			      strcat (buffer, "A");
			      break;
			    case 0x18a4:
			      strcat (buffer, "B");
			      break;
			    default:
			      strcat (buffer, "unknown");
			      break;
			    }
			  break;
#else
			case 0x4222:
			  sprintf (buffer, "CPU Type  : AMCC PowerPC 440ep Rev ");
			  switch (cpu_pvr&0xffff)
			    {
			    case 0x18d3:
			      strcat (buffer, "B");
			      break;
			    case 0x18d4:
			      strcat (buffer, "C");
			      break;
			    default:
			      strcat (buffer, "unknown");
			      break;
			    }
			  break;
#endif
			default:
			  sprintf(buffer, "Unknown: PVR 0x%08X", cpu_pvr);
			}

			sprintf(buffer, "%s / %ld MHz", buffer, gd->cpu_clk / 1000000);
			item = menu_item_create(ITEMTYPE_LABEL, menu, mystrdup(buffer));
			
			sprintf(buffer, "PLB freq  : %4ld MHz", sysinfo.freqPLB / 1000000);
			item = menu_item_create(ITEMTYPE_LABEL, menu, mystrdup(buffer));

#ifdef CONFIG_SAM460EX
			sprintf(buffer, "DDR2 freq : %4ld MHz", 2 * sysinfo.freqDDR / 1000000);
			item = menu_item_create(ITEMTYPE_LABEL, menu, mystrdup(buffer));
#else
			sprintf(buffer, "DDR freq  : %4ld MHz", 2 * sysinfo.freqPLB / 1000000);
			item = menu_item_create(ITEMTYPE_LABEL, menu, mystrdup(buffer));			 
#endif

			/**** DIMM BANK INFO ****/
			SPACER;
			item = menu_item_create(ITEMTYPE_LABEL, menu, "Memory");
			sprintf(buffer, "Total     : %ld MB", (gd->bd->bi_memsize) / 1024 / 1024);
			item = menu_item_create(ITEMTYPE_LABEL, menu, mystrdup(buffer));
		}
	}

	menu_form_add_menu(form, menu);
	return menu;
}

void restore_func(void)
{

}

void recover_func(void)
{

}

/* ********************************************************************************* */

void make_menus(form_t *form)
{
	make_video_menu(form);	
#ifdef CONFIG_SAM460EX	
	make_pcie_sata_menu(form);
#endif	
	make_main_menu(form);
	make_netboot_menu(form);
	make_amigaboot_menu(form);
	make_boot_menu(form);
	make_sysinfo_menu(form);
}
