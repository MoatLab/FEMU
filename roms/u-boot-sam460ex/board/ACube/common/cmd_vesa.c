#include <common.h>
#include <command.h>
#include <asm/cache.h>
#include "sys_dep.h"
#include "vesa.h"

int do_vesa(cmd_tbl_t * cmdtp, int flag, int argc, char *argv[])
{
  DECLARE_GLOBAL_DATA_PTR;
  	DoVesa(argc, argv);
  return 0;
}

U_BOOT_CMD(
	vesa,    5,     1,     do_vesa,
	"vesa    - run a vesa bios call\n",
	"mode"
);
