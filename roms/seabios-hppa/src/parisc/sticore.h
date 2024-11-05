/* SPDX-License-Identifier:GPL-2.0 */
#ifndef STICORE_H
#define STICORE_H

#include "types.h"

/* generic STI structures & functions */

#define MAX_STI_ROMS 4          /* max no. of ROMs which this driver handles */

#define STI_REGION_MAX 8        /* hardcoded STI constants */
#define STI_DEV_NAME_LENGTH 32
#define STI_MONITOR_MAX 256

#define STI_FONT_HPROMAN8 1
#define STI_FONT_KANA8 2

#define ALT_CODE_TYPE_UNKNOWN 0x00      /* alt code type values */
#define ALT_CODE_TYPE_PA_RISC_64 0x01

#define STI_WAIT 1

/* STI function configuration structs */

typedef union region {
    struct {
        u32 offset:14;          /* offset in 4kbyte page */
        u32 sys_only:1;         /* don't map to user space */
        u32 cache:1;            /* map to data cache */
        u32 btlb:1;             /* map to block tlb */
        u32 last:1;             /* last region in list */
        u32 length:14;          /* length in 4kbyte page */
    } region_desc;

    u32 region;                 /* complete region value */
} region_t;

struct sti_glob_cfg_ext {
    u8 curr_mon;                /* current monitor configured */
    u8 friendly_boot;           /* in friendly boot mode */
    s16 power;                  /* power calculation (in Watts) */
    s32 freq_ref;               /* frequency reference */
    u32 sti_mem_addr;           /* pointer to global sti memory (size=sti_mem_request) */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_glob_cfg {
    s32 text_planes;            /* number of planes used for text */
    s16 onscreen_x;             /* screen width in pixels */
    s16 onscreen_y;             /* screen height in pixels */
    s16 offscreen_x;            /* offset width in pixels */
    s16 offscreen_y;            /* offset height in pixels */
    s16 total_x;                /* frame buffer width in pixels */
    s16 total_y;                /* frame buffer height in pixels */
    u32 region_ptrs[STI_REGION_MAX]; /* region pointers */
    s32 reent_lvl;              /* storage for reentry level value */
    u32 save_addr;              /* where to save or restore reentrant state */
    u32 ext_ptr;                /* pointer to extended glob_cfg data structure */
};


/* STI init function structs */

struct sti_init_flags {
    u32 wait:1;                 /* should routine idle wait or not */
    u32 reset:1;                /* hard reset the device? */
    u32 text:1;                 /* turn on text display planes? */
    u32 nontext:1;              /* turn on non-text display planes? */
    u32 clear:1;                /* clear text display planes? */
    u32 cmap_blk:1;             /* non-text planes cmap black? */
    u32 enable_be_timer:1;      /* enable bus error timer */
    u32 enable_be_int:1;        /* enable bus error timer interrupt */
    u32 no_chg_tx:1;            /* don't change text settings */
    u32 no_chg_ntx:1;           /* don't change non-text settings */
    u32 no_chg_bet:1;           /* don't change berr timer settings */
    u32 no_chg_bei:1;           /* don't change berr int settings */
    u32 init_cmap_tx:1;         /* initialize cmap for text planes */
    u32 cmt_chg:1;              /* change current monitor type */
    u32 retain_ie:1;            /* don't allow reset to clear int enables */
    u32 caller_bootrom:1;       /* set only by bootrom for each call */
    u32 caller_kernel:1;        /* set only by kernel for each call */
    u32 caller_other:1;         /* set only by non-[BR/K] caller */
    u32 pad:14;                 /* pad to word boundary */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_init_inptr_ext {
    u8  config_mon_type;        /* configure to monitor type */
    u8  pad[1];                 /* pad to word boundary */
    u16 inflight_data;          /* inflight data possible on PCI */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_init_inptr {
    s32 text_planes;            /* number of planes to use for text */
    u32 ext_ptr;                /* pointer to extended init_graph inptr data structure*/
};


struct sti_init_outptr {
    s32 errno;                  /* error number on failure */
    s32 text_planes;            /* number of planes used for text */
    u32 future_ptr;             /* pointer to future data */
};

/* STI configuration function structs */

struct sti_conf_flags {
    u32 wait:1;                 /* should routine idle wait or not */
    u32 pad:31;                 /* pad to word boundary */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_conf_inptr {
    u32 future_ptr;             /* pointer to future data */
};

struct sti_conf_outptr_ext {
    u32 crt_config[3];          /* hardware specific X11/OGL information */
    u32 crt_hdw[3];
    u32 future_ptr;
};

struct sti_conf_outptr {
    s32 errno;                  /* error number on failure */
    s16 onscreen_x;             /* screen width in pixels */
    s16 onscreen_y;             /* screen height in pixels */
    s16 offscreen_x;            /* offscreen width in pixels */
    s16 offscreen_y;            /* offscreen height in pixels */
    s16 total_x;                /* frame buffer width in pixels */
    s16 total_y;                /* frame buffer height in pixels */
    s32 bits_per_pixel;         /* bits/pixel device has configured */
    s32 bits_used;              /* bits which can be accessed */
    s32 planes;                 /* number of fb planes in system */
    u8 dev_name[STI_DEV_NAME_LENGTH]; /* null terminated product name */
    u32 attributes;             /* flags denoting attributes */
    u32 ext_ptr;                /* pointer to future data */
};

typedef struct {
    u32 x:12;
    u32 y:12;
    u32 hz:7;
    u32 class_flat:1;
    u32 class_vesa:1;
    u32 class_grey:1;
    u32 class_dbl:1;
    u32 class_user:1;
    u32 class_stereo:1;
    u32 class_sam:1;
    u32 pad:15;
    u32 hz_upper:3;
    u32 index:8;
} mon_tbl_desc;

struct sti_rom {
    u8 type[4];
    u8 res004;
    u8 num_mons;
    u8 revno[2];
    u32 graphics_id[2];

    u32 font_start;
    u32 statesize;
    u32 last_addr;
    u32 region_list;

    u16 reentsize;
    u16 maxtime;
    u32 mon_tbl_addr;
    u32 user_data_addr;
    u32 sti_mem_req;

    u32 user_data_size;
    u16 power;
    u8 bus_support;
    u8 ext_bus_support;
    u8 alt_code_type;
    u8 ext_dd_struct[3];
    u32 cfb_addr;

    u32 init_graph;
    u32 state_mgmt;
    u32 font_unpmv;
    u32 block_move;
    u32 self_test;
    u32 excep_hdlr;
    u32 inq_conf;
    u32 set_cm_entry;
    u32 dma_ctrl;
    u32 flow_ctrl;
    u32 user_timing;
    u32 process_mgr;
    u32 sti_util;
    u32 end;

    u32 res040[2];

    u32 init_graph_addr;
    u32 state_mgmt_addr;
    u32 font_unp_addr;
    u32 block_move_addr;
    u32 self_test_addr;
    u32 excep_hdlr_addr;
    u32 inq_conf_addr;
    u32 set_cm_entry_addr;
    u32 image_unpack_addr;
    u32 pa_risx_addrs[7];
};


struct sti_rom_font {
    u16 first_char;
    u16 last_char;
    u8 width;
    u8 height;
    u8 font_type;               /* language type */
    u8 bytes_per_char;
    u32 next_font;
    u8 underline_height;
    u8 underline_pos;
    u8 res008[2];
};

struct font {
    struct sti_rom_font hdr;
    unsigned char font[];
};

/* STI font printing function structs */

struct sti_font_inptr {
    u32 font_start_addr;        /* address of font start */
    s16 index;                  /* index into font table of character */
    u8 fg_color;                /* foreground color of character */
    u8 bg_color;                /* background color of character */
    s16 dest_x;                 /* X location of character upper left */
    s16 dest_y;                 /* Y location of character upper left */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_font_flags {
    u32 wait:1;                 /* should routine idle wait or not */
    u32 non_text:1;             /* font unpack/move in non_text planes =1, text =0 */
    u32 pad:30;                 /* pad to word boundary */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_font_outptr {
    s32 errno;                  /* error number on failure */
    u32 future_ptr;             /* pointer to future data */
};

/* STI blockmove structs */

struct sti_blkmv_flags {
    u32 wait:1;                 /* should routine idle wait or not */
    u32 color:1;                /* change color during move? */
    u32 clear:1;                /* clear during move? */
    u32 non_text:1;             /* block move in non_text planes =1, text =0 */
    u32 pad:28;                 /* pad to word boundary */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_blkmv_inptr {
    u8 fg_color;                /* foreground color after move */
    u8 bg_color;                /* background color after move */
    s16 src_x;                  /* source upper left pixel x location */
    s16 src_y;                  /* source upper left pixel y location */
    s16 dest_x;                 /* dest upper left pixel x location */
    s16 dest_y;                 /* dest upper left pixel y location */
    s16 width;                  /* block width in pixels */
    s16 height;                 /* block height in pixels */
    u32 future_ptr;             /* pointer to future data */
};

struct sti_blkmv_outptr {
        s32 errno;              /* error number on failure */
        u32 future_ptr;         /* pointer to future data */
};

struct sti_state_flags {
    u32 wait:1;                 /* should routing idle wait or not */
    u32 save:1;                 /* save (1) or restore (0) state */
    u32 res_disp:1;             /* restore all display planes */
    u32 pad:29;                 /* pad to word boundary */
    s32 *future_ptr;            /* pointer to future data */
};

struct sti_state_inptr {
    s32 *save_addr;             /* where to save or restore state */
    s32 *future_ptr;            /* pointer to future data */
};

struct sti_state_outptr {
    s32 errno;                  /* error number on failure */
    s32 *future_ptr;            /* pointer to future data */
};

struct setcm_flags {
    u32 wait:1;                 /* should routine idle wait or not */
    u32 pad:31;                 /* pad to word boundary */
    s32 *future_ptr;            /* pointer to future data */
};

struct setcm_inptr {
    s32 entry;                  /* entry number */
    u32 value;                  /* entry value */
    s32 *future_ptr;            /* pointer to future data */
};

struct setcm_outptr {
    s32 errno;                  /* error number on failure */
    s32 *future_ptr;            /* pointer to future data */
};

void sti_rom_init(void);
void sti_console_init(struct sti_rom *rom);
void sti_putc(const char c);

extern struct sti_rom sti_proc_rom;
extern char _sti_rom_end[];
extern char _sti_rom_start[];
extern void parisc_putchar(char c);

#endif  /* STICORE_H */
