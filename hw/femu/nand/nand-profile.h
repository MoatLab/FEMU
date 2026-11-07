#ifndef __FEMU_NAND_PROFILE_H
#define __FEMU_NAND_PROFILE_H

/*
 * NAND profile files (nand_profile=FILE): the base timing of one chip, in a
 * versioned key file that bbssd and ZNS read the same way. Version 1 holds
 * scalars only; the device maps them onto its own timing properties.
 */

#define NAND_PROFILE_NAME_MAX   64

typedef struct NandProfile {
    char    name[NAND_PROFILE_NAME_MAX];
    int     nand_type;      /* 0 none, else SLC (1) to QLC (4) */
    int64_t read_ns;
    int64_t program_ns;     /* one page */
    int64_t erase_ns;
    int64_t cmd_addr_ns;
    int64_t xfer_ns;        /* one NAND page of the mode */
    int64_t status_ns;
} NandProfile;

/*
 * Parse the profile text @buf of file @path into @p. Returns false and sets
 * @err (a g_strdup'd message naming the file and line) on any problem.
 */
bool nand_profile_parse(const char *path, const char *buf, NandProfile *p,
                        char **err);

#endif
