#ifndef __FEMU_NAND_PROFILE_H
#define __FEMU_NAND_PROFILE_H

/*
 * NAND profile files (nand_profile=FILE): the base timing of one chip, in a
 * versioned key file that bbssd and ZNS read the same way. Version 1 holds
 * scalars only; the device maps them onto its own timing properties.
 */

#define NAND_PROFILE_NAME_MAX   64
/* the value keys, nand_type to status_ns, in nand_profile_value_key order */
#define NAND_PROFILE_VALUES     7
/* a source text: 1 to 255 bytes */
#define NAND_PROFILE_SOURCE_MAX 256

/* where one value of a profile comes from in its file */
typedef struct NandProfileValue {
    int     line;               /* 1-based line of the value */
    int     source_line;        /* 1-based line of its source, or 0 */
    char    source[NAND_PROFILE_SOURCE_MAX];
} NandProfileValue;

typedef struct NandProfile {
    char    name[NAND_PROFILE_NAME_MAX];
    int     nand_type;      /* 0 none, else SLC (1) to QLC (4) */
    int64_t read_ns;
    int64_t program_ns;     /* one page */
    int64_t erase_ns;
    int64_t cmd_addr_ns;
    int64_t xfer_ns;        /* one NAND page of the mode */
    int64_t status_ns;
    NandProfileValue val[NAND_PROFILE_VALUES];
} NandProfile;

/*
 * Parse the profile text @buf of file @path into @p. Returns false and sets
 * @err (a g_strdup'd message naming the file and line) on any problem.
 */
bool nand_profile_parse(const char *path, const char *buf, NandProfile *p,
                        char **err);

/* the key of value @i (0 to NAND_PROFILE_VALUES - 1), as in the file */
const char *nand_profile_value_key(int i);

/* value @i of @p in canonical form: decimal ns, or the nand_type name */
char *nand_profile_value_text(const NandProfile *p, int i);

#endif
