/*
 * NAND profile file parser. See nand-profile.h and
 * hw/femu/docs/features/nand-profiles.md for the format.
 *
 * It needs only GLib and osdep.h, so the unit tests build it standalone.
 */

#include "qemu/osdep.h"
#include "nand-profile.h"

enum {
    K_VERSION, K_NAME, K_TYPE, K_READ, K_PROGRAM, K_ERASE, K_CMD, K_XFER,
    K_STATUS, K_NR,
};

static const char *const nand_profile_keys[K_NR] = {
    "femu_nand_profile", "name", "nand_type", "read_ns", "program_ns",
    "erase_ns", "cmd_addr_ns", "xfer_ns", "status_ns",
};

/* a decimal value from @lo to @hi, nothing after it */
static bool nand_profile_num(const char *v, int64_t lo, int64_t hi,
                             int64_t *out)
{
    char *end;
    long long x;

    if (!g_ascii_isdigit(*v)) {
        return false;
    }
    errno = 0;
    x = strtoll(v, &end, 10);
    if (errno || *end || x < lo || x > hi) {
        return false;
    }
    *out = x;
    return true;
}

static int nand_profile_type(const char *v)
{
    static const char *const names[] = { "none", "slc", "mlc", "tlc", "qlc" };

    for (int i = 0; i < ARRAY_SIZE(names); i++) {
        if (!strcmp(v, names[i])) {
            return i;
        }
    }
    return -1;
}

bool nand_profile_parse(const char *path, const char *buf, NandProfile *p,
                        char **err)
{
    g_auto(GStrv) lines = g_strsplit(buf, "\n", -1);
    bool seen[K_NR] = { false };
    bool first = true;

    memset(p, 0, sizeof(*p));
    for (int ln = 0; lines[ln]; ln++) {
        char *line = lines[ln];
        char *eq, *key, *val;
        int64_t num;
        int k;

        line[strcspn(line, ";#")] = '\0';
        g_strstrip(line);
        if (!*line) {
            continue;
        }
        eq = strchr(line, '=');
        if (!eq) {
            *err = g_strdup_printf("%s:%d: expected key = value", path,
                                   ln + 1);
            return false;
        }
        *eq = '\0';
        key = g_strstrip(line);
        val = g_strstrip(eq + 1);
        for (k = 0; k < K_NR && strcmp(key, nand_profile_keys[k]); k++) {
        }
        if (k == K_NR) {
            *err = g_strdup_printf("%s:%d: unknown key '%s'", path, ln + 1,
                                   key);
            return false;
        }
        if (first && k != K_VERSION) {
            *err = g_strdup_printf("%s:%d: the first key must be "
                                   "femu_nand_profile", path, ln + 1);
            return false;
        }
        first = false;
        if (seen[k]) {
            *err = g_strdup_printf("%s:%d: key '%s' given twice", path, ln + 1,
                                   key);
            return false;
        }
        seen[k] = true;

        switch (k) {
        case K_VERSION:
            if (strcmp(val, "1")) {
                *err = g_strdup_printf("%s:%d: version '%s' is not supported; "
                                       "this FEMU reads version 1", path,
                                       ln + 1, val);
                return false;
            }
            break;
        case K_NAME:
            if (!*val || strlen(val) >= NAND_PROFILE_NAME_MAX) {
                *err = g_strdup_printf("%s:%d: name must have 1 to %d "
                                       "characters", path, ln + 1,
                                       NAND_PROFILE_NAME_MAX - 1);
                return false;
            }
            g_strlcpy(p->name, val, sizeof(p->name));
            break;
        case K_TYPE:
            p->nand_type = nand_profile_type(val);
            if (p->nand_type < 0) {
                *err = g_strdup_printf("%s:%d: nand_type must be none, slc, "
                                       "mlc, tlc or qlc", path, ln + 1);
                return false;
            }
            break;
        default:
            /* array times are at least 1 ns; bus phases may be 0 */
            if (!nand_profile_num(val, k <= K_ERASE ? 1 : 0, INT32_MAX,
                                  &num)) {
                *err = g_strdup_printf("%s:%d: %s must be a whole number of "
                                       "ns from %d to %d", path, ln + 1, key,
                                       k <= K_ERASE ? 1 : 0, INT32_MAX);
                return false;
            }
            switch (k) {
            case K_READ:
                p->read_ns = num;
                break;
            case K_PROGRAM:
                p->program_ns = num;
                break;
            case K_ERASE:
                p->erase_ns = num;
                break;
            case K_CMD:
                p->cmd_addr_ns = num;
                break;
            case K_XFER:
                p->xfer_ns = num;
                break;
            default:
                p->status_ns = num;
                break;
            }
            break;
        }
    }
    for (int k = 0; k < K_NR; k++) {
        if (!seen[k]) {
            *err = g_strdup_printf("%s: missing key '%s' at end of file", path,
                                   nand_profile_keys[k]);
            return false;
        }
    }
    return true;
}
