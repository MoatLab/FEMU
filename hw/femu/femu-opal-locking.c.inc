/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU TCG Opal TPer: the Locking SP (Opal SSC 2.30 section 4.3, Core 2.01
 * section 5.7). femu-opal.c includes this file, so it shares the codec and
 * session helpers. The engine keeps the tables; FEMU applies the effects
 * through cfg.erase and the lock view.
 */

/* Locking SP objects (Opal Tables 40 to 48) */
#define UID_LSP_SPINFO      0x0000000200000001ull
#define UID_LOCKINGINFO     0x0000080100000001ull
#define UID_T_LOCKING       0x0000080200000000ull
#define UID_LOCKING(r)      ((r) ? 0x0000080200030000ull + (r) : \
                                   0x0000080200000001ull)
#define UID_MBRCONTROL      0x0000080300000001ull
#define UID_T_MBR           0x0000080400000000ull
#define UID_KAES(r)         ((r) ? 0x0000080600030000ull + (r) : \
                                   0x0000080600000001ull)
#define UID_T_DATASTORE     0x0000100100000000ull
#define UID_T_ACE           0x0000000800000000ull
#define UID_LSP_CPIN_ADMIN(i) (0x0000000B00010001ull + (i))
#define UID_LSP_CPIN_USER(i)  (0x0000000B00030001ull + (i))
#define UID_T_TABLE         0x0000000100000000ull
#define UID_TABLE(t)        (0x0000000100000000ull | (t))
#define UID_T_SPTEMPLATES   0x0000000300000000ull
#define UID_T_METHODID      0x0000000600000000ull
#define UID_T_SECRETPROTECT 0x0000001D00000000ull
#define UID_SECRETPROTECT_KAES 0x0000001D0000001Eull
#define UID_M_GENKEY        0x0000000600000010ull
#define UID_M_REVERTSP      0x0000000600000011ull

/* the half-UIDs of a BooleanExpr (Core Table 210) */
#define HALF_AUTHORITY_REF  0x00000C05u
#define HALF_BOOLEAN_ACE    0x0000040Eu

/* BooleanExpr bits: one per authority index, plus the two classes */
#define EXPR_ADMINS         (1u << 30)
#define EXPR_USERS          (1u << 29)
#define EXPR_ANYBODY        (1u << FEMU_OPAL_AU_ANYBODY)
#define EXPR_ADMIN(i)       (1u << (FEMU_OPAL_AU_LSP_ADMIN1 + (i)))
#define EXPR_USER(i)        (1u << (FEMU_OPAL_AU_LSP_USER1 + (i)))
#define LSP_ADMIN_BITS      (0xFu << FEMU_OPAL_AU_LSP_ADMIN1)
#define LSP_USER_BITS       (0xFFu << FEMU_OPAL_AU_LSP_USER1)

#define COLS_ALL            0xFFFFFFFFu
#define COLS(lo, hi)        ((uint32_t)((2ull << (hi)) - (1ull << (lo))))

/*
 * The ACE rows (Opal Table 39), by index:
 *   0 Anybody, 1 Admin, 2 Anybody_Get_CommonName, 3 Admins_Set_CommonName,
 *   4 ACE_Get_All, 5 ACE_Set_BooleanExpression, 6 Authority_Get_All,
 *   7 Authority_Set_Enabled, 8..15 UserN_Set_CommonName,
 *   16 C_PIN_Admins_Get_All_NOPIN, 17 C_PIN_Admins_Set_PIN,
 *   18..25 C_PIN_UserN_Set_PIN, 26 K_AES_Mode, 27..35 K_AES_256 GenKey,
 *   36..44 Locking Get_RangeStartToActiveKey, 45..53 Set_RdLocked,
 *   54..62 Set_WrLocked, 63 GlblRng_Admins_Set, 64 Admins_RangeStartToLOR,
 *   65 MBRControl_Admins_Set, 66 MBRControl_Set_DoneToDOR,
 *   67 DataStore_Get_All, 68 DataStore_Set_All.
 * Range sets count 9: Global, then Range1 to Range8.
 */
enum {
    ACE_ANYBODY = 0, ACE_ADMIN, ACE_ANYBODY_GET_CN, ACE_ADMINS_SET_CN,
    ACE_ACE_GET_ALL, ACE_ACE_SET_BE, ACE_AUTH_GET_ALL, ACE_AUTH_SET_ENABLED,
    ACE_USER_SET_CN, ACE_CPIN_GET_NOPIN = ACE_USER_SET_CN + 8,
    ACE_CPIN_ADMINS_SET_PIN, ACE_CPIN_USER_SET_PIN,
    ACE_KAES_MODE = ACE_CPIN_USER_SET_PIN + 8,
    ACE_GENKEY, ACE_LOCK_GET = ACE_GENKEY + 9,
    ACE_LOCK_RDLOCKED = ACE_LOCK_GET + 9,
    ACE_LOCK_WRLOCKED = ACE_LOCK_RDLOCKED + 9,
    ACE_GLOBAL_ADMINS_SET = ACE_LOCK_WRLOCKED + 9,
    ACE_RANGE_ADMINS_SET, ACE_MBR_ADMINS_SET, ACE_MBR_DONE_TO_DOR,
    ACE_DS_GET, ACE_DS_SET, ACE_END,
};
QEMU_BUILD_BUG_ON(ACE_END != FEMU_OPAL_ACE_COUNT);

static uint64_t lsp_ace_uid(int i)
{
    static const uint32_t fixed[] = {
        [ACE_ANYBODY] = 0x00000001, [ACE_ADMIN] = 0x00000002,
        [ACE_ANYBODY_GET_CN] = 0x00000003, [ACE_ADMINS_SET_CN] = 0x00000004,
        [ACE_ACE_GET_ALL] = 0x00038000, [ACE_ACE_SET_BE] = 0x00038001,
        [ACE_AUTH_GET_ALL] = 0x00039000, [ACE_AUTH_SET_ENABLED] = 0x00039001,
    };
    uint32_t lo;

    if (i < ACE_USER_SET_CN) {
        lo = fixed[i];
    } else if (i < ACE_CPIN_GET_NOPIN) {
        lo = 0x00044001 + (i - ACE_USER_SET_CN);
    } else if (i == ACE_CPIN_GET_NOPIN) {
        lo = 0x0003A000;
    } else if (i == ACE_CPIN_ADMINS_SET_PIN) {
        lo = 0x0003A001;
    } else if (i < ACE_KAES_MODE) {
        lo = 0x0003A801 + (i - ACE_CPIN_USER_SET_PIN);
    } else if (i == ACE_KAES_MODE) {
        lo = 0x0003BFFF;
    } else if (i < ACE_LOCK_GET) {
        lo = 0x0003B800 + (i - ACE_GENKEY);
    } else if (i < ACE_LOCK_RDLOCKED) {
        lo = 0x0003D000 + (i - ACE_LOCK_GET);
    } else if (i < ACE_LOCK_WRLOCKED) {
        lo = 0x0003E000 + (i - ACE_LOCK_RDLOCKED);
    } else if (i < ACE_GLOBAL_ADMINS_SET) {
        lo = 0x0003E800 + (i - ACE_LOCK_WRLOCKED);
    } else {
        static const uint32_t tail[] = {
            0x0003F000, 0x0003F001, 0x0003F800, 0x0003F801, 0x0003FC00,
            0x0003FC01,
        };

        lo = tail[i - ACE_GLOBAL_ADMINS_SET];
    }
    return 0x0000000800000000ull | lo;
}

static int lsp_ace_index(uint64_t uid)
{
    int i;

    for (i = 0; i < ACE_END; i++) {
        if (lsp_ace_uid(i) == uid) {
            return i;
        }
    }
    return -1;
}

/* the columns an ACE grants (Opal Table 39) */
static uint32_t lsp_ace_cols(int i)
{
    if (i >= ACE_USER_SET_CN && i < ACE_CPIN_GET_NOPIN) {
        return 1u << 2;
    }
    if (i >= ACE_CPIN_USER_SET_PIN && i < ACE_KAES_MODE) {
        return 1u << 3;
    }
    if (i >= ACE_LOCK_GET && i < ACE_LOCK_RDLOCKED) {
        return COLS(3, 10);
    }
    if (i >= ACE_LOCK_RDLOCKED && i < ACE_LOCK_WRLOCKED) {
        return 1u << 7;
    }
    if (i >= ACE_LOCK_WRLOCKED && i < ACE_GLOBAL_ADMINS_SET) {
        return 1u << 8;
    }
    switch (i) {
    case ACE_ANYBODY_GET_CN:
        return 1u << 0 | 1u << 2;
    case ACE_ADMINS_SET_CN:
        return 1u << 2;
    case ACE_ACE_SET_BE:
        return 1u << 3;
    case ACE_AUTH_SET_ENABLED:
        return 1u << 5;
    case ACE_CPIN_GET_NOPIN:
        return 1u << 0 | COLS(4, 7);
    case ACE_CPIN_ADMINS_SET_PIN:
        return 1u << 3;
    case ACE_KAES_MODE:
        return 1u << 4;
    case ACE_GLOBAL_ADMINS_SET:
        return COLS(5, 9);
    case ACE_RANGE_ADMINS_SET:
        return COLS(3, 9);
    case ACE_MBR_ADMINS_SET:
        return COLS(1, 3);
    case ACE_MBR_DONE_TO_DOR:
        return COLS(2, 3);
    default:
        return COLS_ALL;
    }
}

static uint32_t lsp_ace_default(int i)
{
    if (i == ACE_ANYBODY || i == ACE_ANYBODY_GET_CN || i == ACE_KAES_MODE) {
        return EXPR_ANYBODY;
    }
    if (i >= ACE_CPIN_USER_SET_PIN && i < ACE_KAES_MODE) {
        return EXPR_ADMINS | EXPR_USER(i - ACE_CPIN_USER_SET_PIN);
    }
    return EXPR_ADMINS;
}

/* the ACEs whose BooleanExpr a host may Set (Opal Table 38) */
static bool lsp_ace_settable(int i)
{
    return i == ACE_ACE_GET_ALL || i == ACE_AUTH_GET_ALL ||
           (i >= ACE_USER_SET_CN && i < ACE_CPIN_GET_NOPIN) ||
           (i >= ACE_CPIN_USER_SET_PIN && i < ACE_KAES_MODE) ||
           (i >= ACE_GENKEY && i < ACE_GLOBAL_ADMINS_SET) ||
           i == ACE_MBR_DONE_TO_DOR || i == ACE_DS_GET || i == ACE_DS_SET;
}

/* does the session satisfy BooleanExpr @expr? */
static bool lsp_expr_ok(const FemuOpal *o, uint32_t expr)
{
    uint32_t au = o->s.auth;

    return (expr & au) || ((expr & EXPR_ADMINS) && (au & LSP_ADMIN_BITS)) ||
           ((expr & EXPR_USERS) && (au & LSP_USER_BITS));
}

/* a Locking SP range row or key row: the range index, or -1 */
static int lsp_range_of(uint64_t uid, uint64_t global, uint64_t base)
{
    if (uid == global) {
        return 0;
    }
    if (uid > base && uid <= base + FEMU_OPAL_RANGES) {
        return uid - base;
    }
    return -1;
}

static int lsp_lock_row(uint64_t uid)
{
    return lsp_range_of(uid, UID_LOCKING(0), 0x0000080200030000ull);
}

static int lsp_key_row(uint64_t uid)
{
    return lsp_range_of(uid, UID_KAES(0), 0x0000080600030000ull);
}

/* a Locking SP C_PIN row: its authority index, or -1 */
static int lsp_cpin(uint64_t uid)
{
    if (uid >= UID_LSP_CPIN_ADMIN(0) && uid <= UID_LSP_CPIN_ADMIN(3)) {
        return FEMU_OPAL_AU_LSP_ADMIN1 + (uid - UID_LSP_CPIN_ADMIN(0));
    }
    if (uid >= UID_LSP_CPIN_USER(0) && uid <= UID_LSP_CPIN_USER(7)) {
        return FEMU_OPAL_AU_LSP_USER1 + (uid - UID_LSP_CPIN_USER(0));
    }
    return -1;
}

static uint64_t lsp_cpin_uid(int a)
{
    return a < FEMU_OPAL_AU_LSP_USER1 ?
           UID_LSP_CPIN_ADMIN(a - FEMU_OPAL_AU_LSP_ADMIN1) :
           UID_LSP_CPIN_USER(a - FEMU_OPAL_AU_LSP_USER1);
}

/* a Locking SP authority row, classes included */
static bool lsp_authority(uint64_t uid)
{
    return femu_opal_auth_index(true, uid) >= 0 ||
           femu_opal_auth_class(true, uid);
}

/* the Table table of the Locking SP (Opal Table 36): K_AES_256 only */
static const struct {
    uint32_t t;
    const char *name;
    uint32_t rows;              /* byte tables: their size */
} lsp_tables[] = {
    { 0x0001, "Table" }, { 0x0002, "SPInfo" }, { 0x0003, "SPTemplates" },
    { 0x0006, "MethodID" }, { 0x0007, "AccessControl" }, { 0x0008, "ACE" },
    { 0x0009, "Authority" }, { 0x000B, "C_PIN" },
    { 0x001D, "SecretProtect" }, { 0x0801, "LockingInfo" },
    { 0x0802, "Locking" }, { 0x0803, "MBRControl" },
    { 0x0804, "MBR", FEMU_OPAL_MBR_SIZE }, { 0x0806, "K_AES_256" },
    { 0x1001, "DataStore", FEMU_OPAL_DS_SIZE },
};

/* the SPTemplates rows (Opal Table 35) */
static const struct {
    const char *name;
    uint32_t tid;               /* TemplateID low half */
} lsp_templates[] = { { "Base", 1 }, { "Locking", 6 } };

/* the MethodID rows (Opal Table 37) */
static const struct {
    uint64_t uid;
    const char *name;
} lsp_methods[] = {
    { UID_M_NEXT, "Next" }, { UID_M_GETACL, "GetACL" },
    { UID_M_GENKEY, "GenKey" }, { UID_M_REVERTSP, "RevertSP" },
    { UID_M_GET, "Get" }, { UID_M_SET, "Set" },
    { UID_M_AUTHENTICATE, "Authenticate" }, { UID_M_RANDOM, "Random" },
};

static int lsp_table_row(uint64_t uid)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(lsp_tables); i++) {
        if (uid == UID_TABLE(lsp_tables[i].t)) {
            return i;
        }
    }
    return -1;
}

static int lsp_template_row(uint64_t uid)
{
    return uid == UID_T_SPTEMPLATES + 1 ? 0 :
           uid == UID_T_SPTEMPLATES + 2 ? 1 : -1;
}

static int lsp_method_row(uint64_t uid)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(lsp_methods); i++) {
        if (uid == lsp_methods[i].uid) {
            return i;
        }
    }
    return -1;
}

/* rows that Anybody reads (Opal Table 38) */
static bool lsp_public_row(uint64_t uid)
{
    return uid == UID_LSP_SPINFO || uid == UID_LOCKINGINFO ||
           uid == UID_MBRCONTROL || uid == UID_SECRETPROTECT_KAES ||
           lsp_table_row(uid) >= 0 || lsp_template_row(uid) >= 0 ||
           lsp_method_row(uid) >= 0;
}

/*
 * The ACL of (object, method) in the Locking SP (Opal Table 38). Returns
 * the ACE count, 0 when the association does not exist.
 */
static int lsp_acl(uint64_t obj, uint64_t m, int *ace)
{
    int r;
    int a;

    if (obj == UID_THISSP) {
        if (m == UID_M_AUTHENTICATE || m == UID_M_RANDOM) {
            ace[0] = ACE_ANYBODY;
            return 1;
        }
        if (m == UID_M_REVERTSP) {
            ace[0] = ACE_ADMIN;
            return 1;
        }
        return 0;
    }
    if (m == UID_M_NEXT) {
        if (obj == UID_T_LOCKING || obj == UID_T_ACE ||
            obj == UID_T_AUTHORITY || obj == UID_T_CPIN ||
            obj == UID_T_TABLE || obj == UID_T_SPTEMPLATES ||
            obj == UID_T_METHODID || obj == UID_T_SECRETPROTECT) {
            ace[0] = ACE_ANYBODY;
            return 1;
        }
        return 0;
    }
    if (m == UID_M_GET) {
        if (lsp_public_row(obj) || obj == UID_T_MBR) {
            ace[0] = ACE_ANYBODY;
            return 1;
        }
        if (obj == UID_T_DATASTORE) {
            ace[0] = ACE_DS_GET;
            return 1;
        }
        if (lsp_ace_index(obj) >= 0) {
            ace[0] = ACE_ACE_GET_ALL;
            return 1;
        }
        if (lsp_authority(obj)) {
            ace[0] = ACE_AUTH_GET_ALL;
            ace[1] = ACE_ANYBODY_GET_CN;
            return 2;
        }
        if (lsp_cpin(obj) >= 0) {
            ace[0] = ACE_CPIN_GET_NOPIN;
            return 1;
        }
        r = lsp_lock_row(obj);
        if (r >= 0) {
            ace[0] = ACE_LOCK_GET + r;
            ace[1] = ACE_ANYBODY_GET_CN;
            return 2;
        }
        if (lsp_key_row(obj) >= 0) {
            ace[0] = ACE_KAES_MODE;
            return 1;
        }
        return 0;
    }
    if (m == UID_M_SET) {
        if (obj == UID_MBRCONTROL) {
            ace[0] = ACE_MBR_ADMINS_SET;
            ace[1] = ACE_MBR_DONE_TO_DOR;
            return 2;
        }
        if (obj == UID_T_MBR) {
            ace[0] = ACE_ADMIN;
            return 1;
        }
        if (obj == UID_T_DATASTORE) {
            ace[0] = ACE_DS_SET;
            return 1;
        }
        if (lsp_ace_settable(lsp_ace_index(obj))) {
            ace[0] = ACE_ACE_SET_BE;
            return 1;
        }
        a = femu_opal_auth_index(true, obj);
        if (a == FEMU_OPAL_AU_LSP_ADMIN1) {
            ace[0] = ACE_ADMINS_SET_CN;
            return 1;
        }
        if (a > FEMU_OPAL_AU_LSP_ADMIN1) {
            ace[0] = ACE_AUTH_SET_ENABLED;
            ace[1] = a < FEMU_OPAL_AU_LSP_USER1 ? ACE_ADMINS_SET_CN :
                     ACE_USER_SET_CN + (a - FEMU_OPAL_AU_LSP_USER1);
            return 2;
        }
        a = lsp_cpin(obj);
        if (a >= 0) {
            ace[0] = a < FEMU_OPAL_AU_LSP_USER1 ? ACE_CPIN_ADMINS_SET_PIN :
                     ACE_CPIN_USER_SET_PIN + (a - FEMU_OPAL_AU_LSP_USER1);
            return 1;
        }
        r = lsp_lock_row(obj);
        if (r >= 0) {
            ace[0] = r ? ACE_RANGE_ADMINS_SET : ACE_GLOBAL_ADMINS_SET;
            ace[1] = ACE_LOCK_RDLOCKED + r;
            ace[2] = ACE_LOCK_WRLOCKED + r;
            ace[3] = ACE_ADMINS_SET_CN;
            return 4;
        }
        return 0;
    }
    if (m == UID_M_GENKEY) {
        r = lsp_key_row(obj);
        if (r >= 0) {
            ace[0] = ACE_GENKEY + r;
            return 1;
        }
    }
    return 0;
}

/* the union of the columns that the passing ACEs grant; 0 when none pass */
static uint32_t lsp_grant(const FemuOpal *o, const int *ace, int n)
{
    uint32_t cols = 0;
    int i;

    for (i = 0; i < n; i++) {
        if (lsp_expr_ok(o, o->sp.ace[ace[i]])) {
            cols |= lsp_ace_cols(ace[i]);
        }
    }
    return cols;
}

static bool lsp_allowed(const FemuOpal *o, uint64_t obj, uint64_t m)
{
    int ace[4] = { 0 };

    return lsp_grant(o, ace, lsp_acl(obj, m, ace)) != 0;
}

/* the Locking SP tables as they leave the factory (Opal Tables 39 to 48) */
static void lsp_factory_tables(FemuOpal *o, bool keep_global)
{
    uint64_t global_key = o->sp.range[0].key;
    int i;

    memset(o->sp.range, 0, sizeof(o->sp.range));
    for (i = 0; i <= FEMU_OPAL_RANGES; i++) {
        o->sp.range[i].lor = 1u << FEMU_OPAL_RESET_POWER;
        o->sp.range[i].key = o->next_key++;
    }
    if (keep_global) {
        o->sp.range[0].key = global_key;
    }
    o->sp.mbr_enable = false;
    o->sp.mbr_done = false;
    o->sp.mbr_dor = 1u << FEMU_OPAL_RESET_POWER;
    for (i = 0; i < ACE_END; i++) {
        o->sp.ace[i] = lsp_ace_default(i);
    }
    for (i = FEMU_OPAL_AU_LSP_ADMIN1; i < FEMU_OPAL_AU_COUNT; i++) {
        memset(&o->sp.au_cn[i], 0, sizeof(o->sp.au_cn[i]));
    }
}

/* ---- byte tables (MBR, DataStore) ---- */

static uint8_t **lsp_chunks(FemuOpal *o, bool ds)
{
    return ds ? o->ds : o->mbr;
}

/* the undo key of chunk @k of a byte table */
static gpointer lsp_undo_key(bool ds, uint64_t k)
{
    return GUINT_TO_POINTER((ds ? 1u << 16 : 0) | (uint32_t)k);
}

/*
 * Read bytes the caller has bounds-checked. @committed reads the state
 * before an open transaction: a chunk the transaction changed comes from
 * its undo copy (Core 3.3.7.3).
 */
static void lsp_bytes_read(const FemuOpal *o, bool ds, bool committed,
                           uint64_t off, uint8_t *buf, uint32_t len)
{
    uint8_t *const *c = ds ? o->ds : o->mbr;

    while (len) {
        uint64_t k = off / FEMU_OPAL_CHUNK;
        uint32_t in = off % FEMU_OPAL_CHUNK;
        uint32_t n = MIN(len, FEMU_OPAL_CHUNK - in);
        const uint8_t *src = c[k];
        gpointer old;

        if (committed && o->undo &&
            g_hash_table_lookup_extended(o->undo, lsp_undo_key(ds, k), NULL,
                                         &old)) {
            src = old;
        }
        if (src) {
            memcpy(buf, src + in, n);
        } else {
            memset(buf, 0, n);
        }
        buf += n;
        off += n;
        len -= n;
    }
}

static void lsp_bytes_write(FemuOpal *o, bool ds, uint64_t off,
                            const uint8_t *buf, uint32_t len)
{
    uint8_t **c = lsp_chunks(o, ds);

    while (len) {
        uint64_t k = off / FEMU_OPAL_CHUNK;
        uint32_t in = off % FEMU_OPAL_CHUNK;
        uint32_t n = MIN(len, FEMU_OPAL_CHUNK - in);

        if (!c[k]) {
            c[k] = g_malloc0(FEMU_OPAL_CHUNK);
        }
        memcpy(c[k] + in, buf, n);
        buf += n;
        off += n;
        len -= n;
    }
}

static void lsp_bytes_clear(FemuOpal *o)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(o->mbr); i++) {
        g_clear_pointer(&o->mbr[i], g_free);
    }
    for (i = 0; i < ARRAY_SIZE(o->ds); i++) {
        g_clear_pointer(&o->ds[i], g_free);
    }
}

/*
 * Keep a copy of each chunk a write in a transaction touches, once per
 * chunk; NULL stands for a chunk that did not exist. False when the copies
 * would pass FEMU_OPAL_UNDO_CHUNKS: the write must not happen.
 */
static bool lsp_undo_save(FemuOpal *o, bool ds, uint64_t off, uint32_t len)
{
    uint8_t **c = lsp_chunks(o, ds);
    uint64_t first = off / FEMU_OPAL_CHUNK;
    uint64_t last = (off + len - 1) / FEMU_OPAL_CHUNK;
    uint32_t need = 0;
    uint64_t k;

    if (!o->undo) {
        o->undo = g_hash_table_new_full(NULL, NULL, NULL, g_free);
    }
    for (k = first; k <= last; k++) {
        need += !g_hash_table_contains(o->undo, lsp_undo_key(ds, k));
    }
    if (g_hash_table_size(o->undo) + need > FEMU_OPAL_UNDO_CHUNKS) {
        return false;
    }
    for (k = first; k <= last; k++) {
        if (!g_hash_table_contains(o->undo, lsp_undo_key(ds, k))) {
            g_hash_table_insert(o->undo, lsp_undo_key(ds, k),
                                c[k] ? g_memdup2(c[k], FEMU_OPAL_CHUNK) :
                                       NULL);
        }
    }
    return true;
}

/* end a transaction: put the saved chunks back, or drop them */
static void lsp_undo_finish(FemuOpal *o, bool rollback)
{
    GHashTableIter it;
    gpointer key;
    gpointer old;

    if (!o->undo) {
        return;
    }
    g_hash_table_iter_init(&it, o->undo);
    while (rollback && g_hash_table_iter_next(&it, &key, &old)) {
        uint32_t v = GPOINTER_TO_UINT(key);
        uint8_t **c = lsp_chunks(o, v >> 16);

        g_free(c[v & 0xFFFF]);
        c[v & 0xFFFF] = old;
        g_hash_table_iter_steal(&it);
    }
    g_hash_table_destroy(o->undo);
    o->undo = NULL;
}

void femu_opal_cleanup(FemuOpal *o)
{
    lsp_undo_finish(o, false);
    lsp_bytes_clear(o);
}

void femu_opal_free(FemuOpal *o)
{
    femu_opal_cleanup(o);
    g_free(o);
}

bool femu_opal_mbr_read(const FemuOpal *o, uint64_t off, void *buf,
                        uint32_t len)
{
    if (off > FEMU_OPAL_MBR_SIZE || len > FEMU_OPAL_MBR_SIZE - off) {
        return false;
    }
    lsp_bytes_read(o, false, true, off, buf, len);
    return true;
}

/* ---- effects: which LBAs lose their data ---- */

/* the range that owns @lba: a non-global range that holds it, else Global */
static int lsp_owner(const FemuOpalSp *sp, uint64_t lba)
{
    int r;

    for (r = 1; r <= FEMU_OPAL_RANGES; r++) {
        const FemuOpalRange *g = &sp->range[r];

        if (g->len && lba >= g->start && lba - g->start < g->len) {
            return r;
        }
    }
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

/*
 * Erase every LBA whose owner range or owner key differs between @old and
 * the current tables (design 17.2). Runs after a method outside a
 * transaction, or at commit.
 */
static void femu_opal_effects(FemuOpal *o, const FemuOpalSp *old)
{
    const FemuOpalSp *sp = &o->sp;
    uint64_t pt[4 * FEMU_OPAL_RANGES + 2];
    uint64_t end = o->cfg.nlbas;
    uint64_t es = 0;
    uint64_t el = 0;
    int n = 0;
    int i;
    int r;

    if (!o->cfg.erase || !end) {
        return;
    }
    pt[n++] = 0;
    pt[n++] = end;
    for (r = 1; r <= FEMU_OPAL_RANGES; r++) {
        pt[n++] = MIN(old->range[r].start, end);
        pt[n++] = MIN(old->range[r].start + old->range[r].len, end);
        pt[n++] = MIN(sp->range[r].start, end);
        pt[n++] = MIN(sp->range[r].start + sp->range[r].len, end);
    }
    qsort(pt, n, sizeof(pt[0]), cmp_u64);
    for (i = 0; i + 1 < n; i++) {
        uint64_t a = pt[i];
        uint64_t b = pt[i + 1];
        int ro;
        int rn;

        if (a == b) {
            continue;
        }
        ro = lsp_owner(old, a);
        rn = lsp_owner(sp, a);
        if (ro == rn && old->range[ro].key == sp->range[rn].key) {
            continue;
        }
        if (el && es + el == a) {
            el += b - a;
            continue;
        }
        if (el) {
            o->cfg.erase(o->cfg.opaque, es, el);
        }
        es = a;
        el = b - a;
    }
    if (el) {
        o->cfg.erase(o->cfg.opaque, es, el);
    }
}

/* ---- lock view for the I/O path ---- */

void femu_opal_view(const FemuOpal *o, FemuOpalView *v)
{
    const FemuOpalSp *sp = committed(o);
    int r;

    memset(v, 0, sizeof(*v));
    v->enabled = sp->lsp_life == FEMU_OPAL_LIFE_MANUFACTURED;
    v->shadow = v->enabled && sp->mbr_enable && !sp->mbr_done;
    v->mbr_lbas = FEMU_OPAL_MBR_SIZE / MAX(o->cfg.lba_size, 1);
    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        v->r[r].start = r ? sp->range[r].start : 0;
        v->r[r].len = r ? sp->range[r].len : 0;
        v->r[r].rlocked = sp->range[r].rle && sp->range[r].rl;
        v->r[r].wlocked = sp->range[r].wle && sp->range[r].wl;
    }
}

/*
 * Core Tables 230 and 231 and SIIS 6.7.9 to 6.7.11. A Read inside an
 * active MBR shadow gets the MBR bytes whatever the locks. Verify, Compare
 * and a Copy source there need unlocked owners first. Outside the shadow a
 * command that touches a read-locked owner gets DENY, except a Read whose
 * owners are all read locked while the shadow is active: zeros.
 */
FemuOpalAccess femu_opal_access(const FemuOpalView *v, FemuOpalOp op,
                               uint64_t slba, uint64_t nlb)
{
    uint64_t end = slba + nlb;
    uint64_t covered = 0;
    bool any_r = false;
    bool all_r = true;
    bool any_w = false;
    int r;

    if (!v->enabled) {
        return FEMU_OPAL_MEDIA;
    }
    /* an extent past the LBA space never passes */
    if (nlb > UINT64_MAX - slba) {
        return FEMU_OPAL_DENY;
    }
    for (r = 1; r <= FEMU_OPAL_RANGES; r++) {
        uint64_t a = MAX(slba, v->r[r].start);
        uint64_t b = MIN(end, v->r[r].start + v->r[r].len);

        if (!v->r[r].len || a >= b) {
            continue;
        }
        covered += b - a;
        any_r |= v->r[r].rlocked;
        all_r &= v->r[r].rlocked;
        any_w |= v->r[r].wlocked;
    }
    if (covered < nlb) {
        any_r |= v->r[0].rlocked;
        all_r &= v->r[0].rlocked;
        any_w |= v->r[0].wlocked;
    }
    if (v->shadow && slba < v->mbr_lbas) {
        if (end > v->mbr_lbas || op == FEMU_OPAL_OP_WRITE) {
            return FEMU_OPAL_DENY;
        }
        return op == FEMU_OPAL_OP_READ || !any_r ? FEMU_OPAL_SHADOW :
                                                   FEMU_OPAL_DENY;
    }
    if (op == FEMU_OPAL_OP_WRITE) {
        return any_w ? FEMU_OPAL_DENY : FEMU_OPAL_MEDIA;
    }
    if (!any_r) {
        return FEMU_OPAL_MEDIA;
    }
    return op == FEMU_OPAL_OP_READ && v->shadow && all_r ? FEMU_OPAL_ZEROS :
                                                           FEMU_OPAL_DENY;
}

/* a TCG reset of @type: LockOnReset and DoneOnReset (Opal 4.3.5.2.2) */
static void lsp_reset(FemuOpal *o, int type)
{
    int r;

    if (o->sp.lsp_life != FEMU_OPAL_LIFE_MANUFACTURED) {
        return;
    }
    for (r = 0; r <= FEMU_OPAL_RANGES; r++) {
        if (o->sp.range[r].lor & (1u << type)) {
            o->sp.range[r].rl = true;
            o->sp.range[r].wl = true;
        }
    }
    if (o->sp.mbr_dor & (1u << type)) {
        o->sp.mbr_done = false;
    }
}

/* ---- value codecs ---- */

/* the index after the value at t[i]: one token or a nested list */
static int value_end(const FemuOpalTok *t, int n, int i)
{
    int depth = 0;

    do {
        if (i >= n) {
            return -1;
        }
        if (tok_is(&t[i], TOK_SL)) {
            depth++;
        } else if (tok_is(&t[i], TOK_EL)) {
            depth--;
        } else if (tok_is(&t[i], TOK_SN) || tok_is(&t[i], TOK_EN)) {
            /* a named value inside a list */
            if (!depth) {
                return -1;
            }
        }
        i++;
    } while (depth > 0);
    return depth ? -1 : i;
}

static bool val_bool(const FemuOpalTok *v, int vn, bool *out)
{
    if (vn != 1 || v->type != FEMU_OPAL_TOK_UINT || v->val > 1) {
        return false;
    }
    *out = v->val;
    return true;
}

/* reset_types set {0} or {0, 3} as a list of uints (Opal 4.3.5.2.2) */
static bool val_resets(const FemuOpalTok *v, int vn, uint8_t *out)
{
    uint8_t m = 0;
    int i;

    if (vn < 2 || !tok_is(&v[0], TOK_SL) || !tok_is(&v[vn - 1], TOK_EL)) {
        return false;
    }
    for (i = 1; i < vn - 1; i++) {
        if (v[i].type != FEMU_OPAL_TOK_UINT || v[i].val > 7 ||
            (m & (1u << v[i].val))) {
            return false;
        }
        m |= 1u << v[i].val;
    }
    if (m != (1u << FEMU_OPAL_RESET_POWER) &&
        m != (1u << FEMU_OPAL_RESET_POWER | 1u << FEMU_OPAL_RESET_PROG)) {
        return false;
    }
    *out = m;
    return true;
}

static void enc_resets(FemuOpalEnc *e, uint8_t m)
{
    int i;

    femu_opal_enc_ctrl(e, TOK_SL);
    for (i = 0; i < 8; i++) {
        if (m & (1u << i)) {
            femu_opal_enc_uint(e, i);
        }
    }
    femu_opal_enc_ctrl(e, TOK_EL);
}

static bool val_name(const FemuOpalTok *v, int vn, FemuOpalPin *out)
{
    if (vn != 1 || v->type != FEMU_OPAL_TOK_BYTES ||
        v->len > FEMU_OPAL_PIN_MAX) {
        return false;
    }
    out->len = v->len;
    memcpy(out->v, v->p, v->len);
    return true;
}

static bool tok_half(const FemuOpalTok *t, uint32_t half)
{
    return t->type == FEMU_OPAL_TOK_BYTES && t->len == 4 &&
           get32(t->p) == half;
}

/* the BooleanExpr bit of a Locking SP authority, or 0 */
static uint32_t expr_bit(uint64_t uid)
{
    int a;

    if (uid == UID_AU_ADMINS) {
        return EXPR_ADMINS;
    }
    if (uid == UID_AU_USERS) {
        return EXPR_USERS;
    }
    a = femu_opal_auth_index(true, uid);
    return a < 0 ? 0 : 1u << a;
}

/*
 * A BooleanExpr (Core Table 210): authority references joined by OR, in
 * postfix. AND, NOT or a bad stack: false (Opal 4.3.1.7 needs only OR).
 */
static bool val_expr(const FemuOpalTok *v, int vn, uint32_t *out)
{
    uint32_t m = 0;
    int depth = 0;
    int i;

    if (vn < 2 || !tok_is(&v[0], TOK_SL) || !tok_is(&v[vn - 1], TOK_EL)) {
        return false;
    }
    for (i = 1; i + 3 < vn; i += 4) {
        uint64_t uid;
        uint32_t bit;

        if (!tok_is(&v[i], TOK_SN) || !tok_is(&v[i + 3], TOK_EN)) {
            return false;
        }
        if (tok_half(&v[i + 1], HALF_AUTHORITY_REF)) {
            if (!tok_uid(&v[i + 2], &uid)) {
                return false;
            }
            bit = expr_bit(uid);
            if (!bit || (m & bit)) {
                return false;
            }
            m |= bit;
            depth++;
        } else if (tok_half(&v[i + 1], HALF_BOOLEAN_ACE)) {
            /* 1 is OR (Core Table 61) */
            if (v[i + 2].type != FEMU_OPAL_TOK_UINT || v[i + 2].val != 1 ||
                depth < 2) {
                return false;
            }
            depth--;
        } else {
            return false;
        }
    }
    if (i != vn - 1 || depth != 1) {
        return false;
    }
    *out = m;
    return true;
}

static void enc_half(FemuOpalEnc *e, uint32_t half)
{
    uint8_t b[4];

    put32(b, half);
    femu_opal_enc_bytes(e, b, 4);
}

static void enc_expr(FemuOpalEnc *e, uint32_t m)
{
    static const uint64_t uids[] = {
        UID_AU_ANYBODY, UID_AU_ADMINS,
        UID_AU_LSP_ADMIN(0), UID_AU_LSP_ADMIN(1), UID_AU_LSP_ADMIN(2),
        UID_AU_LSP_ADMIN(3), UID_AU_USERS,
        UID_AU_USER(0), UID_AU_USER(1), UID_AU_USER(2), UID_AU_USER(3),
        UID_AU_USER(4), UID_AU_USER(5), UID_AU_USER(6), UID_AU_USER(7),
    };
    int k = 0;
    int i;

    femu_opal_enc_ctrl(e, TOK_SL);
    for (i = 0; i < ARRAY_SIZE(uids); i++) {
        if (!(m & expr_bit(uids[i]))) {
            continue;
        }
        femu_opal_enc_ctrl(e, TOK_SN);
        enc_half(e, HALF_AUTHORITY_REF);
        femu_opal_enc_uid(e, uids[i]);
        femu_opal_enc_ctrl(e, TOK_EN);
        if (k++) {
            femu_opal_enc_ctrl(e, TOK_SN);
            enc_half(e, HALF_BOOLEAN_ACE);
            femu_opal_enc_uint(e, 1);
            femu_opal_enc_ctrl(e, TOK_EN);
        }
    }
    femu_opal_enc_ctrl(e, TOK_EL);
}

static void G_GNUC_PRINTF(2, 3) enc_name(FemuOpalEnc *e, const char *fmt,
                                         ...)
{
    char b[64];
    va_list ap;

    va_start(ap, fmt);
    g_vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    femu_opal_enc_bytes(e, b, strlen(b));
}

static void enc_str(FemuOpalEnc *e, const char *s)
{
    femu_opal_enc_bytes(e, s, strlen(s));
}

/* the Name of ACE @i (Opal Table 39) */
static void lsp_ace_name(FemuOpalEnc *e, int i)
{
    static const char *const fixed[] = {
        "ACE_Anybody", "ACE_Admin", "ACE_Anybody_Get_CommonName",
        "ACE_Admins_Set_CommonName", "ACE_ACE_Get_All",
        "ACE_ACE_Set_BooleanExpression", "ACE_Authority_Get_All",
        "ACE_Authority_Set_Enabled",
    };
    static const char *const tail[] = {
        "ACE_Locking_GlblRng_Admins_Set", "ACE_Locking_Admins_RangeStartToLOR",
        "ACE_MBRControl_Admins_Set", "ACE_MBRControl_Set_DoneToDOR",
        "ACE_DataStore_Get_All", "ACE_DataStore_Set_All",
    };
    static const char *const rng[] = {
        "GenKey", "Get_RangeStartToActiveKey", "Set_RdLocked",
        "Set_WrLocked",
    };
    char b[64];
    char g[16];
    int r;

    if (i < ACE_USER_SET_CN) {
        enc_str(e, fixed[i]);
    } else if (i < ACE_CPIN_GET_NOPIN) {
        enc_name(e, "ACE_User%d_Set_CommonName", i - ACE_USER_SET_CN + 1);
    } else if (i == ACE_CPIN_GET_NOPIN) {
        enc_str(e, "ACE_C_PIN_Admins_Get_All_NOPIN");
    } else if (i == ACE_CPIN_ADMINS_SET_PIN) {
        enc_str(e, "ACE_C_PIN_Admins_Set_PIN");
    } else if (i < ACE_KAES_MODE) {
        enc_name(e, "ACE_C_PIN_User%d_Set_PIN",
                 i - ACE_CPIN_USER_SET_PIN + 1);
    } else if (i == ACE_KAES_MODE) {
        enc_str(e, "ACE_K_AES_Mode");
    } else if (i < ACE_GLOBAL_ADMINS_SET) {
        r = (i - ACE_GENKEY) % 9;
        if (r) {
            snprintf(g, sizeof(g), "Range%d", r);
        } else {
            snprintf(g, sizeof(g), "GlobalRange");
        }
        snprintf(b, sizeof(b), "%s%s_%s",
                 i < ACE_LOCK_GET ? "ACE_K_AES_256_" : "ACE_Locking_", g,
                 rng[(i - ACE_GENKEY) / 9]);
        enc_str(e, b);
    } else {
        enc_str(e, tail[i - ACE_GLOBAL_ADMINS_SET]);
    }
}

/* ---- Get ---- */

/* the last column of a Locking SP object, or -1 */
static int lsp_maxcol(uint64_t uid)
{
    if (lsp_table_row(uid) >= 0) {
        return 14;
    }
    if (lsp_template_row(uid) >= 0 || lsp_method_row(uid) >= 0 ||
        uid == UID_SECRETPROTECT_KAES) {
        return 3;
    }
    if (uid == UID_LSP_SPINFO) {
        return 6;
    }
    if (uid == UID_LOCKINGINFO || lsp_lock_row(uid) >= 0) {
        return 10;
    }
    if (uid == UID_MBRCONTROL) {
        return 3;
    }
    if (lsp_key_row(uid) >= 0 || lsp_ace_index(uid) >= 0) {
        return 4;
    }
    if (lsp_authority(uid)) {
        return 18;
    }
    if (lsp_cpin(uid) >= 0) {
        return 7;
    }
    return -1;
}

/* one column of a Locking SP object; false when it has no value */
static bool lsp_col(FemuOpal *o, uint64_t uid, uint32_t col, FemuOpalEnc *e)
{
    const FemuOpalSp *sp = &o->sp;
    int r;
    int a;

    if (col == 0) {
        femu_opal_enc_uid(e, uid);
        return true;
    }
    r = lsp_table_row(uid);
    if (r >= 0) {
        uint32_t rows = lsp_tables[r].rows;

        switch (col) {
        case 1:
            femu_opal_enc_bytes(e, lsp_tables[r].name,
                                strlen(lsp_tables[r].name));
            return true;
        case 4:                                 /* Kind: 1 Object, 2 Byte */
            femu_opal_enc_uint(e, rows ? 2 : 1);
            return true;
        case 7:
            if (!rows) {
                return false;
            }
            femu_opal_enc_uint(e, rows);
            return true;
        case 13:                                /* write granularity */
        case 14:                                /* access granularity */
            femu_opal_enc_uint(e, rows ? 1 : 0);
            return true;
        }
        return false;
    }
    r = lsp_template_row(uid);
    if (r >= 0) {
        switch (col) {
        case 1:
            femu_opal_enc_uid(e, 0x0000020400000000ull |
                              lsp_templates[r].tid);
            return true;
        case 2:
            femu_opal_enc_bytes(e, lsp_templates[r].name,
                                strlen(lsp_templates[r].name));
            return true;
        case 3:
            femu_opal_enc_uint(e, 2);
            return true;
        }
        return false;
    }
    r = lsp_method_row(uid);
    if (r >= 0) {
        if (col != 1) {
            return false;
        }
        femu_opal_enc_bytes(e, lsp_methods[r].name,
                            strlen(lsp_methods[r].name));
        return true;
    }
    if (uid == UID_SECRETPROTECT_KAES) {
        switch (col) {
        case 1:
            femu_opal_enc_uid(e, UID_TABLE(0x0806));
            return true;
        case 2:                                 /* the Key column */
            femu_opal_enc_uint(e, 3);
            return true;
        case 3:                                 /* ProtectMechanisms: VU */
            femu_opal_enc_ctrl(e, TOK_SL);
            femu_opal_enc_ctrl(e, TOK_EL);
            return true;
        }
        return false;
    }
    if (uid == UID_LSP_SPINFO) {
        switch (col) {
        case 1:
            femu_opal_enc_uid(e, UID_SP_LOCKING);
            return true;
        case 2:
            femu_opal_enc_bytes(e, "Locking", 7);
            return true;
        case 3:
        case 4:
        case 5:
            femu_opal_enc_uint(e, 0);
            return true;
        case 6:
            femu_opal_enc_uint(e, 1);
            return true;
        }
        return false;
    }
    if (uid == UID_LOCKINGINFO) {
        /* Version, EncryptSupport, MaxRanges, ... (Core Table 225) */
        static const uint8_t vals[] = { 0, 0, 1, 1, FEMU_OPAL_RANGES, 0, 0,
                                        0, 0, 1, 0 };

        if (col == 1) {
            femu_opal_enc_bytes(e, "", 0);
        } else if (col == 8) {
            femu_opal_enc_uint(e, o->cfg.lba_size);
        } else {
            femu_opal_enc_uint(e, vals[col]);
        }
        return true;
    }
    r = lsp_lock_row(uid);
    if (r >= 0) {
        const FemuOpalRange *g = &sp->range[r];

        switch (col) {
        case 1:
            if (r) {
                enc_name(e, "Locking_Range%d", r);
            } else {
                femu_opal_enc_bytes(e, "Locking_GlobalRange", 19);
            }
            return true;
        case 2:
            femu_opal_enc_bytes(e, g->cn.v, g->cn.len);
            return true;
        case 3:
            femu_opal_enc_uint(e, g->start);
            return true;
        case 4:
            femu_opal_enc_uint(e, g->len);
            return true;
        case 5:
        case 6:
        case 7:
        case 8:
            femu_opal_enc_uint(e, col == 5 ? g->rle : col == 6 ? g->wle :
                                  col == 7 ? g->rl : g->wl);
            return true;
        case 9:
            enc_resets(e, g->lor);
            return true;
        case 10:
            femu_opal_enc_uid(e, UID_KAES(r));
            return true;
        }
        return false;
    }
    if (uid == UID_MBRCONTROL) {
        if (col == 3) {
            enc_resets(e, sp->mbr_dor);
        } else {
            femu_opal_enc_uint(e, col == 1 ? sp->mbr_enable : sp->mbr_done);
        }
        return true;
    }
    r = lsp_key_row(uid);
    if (r >= 0) {
        switch (col) {
        case 1:
            if (r) {
                enc_name(e, "K_AES_256_Range%d_Key", r);
            } else {
                femu_opal_enc_bytes(e, "K_AES_256_GlobalRange_Key", 25);
            }
            return true;
        case 2:
            femu_opal_enc_bytes(e, "", 0);
            return true;
        case 4:                                 /* Mode: Media Encryption */
            femu_opal_enc_uint(e, 23);
            return true;
        }
        return false;                           /* the Key stays hidden */
    }
    a = lsp_ace_index(uid);
    if (a >= 0) {
        uint32_t cols = lsp_ace_cols(a);
        int c;

        switch (col) {
        case 1:
            lsp_ace_name(e, a);
            return true;
        case 3:
            enc_expr(e, sp->ace[a]);
            return true;
        case 4:                                 /* Columns: empty is All */
            femu_opal_enc_ctrl(e, TOK_SL);
            for (c = 0; cols != COLS_ALL && c < 32; c++) {
                if (cols & (1u << c)) {
                    femu_opal_enc_uint(e, c);
                }
            }
            femu_opal_enc_ctrl(e, TOK_EL);
            return true;
        }
        return false;
    }
    a = lsp_cpin(uid);
    if (a >= 0) {
        switch (col) {
        case 1:
            if (a < FEMU_OPAL_AU_LSP_USER1) {
                enc_name(e, "C_PIN_Admin%d", a - FEMU_OPAL_AU_LSP_ADMIN1 + 1);
            } else {
                enc_name(e, "C_PIN_User%d", a - FEMU_OPAL_AU_LSP_USER1 + 1);
            }
            return true;
        case 2:
            femu_opal_enc_bytes(e, "", 0);
            return true;
        case 4:
            femu_opal_enc_uid(e, 0);
            return true;
        case 5:
            femu_opal_enc_uint(e, sp->au[a].try_limit);
            return true;
        case 6:
            femu_opal_enc_uint(e, o->tries[a]);
            return true;
        case 7:
            femu_opal_enc_uint(e, 0);
            return true;
        }
        return false;                           /* the PIN stays hidden */
    }
    if (lsp_authority(uid)) {
        bool cls = femu_opal_auth_class(true, uid);
        bool users;

        a = femu_opal_auth_index(true, uid);
        users = cls ? uid == UID_AU_USERS : a >= FEMU_OPAL_AU_LSP_USER1;
        switch (col) {
        case 1:
            if (a == FEMU_OPAL_AU_ANYBODY) {
                femu_opal_enc_bytes(e, "Anybody", 7);
            } else if (cls) {
                femu_opal_enc_bytes(e, users ? "Users" : "Admins",
                                    users ? 5 : 6);
            } else if (users) {
                enc_name(e, "User%d", a - FEMU_OPAL_AU_LSP_USER1 + 1);
            } else {
                enc_name(e, "Admin%d", a - FEMU_OPAL_AU_LSP_ADMIN1 + 1);
            }
            return true;
        case 2:
            if (cls) {
                femu_opal_enc_bytes(e, "", 0);
            } else {
                femu_opal_enc_bytes(e, sp->au_cn[a].v, sp->au_cn[a].len);
            }
            return true;
        case 3:
            femu_opal_enc_uint(e, cls);
            return true;
        case 4:
            femu_opal_enc_uid(e, cls || a == FEMU_OPAL_AU_ANYBODY ? 0 :
                              users ? UID_AU_USERS : UID_AU_ADMINS);
            return true;
        case 5:
            femu_opal_enc_uint(e, cls || sp->au[a].enabled);
            return true;
        case 6:                                 /* Secure: None */
        case 7:                                 /* HashAndSign: None */
        case 8:                                 /* PresentCertificate */
            femu_opal_enc_uint(e, 0);
            return true;
        case 9:                                 /* Operation: Password */
            femu_opal_enc_uint(e, !cls && a != FEMU_OPAL_AU_ANYBODY);
            return true;
        case 11:                                /* ResponseSign */
        case 12:                                /* ResponseExch */
            femu_opal_enc_uid(e, 0);
            return true;
        case 10:
            femu_opal_enc_uid(e, cls || a == FEMU_OPAL_AU_ANYBODY ? 0 :
                              lsp_cpin_uid(a));
            return true;
        }
        return false;
    }
    return false;
}

/* Get[Cellblock startRow = 1, endRow = 2] on a byte table (Core 5.3.3.6) */
static void lsp_byte_get(FemuOpal *o, bool ds, const FemuOpalTok *t, int n,
                         FemuOpalReply *r)
{
    uint64_t size = ds ? FEMU_OPAL_DS_SIZE : FEMU_OPAL_MBR_SIZE;
    uint64_t start = 0;
    uint64_t end = size - 1;
    uint8_t buf[FEMU_OPAL_BUF];
    int i;

    if (n < 2 || !tok_is(&t[0], TOK_SL) || !tok_is(&t[n - 1], TOK_EL)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    for (i = 1; i < n - 1; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n - 1, i, &name);

        if (!v || v->type != FEMU_OPAL_TOK_UINT || (name != 1 && name != 2)) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        if (name == 1) {
            start = v->val;
        } else {
            end = v->val;
        }
    }
    /* the bytes, their framing and the status list fit one response */
    if (start > end || end >= size ||
        end - start + 1 + 24 > r->e.cap - r->e.len) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    lsp_bytes_read(o, ds, false, start, buf, end - start + 1);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_bytes(&r->e, buf, end - start + 1);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

static void lsp_get(FemuOpal *o, uint64_t uid, const FemuOpalTok *t, int n,
                    FemuOpalReply *r)
{
    int ace[4] = { 0 };
    int na = lsp_acl(uid, UID_M_GET, ace);
    uint32_t cols = lsp_grant(o, ace, na);
    uint64_t start = 0;
    uint64_t end;
    bool have_end = false;
    uint32_t c;
    int i;

    if (!cols) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (uid == UID_T_MBR || uid == UID_T_DATASTORE) {
        lsp_byte_get(o, uid == UID_T_DATASTORE, t, n, r);
        return;
    }
    if (n < 2 || !tok_is(&t[0], TOK_SL) || !tok_is(&t[n - 1], TOK_EL)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    for (i = 1; i < n - 1; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n - 1, i, &name);

        if (!v || v->type != FEMU_OPAL_TOK_UINT || (name != 3 && name != 4)) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        if (name == 3) {
            start = v->val;
        } else {
            end = v->val;
            have_end = true;
        }
    }
    if (!have_end) {
        end = lsp_maxcol(uid);
    }
    if (start > end || end > lsp_maxcol(uid)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    for (c = start; c <= end; c++) {
        uint32_t mark = r->e.len;

        if (!(cols & (1u << c))) {
            continue;
        }
        femu_opal_enc_ctrl(&r->e, TOK_SN);
        femu_opal_enc_uint(&r->e, c);
        if (!lsp_col(o, uid, c, &r->e)) {
            r->e.len = mark;
            continue;
        }
        femu_opal_enc_ctrl(&r->e, TOK_EN);
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* ---- Set ---- */

/* Set[Where = offset, Values = bytes] on a byte table (Core 5.3.3.7) */
static void lsp_byte_set(FemuOpal *o, bool ds, const FemuOpalTok *t, int n,
                         FemuOpalReply *r)
{
    uint64_t size = ds ? FEMU_OPAL_DS_SIZE : FEMU_OPAL_MBR_SIZE;
    const FemuOpalTok *val = NULL;
    uint64_t off = 0;
    int i;

    for (i = 0; i < n; i += 4) {
        uint64_t name = ~0ull;
        const FemuOpalTok *v = named(t, n, i, &name);

        if (v && name == 0 && v->type == FEMU_OPAL_TOK_UINT && !val) {
            off = v->val;
        } else if (v && name == 1 && v->type == FEMU_OPAL_TOK_BYTES) {
            val = v;
        } else {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
    }
    if (val && (off > size || val->len > size - off)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    if (val && val->len) {
        if (o->s.txn && !lsp_undo_save(o, ds, off, val->len)) {
            r->status = FEMU_OPAL_ST_FAIL;
            return;
        }
        lsp_bytes_write(o, ds, off, val->p, val->len);
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* apply column @col = v[0..vn) to @next; false: INVALID_PARAMETER */
static bool lsp_apply(FemuOpalSp *next, uint64_t uid, uint32_t col,
                      const FemuOpalTok *v, int vn)
{
    int r = lsp_lock_row(uid);
    int a;
    int ai;

    if (r >= 0) {
        FemuOpalRange *g = &next->range[r];

        switch (col) {
        case 2:
            return val_name(v, vn, &g->cn);
        case 3:
        case 4:
            if (vn != 1 || v->type != FEMU_OPAL_TOK_UINT) {
                return false;
            }
            *(col == 3 ? &g->start : &g->len) = v->val;
            return true;
        case 5:
            return val_bool(v, vn, &g->rle);
        case 6:
            return val_bool(v, vn, &g->wle);
        case 7:
            return val_bool(v, vn, &g->rl);
        case 8:
            return val_bool(v, vn, &g->wl);
        case 9:
            return val_resets(v, vn, &g->lor);
        }
        return false;
    }
    if (uid == UID_MBRCONTROL) {
        switch (col) {
        case 1:
            return val_bool(v, vn, &next->mbr_enable);
        case 2:
            return val_bool(v, vn, &next->mbr_done);
        case 3:
            return val_resets(v, vn, &next->mbr_dor);
        }
        return false;
    }
    a = femu_opal_auth_index(true, uid);
    if (a > FEMU_OPAL_AU_ANYBODY) {
        if (col == 2) {
            return val_name(v, vn, &next->au_cn[a]);
        }
        return col == 5 && val_bool(v, vn, &next->au[a].enabled);
    }
    a = lsp_cpin(uid);
    if (a >= 0) {
        /* a PIN of at most 32 bytes (Core 5.1.3.63) */
        return col == 3 && val_name(v, vn, &next->au[a].pin);
    }
    ai = lsp_ace_index(uid);
    if (ai >= 0 && col == 3) {
        uint32_t m;

        if (!val_expr(v, vn, &m)) {
            return false;
        }
        /* *ACE1: only Admins, or Admins OR UserN (Opal 4.3.1.7) */
        if (ai >= ACE_CPIN_USER_SET_PIN && ai < ACE_KAES_MODE &&
            m != EXPR_ADMINS &&
            m != (EXPR_ADMINS | EXPR_USER(ai - ACE_CPIN_USER_SET_PIN))) {
            return false;
        }
        next->ace[ai] = m;
        return true;
    }
    return false;
}

/*
 * Non-global ranges never overlap. A range the Set moves must stay inside
 * the namespace; one it leaves alone may lie past the end after a Format
 * that shrank the LBA count (its LBA numbers stay).
 */
static bool lsp_ranges_ok(const FemuOpal *o, const FemuOpalSp *sp)
{
    int i;
    int j;

    for (i = 1; i <= FEMU_OPAL_RANGES; i++) {
        const FemuOpalRange *a = &sp->range[i];
        const FemuOpalRange *was = &o->sp.range[i];
        bool moved = a->start != was->start || a->len != was->len;

        if (!a->len) {
            continue;
        }
        if (a->start + a->len < a->start ||
            (moved && o->cfg.nlbas && a->start + a->len > o->cfg.nlbas)) {
            return false;
        }
        for (j = i + 1; j <= FEMU_OPAL_RANGES; j++) {
            const FemuOpalRange *b = &sp->range[j];

            if (b->len && a->start < b->start + b->len &&
                b->start < a->start + a->len) {
                return false;
            }
        }
    }
    return true;
}

/*
 * Set on a Locking SP object: SN 1 SL {SN col value EN} EL EN. Every
 * column is checked before any change. A column no passing ACE grants:
 * NOT_AUTHORIZED. A bad value, a column twice, an overlap: INVALID.
 */
static void lsp_set(FemuOpal *o, uint64_t uid, const FemuOpalTok *t, int n,
                    FemuOpalReply *r)
{
    FemuOpalSp next = o->sp;
    int ace[4] = { 0 };
    int na = lsp_acl(uid, UID_M_SET, ace);
    uint32_t cols = lsp_grant(o, ace, na);
    uint32_t seen = 0;
    bool denied = false;
    int i;

    if (!na || !o->s.write) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (!cols) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (uid == UID_T_MBR || uid == UID_T_DATASTORE) {
        lsp_byte_set(o, uid == UID_T_DATASTORE, t, n, r);
        return;
    }
    if (n && (n < 5 || !tok_is(&t[0], TOK_SN) ||
              t[1].type != FEMU_OPAL_TOK_UINT || t[1].val != 1 ||
              !tok_is(&t[2], TOK_SL) ||
              !tok_is(&t[n - 2], TOK_EL) || !tok_is(&t[n - 1], TOK_EN))) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    for (i = 3; i < n - 2;) {
        const FemuOpalTok *col = &t[i + 1];
        int ve;

        if (i + 3 >= n - 1 || !tok_is(&t[i], TOK_SN) ||
            col->type != FEMU_OPAL_TOK_UINT ||
            col->val > lsp_maxcol(uid) || (seen & (1u << col->val))) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        ve = value_end(t, n - 2, i + 2);
        if (ve < 0 || ve >= n - 2 || !tok_is(&t[ve], TOK_EN)) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        seen |= 1u << col->val;
        if (!(cols & (1u << col->val))) {
            denied = true;
        } else if (!lsp_apply(&next, uid, col->val, &t[i + 2],
                              ve - (i + 2))) {
            r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
            return;
        }
        i = ve + 1;
    }
    if (denied) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (!lsp_ranges_ok(o, &next)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    o->sp = next;
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* ---- other methods ---- */

/* GenKey on a K_AES_256 row (Core 5.3.3.16): a new key erases its LBAs */
static void lsp_genkey(FemuOpal *o, uint64_t uid, int n, FemuOpalReply *r)
{
    int k = lsp_key_row(uid);

    if (k < 0 || !lsp_allowed(o, uid, UID_M_GENKEY) || !o->s.write) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    if (n) {
        /* PinLength and PublicExponent do not apply to a K_AES row */
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    o->sp.range[k].key = o->next_key++;
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/*
 * RevertSP[KeepGlobalRangeKey = 060000h] on ThisSP of the Locking SP
 * (Opal 5.1.3). The SP goes back to Manufactured-Inactive and the session
 * ends after the status. Returns true when the session must end.
 */
static bool lsp_revertsp(FemuOpal *o, const FemuOpalTok *t, int n,
                         FemuOpalReply *r)
{
    const FemuOpalRange *g = &o->sp.range[0];
    bool keep = false;
    uint64_t name = ~0ull;
    const FemuOpalTok *v = n == 4 ? named(t, n, 0, &name) : NULL;

    if (!lsp_allowed(o, UID_THISSP, UID_M_REVERTSP) || !o->s.write) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return false;
    }
    if ((n && (!v || name != 0x060000 || !val_bool(v, 1, &keep))) ||
        o->s.txn) {
        r->status = o->s.txn ? FEMU_OPAL_ST_FAIL :
                               FEMU_OPAL_ST_INVALID_PARAMETER;
        return false;
    }
    if (keep && g->rle && g->rl && g->wle && g->wl) {
        r->status = FEMU_OPAL_ST_FAIL;
        return false;
    }
    femu_opal_factory_lsp(o, keep);
    lsp_bytes_clear(o);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    return true;
}

static void lsp_getacl(FemuOpal *o, const FemuOpalTok *t, int n,
                       FemuOpalReply *r)
{
    uint64_t obj;
    uint64_t m;
    int ace[4] = { 0 };
    int na;
    int i;

    if (n != 2 || !tok_uid(&t[0], &obj) || !tok_uid(&t[1], &m)) {
        r->status = FEMU_OPAL_ST_INVALID_PARAMETER;
        return;
    }
    na = lsp_acl(obj, m, ace);
    if (!na) {
        r->status = FEMU_OPAL_ST_NOT_AUTHORIZED;
        return;
    }
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    femu_opal_enc_ctrl(&r->e, TOK_SL);
    for (i = 0; i < na; i++) {
        femu_opal_enc_uid(&r->e, lsp_ace_uid(ace[i]));
    }
    femu_opal_enc_ctrl(&r->e, TOK_EL);
    femu_opal_enc_ctrl(&r->e, TOK_EL);
}

/* the rows Next walks in the Locking SP, in table order; returns the count */
static int lsp_rows(uint64_t table, uint64_t *rows)
{
    int k = 0;
    int i;

    switch (table) {
    case UID_T_LOCKING:
        for (i = 0; i <= FEMU_OPAL_RANGES; i++) {
            rows[k++] = UID_LOCKING(i);
        }
        break;
    case UID_T_AUTHORITY:
        rows[k++] = UID_AU_ANYBODY;
        rows[k++] = UID_AU_ADMINS;
        for (i = 0; i < 4; i++) {
            rows[k++] = UID_AU_LSP_ADMIN(i);
        }
        rows[k++] = UID_AU_USERS;
        for (i = 0; i < 8; i++) {
            rows[k++] = UID_AU_USER(i);
        }
        break;
    case UID_T_CPIN:
        for (i = 0; i < 4; i++) {
            rows[k++] = UID_LSP_CPIN_ADMIN(i);
        }
        for (i = 0; i < 8; i++) {
            rows[k++] = UID_LSP_CPIN_USER(i);
        }
        break;
    case UID_T_ACE:
        for (i = 0; i < ACE_END; i++) {
            rows[k++] = lsp_ace_uid(i);
        }
        break;
    case UID_T_TABLE:
        for (i = 0; i < ARRAY_SIZE(lsp_tables); i++) {
            rows[k++] = UID_TABLE(lsp_tables[i].t);
        }
        break;
    case UID_T_SPTEMPLATES:
        rows[k++] = UID_T_SPTEMPLATES + 1;
        rows[k++] = UID_T_SPTEMPLATES + 2;
        break;
    case UID_T_METHODID:
        for (i = 0; i < ARRAY_SIZE(lsp_methods); i++) {
            rows[k++] = lsp_methods[i].uid;
        }
        break;
    case UID_T_SECRETPROTECT:
        rows[k++] = UID_SECRETPROTECT_KAES;
        break;
    }
    return k;
}
