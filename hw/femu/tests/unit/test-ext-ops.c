/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The table checks and the distinct mode walk of the FEMU extension
 * interface (femu-ext-ops.h, bbssd/ftl-ops.h). Each check meets good
 * tables and one bad case per rule it enforces, so a check that accepts
 * everything fails here.
 */

#include "qemu/osdep.h"

/* the FTL interface names struct ppa by value; the test needs a body */
struct ppa {
    uint64_t ppa;
};

#include "hw/femu/femu-ext-ops.h"
#include "hw/femu/bbssd/ftl-ops.h"

static uint16_t fake_io(struct FemuCtrl *n, struct NvmeNamespace *ns,
                        struct NvmeCmd *cmd, struct NvmeRequest *req)
{
    return 0;
}

static uint16_t fake_admin(struct FemuCtrl *n, struct NvmeCmd *cmd)
{
    return 0;
}

static uint16_t fake_admin_cqe(struct FemuCtrl *n, struct NvmeCmd *cmd,
                               struct NvmeCqe *cqe)
{
    return 0;
}

static int fake_start(struct FemuCtrl *n)
{
    return 0;
}

static int fake_start2(struct FemuCtrl *n)
{
    return 0;
}

static void fake_exit(struct FemuCtrl *n)
{
}

static void fake_exit2(struct FemuCtrl *n)
{
}

static const FemuExtCtrlOps good_ext = {
    .name = "bbssd",
    .io_cmd = fake_io,
    .admin_cmd = fake_admin,
};

static void expect_ext_refused(const FemuExtCtrlOps *ops, const char *rule)
{
    const char *why = NULL;

    g_assert_false(femu_ext_ops_check(ops, &why));
    g_assert_cmpstr(why, ==, rule);
}

static void test_ext_check(void)
{
    FemuExtCtrlOps t;
    int state;
    const char *why = "unchanged";

    g_assert_true(femu_ext_ops_check(&good_ext, &why));
    g_assert_cmpstr(why, ==, "unchanged");
    g_assert_true(femu_ext_ops_check(&good_ext, NULL));

    expect_ext_refused(NULL, "no table");

    t = good_ext;
    t.name = NULL;
    expect_ext_refused(&t, "no name");
    t.name = "";
    expect_ext_refused(&t, "no name");

    t = good_ext;
    t.io_cmd = NULL;
    expect_ext_refused(&t, "no io_cmd");

    t = good_ext;
    t.admin_cmd_cqe = fake_admin_cqe;
    expect_ext_refused(&t, "both admin_cmd and admin_cmd_cqe");
    t.admin_cmd = NULL;
    g_assert_true(femu_ext_ops_check(&t, NULL));

    t = good_ext;
    t.state = &state;
    expect_ext_refused(&t, "state set in the exported table");
    g_assert_false(femu_ext_ops_check(&t, NULL));
}

static void test_ext_check_set(void)
{
    FemuExtCtrlOps a = good_ext;
    FemuExtCtrlOps b = good_ext;
    const FemuExtCtrlOps *set[] = { &a, &b };
    const char *why = NULL;

    b.name = "znssd";
    a.start_ctrl = fake_start;
    b.start_ctrl = fake_start2;
    a.exit = fake_exit;
    b.exit = fake_exit2;
    g_assert_true(femu_ext_ops_check_set(set, 2, NULL));
    g_assert_true(femu_ext_ops_check_set(set, 0, NULL));

    /* NULL hooks may repeat */
    b.start_ctrl = NULL;
    a.start_ctrl = NULL;
    g_assert_true(femu_ext_ops_check_set(set, 2, NULL));

    b.name = "bbssd";
    g_assert_false(femu_ext_ops_check_set(set, 2, &why));
    g_assert_cmpstr(why, ==, "two tables share a name");
    b.name = "znssd";

    a.start_ctrl = fake_start;
    b.start_ctrl = fake_start;
    g_assert_false(femu_ext_ops_check_set(set, 2, &why));
    g_assert_cmpstr(why, ==, "two tables share start_ctrl");
    b.start_ctrl = fake_start2;

    b.exit = fake_exit;
    g_assert_false(femu_ext_ops_check_set(set, 2, &why));
    g_assert_cmpstr(why, ==, "two tables share exit");
}

static void test_ext_distinct(void)
{
    FemuExtCtrlOps bb = good_ext;
    FemuExtCtrlOps bb_copy = good_ext;
    FemuExtCtrlOps kv = good_ext;
    FemuExtCtrlOps zns = good_ext;
    FemuExtCtrlOps none = good_ext;
    const FemuExtCtrlOps *out[8];
    size_t n;

    kv.name = "kvssd";
    zns.name = "znssd";
    none.name = NULL;

    /* the controller copy first; namespace copies are other pointers */
    {
        const FemuExtCtrlOps *list[] = {
            &kv, &bb, &bb_copy, NULL, &none, &zns, &kv,
        };

        n = femu_ext_ops_distinct(list, G_N_ELEMENTS(list), out,
                                  G_N_ELEMENTS(out));
        g_assert_cmpuint(n, ==, 3);
        g_assert_true(out[0] == &kv);
        g_assert_true(out[1] == &bb);
        g_assert_true(out[2] == &zns);

        /* no room past max, and the order holds */
        n = femu_ext_ops_distinct(list, G_N_ELEMENTS(list), out, 2);
        g_assert_cmpuint(n, ==, 2);
        g_assert_true(out[0] == &kv);
        g_assert_true(out[1] == &bb);

        n = femu_ext_ops_distinct(list, 0, out, G_N_ELEMENTS(out));
        g_assert_cmpuint(n, ==, 0);
    }

    /* one mode on every namespace: one call, to the controller copy */
    {
        const FemuExtCtrlOps *list[] = { &bb, &bb_copy, &bb_copy };

        n = femu_ext_ops_distinct(list, G_N_ELEMENTS(list), out,
                                  G_N_ELEMENTS(out));
        g_assert_cmpuint(n, ==, 1);
        g_assert_true(out[0] == &bb);
    }
}

static struct ppa fake_translate(struct ssd *ssd, uint64_t lpn)
{
    return (struct ppa) { .ppa = lpn };
}

static struct map_write_plan fake_prepare(struct ssd *ssd, uint64_t lpn,
                                          int io_type)
{
    return (struct map_write_plan) { .target_class = FEMU_MAP_CLASS_DATA };
}

static void fake_commit(struct ssd *ssd, uint64_t lpn, struct ppa *new_ppa)
{
}

static void fake_relocate(struct ssd *ssd, uint64_t lpn, struct ppa *old_ppa,
                          struct ppa *new_ppa)
{
}

static bool fake_needs(struct ssd *ssd)
{
    return false;
}

static uint64_t fake_reclaim(struct ssd *ssd, int budget)
{
    return 0;
}

static const struct femu_mapping_ops good_map = {
    .name = "page",
    .translate = fake_translate,
    .prepare_write = fake_prepare,
    .commit_write = fake_commit,
    .gc_relocate_commit = fake_relocate,
};

static void expect_map_refused(const struct femu_mapping_ops *ops,
                               const char *rule)
{
    const char *why = NULL;

    g_assert_false(femu_mapping_ops_check(ops, &why));
    g_assert_cmpstr(why, ==, rule);
}

static void test_map_check(void)
{
    struct femu_mapping_ops t;

    g_assert_true(femu_mapping_ops_check(&good_map, NULL));
    expect_map_refused(NULL, "no table");

    t = good_map;
    t.name = NULL;
    expect_map_refused(&t, "no name");

    t = good_map;
    t.translate = NULL;
    expect_map_refused(&t, "a required hook is NULL");
    t = good_map;
    t.prepare_write = NULL;
    expect_map_refused(&t, "a required hook is NULL");
    t = good_map;
    t.commit_write = NULL;
    expect_map_refused(&t, "a required hook is NULL");
    t = good_map;
    t.gc_relocate_commit = NULL;
    expect_map_refused(&t, "a required hook is NULL");

    t = good_map;
    t.needs_reclaim = fake_needs;
    expect_map_refused(&t, "needs_reclaim and reclaim must come together");
    t.needs_reclaim = NULL;
    t.reclaim = fake_reclaim;
    expect_map_refused(&t, "needs_reclaim and reclaim must come together");
    t.needs_reclaim = fake_needs;
    g_assert_true(femu_mapping_ops_check(&t, NULL));

    t = good_map;
    t.reclaim_per_page = true;
    expect_map_refused(&t, "reclaim_per_page without reclaim");
    t.needs_reclaim = fake_needs;
    t.reclaim = fake_reclaim;
    g_assert_true(femu_mapping_ops_check(&t, NULL));
}

static struct line *fake_select(struct ssd *ssd, bool force)
{
    return NULL;
}

static void test_policy_check(void)
{
    struct femu_ftl_policy_ops t = {
        .name = "greedy",
        .select_victim_line = fake_select,
        .fdp_strategy = FEMU_FDP_FROM_GC_STRATEGY,
    };
    const char *why = NULL;

    g_assert_true(femu_ftl_policy_ops_check(&t, NULL));
    t.fdp_strategy = 6;
    g_assert_true(femu_ftl_policy_ops_check(&t, NULL));

    g_assert_false(femu_ftl_policy_ops_check(NULL, &why));
    g_assert_cmpstr(why, ==, "no table");

    /* an omitted fdp_strategy reads as 0 and is refused */
    t.fdp_strategy = 0;
    g_assert_false(femu_ftl_policy_ops_check(&t, &why));
    g_assert_cmpstr(why, ==, "no fdp_strategy");
    t.fdp_strategy = -2;
    g_assert_false(femu_ftl_policy_ops_check(&t, &why));
    g_assert_cmpstr(why, ==, "no fdp_strategy");
    t.fdp_strategy = FEMU_FDP_FROM_GC_STRATEGY;

    t.select_victim_line = NULL;
    g_assert_false(femu_ftl_policy_ops_check(&t, &why));
    g_assert_cmpstr(why, ==, "no select_victim_line");
    t.select_victim_line = fake_select;

    t.name = "";
    g_assert_false(femu_ftl_policy_ops_check(&t, &why));
    g_assert_cmpstr(why, ==, "no name");
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/ext-ops/check", test_ext_check);
    g_test_add_func("/femu/ext-ops/check-set", test_ext_check_set);
    g_test_add_func("/femu/ext-ops/distinct", test_ext_distinct);
    g_test_add_func("/femu/ftl-ops/mapping-check", test_map_check);
    g_test_add_func("/femu/ftl-ops/policy-check", test_policy_check);
    return g_test_run();
}
