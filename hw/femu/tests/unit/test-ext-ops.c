/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The table checks and the distinct mode walk of the mode handler tables
 * (femu-ext-ops.h). Each check meets good tables and one bad case per rule
 * it enforces, so a check that accepts everything fails here.
 */

#include "qemu/osdep.h"

#include "hw/femu/femu-ext-ops.h"

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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/ext-ops/check", test_ext_check);
    g_test_add_func("/femu/ext-ops/check-set", test_ext_check_set);
    g_test_add_func("/femu/ext-ops/distinct", test_ext_distinct);
    return g_test_run();
}
