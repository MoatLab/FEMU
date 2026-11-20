/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_EXT_OPS_H
#define FEMU_EXT_OPS_H

/*
 * The mode handler table: what each FEMU mode adds to the NVMe front end.
 *
 * Each mode (bbssd, nossd, zns, ocssd 1.2 and 2.0, csd, kvssd) exports one
 * constant table. Realize copies the table of the controller's mode into
 * FemuCtrl.ext_ops, and the table of each namespace's mode into
 * NvmeNamespace.ext_ops. The front end then calls the hooks below.
 *
 *   hook             context                         I/O processing
 *   ---------------  ------------------------------  ---------------------
 *   init, ns_exit    BQL: realize, or an admin       not started, or paused
 *                    command (namespace create or
 *                    delete) on a vCPU
 *   init_ctrl_name   BQL: realize                    not started
 *   exit             BQL: realize undo, unrealize    stopped
 *   start_ctrl       BQL: CC.EN write                not running
 *   admin_cmd(_cqe)  BQL: admin queue                runs
 *   get_log          BQL: admin queue                runs
 *   io_cmd           poller thread, or the FTL       runs; no BQL; the
 *                    thread with power_loss          subsystem ns_lock
 *                                                    if shared
 *
 * Rules for every table:
 *
 * - io_cmd, admin_cmd, admin_cmd_cqe and get_log return an NVMe status;
 *   0 is success. The front end returns it as it is, with no other hook
 *   tried. start_ctrl returns 0 or -1. init reports through its Error.
 * - io_cmd never takes the BQL, and copies guest memory with femu_dma_rw().
 *   Request times keep the clock that set them (femu_io_now()).
 * - exit runs at most once per mode and controller, also after a realize
 *   that failed before init. ns_exit may run before it for the same
 *   namespace. Each frees only what it finds.
 * - Two modes never share a start_ctrl or an exit function: the walks of the
 *   distinct modes call one hook per @name.
 * - The table a mode exports has a NULL state. State belongs to an instance:
 *   the controller copy or a namespace copy, see @state.
 *
 * femu_ext_ops_check() and femu_ext_ops_check_set() refuse tables that break
 * a rule they can see.
 *
 * Version rule: an optional hook, whose NULL keeps the old behaviour, keeps
 * the version. A new required hook, a changed signature or rule, or a
 * removed hook adds one.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FEMU_EXT_OPS_VERSION 1

struct Error;
struct FemuCtrl;
struct NvmeCmd;
struct NvmeCqe;
struct NvmeNamespace;
struct NvmeRequest;

/**
 * struct FemuExtCtrlOps - hooks of one FEMU mode
 * @name: unique name of the table, for example "bbssd" or "ocssd20". The
 *        walks of the distinct modes key on it.
 * @state: instance state. The controller copy holds controller-wide state
 *         (OC 2.0 from registration on; KV points it at its first
 *         namespace's store). A namespace copy holds that namespace's state
 *         (KV). Registration leaves a namespace copy NULL for its init.
 * @init_ctrl_name: set the Identify model number and serial. With ns_mgmt it
 *                  runs once per boot namespace; with no namespace of the
 *                  controller's mode, the controller copy runs with a NULL
 *                  namespace. Without ns_mgmt, @init sets the name.
 * @init: build the mode's state for one namespace. Runs at realize for each
 *        namespace of the mode, and at Namespace Management create. Sets
 *        @errp on failure.
 * @exit: free the mode's state for the whole controller.
 * @ns_exit: free one namespace's state at namespace delete or release, and
 *           for each slot when shared storage goes.
 * @start_ctrl: check the host's controller settings at CC.EN, once per
 *              distinct mode. Non-zero keeps the controller from ready.
 * @admin_cmd: serve an admin opcode the front end does not handle. Only the
 *             controller copy runs.
 * @admin_cmd_cqe: as @admin_cmd, with the completion entry to fill. A table
 *                 sets at most one of the two.
 * @io_cmd: serve an I/O opcode the front end does not handle, and every I/O
 *          opcode of an SLM or CP namespace. Required.
 * @get_log: serve a log page the front end does not handle. The named
 *           namespace's copy runs if it has the hook, else the controller
 *           copy.
 *
 * Admin commands reach only the controller copy, so an admin opcode of a
 * namespace in another mode is not served.
 */
typedef struct FemuExtCtrlOps {
    const char *name;
    void       *state;
    void       (*init_ctrl_name)(struct FemuCtrl *n,
                                 struct NvmeNamespace *ns);
    void       (*init)(struct FemuCtrl *n, struct NvmeNamespace *ns,
                       struct Error **errp);
    void       (*exit)(struct FemuCtrl *n);
    void       (*ns_exit)(struct FemuCtrl *n, struct NvmeNamespace *ns);
    int        (*start_ctrl)(struct FemuCtrl *n);
    uint16_t   (*admin_cmd)(struct FemuCtrl *n, struct NvmeCmd *cmd);
    uint16_t   (*admin_cmd_cqe)(struct FemuCtrl *n, struct NvmeCmd *cmd,
                                struct NvmeCqe *cqe);
    uint16_t   (*io_cmd)(struct FemuCtrl *n, struct NvmeNamespace *ns,
                         struct NvmeCmd *cmd, struct NvmeRequest *req);
    uint16_t   (*get_log)(struct FemuCtrl *n, struct NvmeCmd *cmd);
} FemuExtCtrlOps;

extern const FemuExtCtrlOps femu_bbssd_ext_ops;
extern const FemuExtCtrlOps femu_nossd_ext_ops;
extern const FemuExtCtrlOps femu_zns_ext_ops;
extern const FemuExtCtrlOps femu_ocssd12_ext_ops;
extern const FemuExtCtrlOps femu_ocssd20_ext_ops;
extern const FemuExtCtrlOps femu_csd_ext_ops;
extern const FemuExtCtrlOps femu_kvssd_ext_ops;

/**
 * femu_ext_ops_check - check one exported table against the rules
 * @ops: the table a mode exports, not a live copy
 * @why: set to the broken rule when the check fails; may be NULL
 *
 * Returns: true when @ops has a name and @io_cmd, at most one of the two
 * admin hooks, and a NULL state.
 */
bool femu_ext_ops_check(const FemuExtCtrlOps *ops, const char **why);

/**
 * femu_ext_ops_check_set - check that the tables of all modes fit together
 * @set: every exported table
 * @nr: entries in @set
 * @why: set to the broken rule when the check fails; may be NULL
 *
 * Returns: true when no two tables share a name, a non-NULL start_ctrl or a
 * non-NULL exit. The walks of the distinct modes depend on this.
 */
bool femu_ext_ops_check_set(const FemuExtCtrlOps *const *set, size_t nr,
                            const char **why);

/**
 * femu_ext_ops_distinct - the first table of each mode in a list
 * @list: tables in call order, the controller copy first; NULL entries and
 *        tables with no name are skipped
 * @nr: entries in @list
 * @out: receives the first table of each distinct name, in @list order
 * @max: room in @out; tables past it are dropped
 *
 * Returns: the number of tables written to @out.
 */
size_t femu_ext_ops_distinct(const FemuExtCtrlOps *const *list, size_t nr,
                             const FemuExtCtrlOps **out, size_t max);

#endif
