/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_EXT_OPS_H
#define FEMU_EXT_OPS_H

/*
 * The mode handler table: what each FEMU mode adds to the NVMe front end.
 *
 * Each mode (bbssd, nossd, zns, ocssd 1.2 and 2.0, csd, kvssd) exports one
 * constant table. Realize copies the table of the controller's femu_mode into
 * FemuCtrl.ext_ops, and the table of each namespace's mode into
 * NvmeNamespace.ext_ops. The front end then calls the hooks below.
 *
 *   hook             thread                     lock
 *   ---------------  -------------------------  ---------------------------
 *   init, exit,      main loop: realize, its    BQL; pollers and the FTL
 *   ns_exit,         undo, unrealize, and       thread are not running, or
 *   init_ctrl_name   namespace create/delete    are paused
 *   start_ctrl       vCPU, CC.EN write          BQL; pollers not started
 *   admin_cmd(_cqe)  vCPU or main loop          BQL
 *   get_log          vCPU or main loop          BQL
 *   io_cmd           poller thread              no BQL; the subsystem
 *                                               ns_lock if shared
 *
 * Rules for every table:
 *
 * - A hook that returns uint16_t returns an NVMe status; 0 is success.
 * - io_cmd never takes the BQL, and copies guest memory with femu_dma_rw().
 * - Time is femu_dev_now() in nanoseconds.
 * - exit and ns_exit may run more than once for one namespace, and after a
 *   realize that failed before init. Each frees only what it finds.
 * - The table a mode exports has a NULL state. State belongs to an instance:
 *   the controller copy or a namespace copy, see @state.
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
 * @name: mode name as in femu_mode=NAME; one name per table. The distinct
 *        mode walks of start_ctrl and exit key on it.
 * @state: instance state. The controller copy holds controller-wide state
 *         (OC 2.0; KV points it at its first namespace's store). A namespace
 *         copy holds that namespace's state (KV). Registration leaves a
 *         namespace copy NULL for its init to fill.
 * @init_ctrl_name: set the Identify model number and serial. With ns_mgmt it
 *                  runs once per boot namespace; with no namespace of the
 *                  controller's mode, the controller copy runs with a NULL
 *                  namespace. Without ns_mgmt, @init sets the name.
 * @init: build the mode's state for one namespace. Runs at realize for each
 *        namespace of the mode, and at Namespace Management create. Sets
 *        @errp on failure.
 * @exit: free the mode's state for the whole controller. Runs once per
 *        distinct mode at unrealize and at realize undo.
 * @ns_exit: free one namespace's state at namespace delete or release.
 * @start_ctrl: check the host's controller settings at CC.EN, once per
 *              distinct mode. Non-zero keeps the controller from ready.
 * @admin_cmd: serve an admin opcode the front end does not handle.
 * @admin_cmd_cqe: as @admin_cmd, with the completion entry to fill. A table
 *                 sets at most one of the two.
 * @io_cmd: serve an I/O opcode the front end does not handle, and every I/O
 *          opcode of an SLM or CP namespace. Required.
 * @get_log: serve a log page the front end does not handle. The named
 *           namespace's copy runs first, then the controller copy.
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

#endif
