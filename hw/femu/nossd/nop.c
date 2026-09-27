#include "../nvme.h"

static void bb_init_ctrl_str(FemuCtrl *n, NvmeNamespace *ns)
{
    static int fsid_vno = 0;
    const char *vnossd_mn = "FEMU NoSSD NVMe Controller";
    const char *vnossd_sn = "vNoSSD";

    nvme_set_ctrl_name(n, vnossd_mn, vnossd_sn, &fsid_vno);
}

static uint16_t nop_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    uint16_t status;

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        status = nvme_rw(n, ns, cmd, req);
        if (n->streams && cmd->opcode == NVME_CMD_WRITE &&
            status == NVME_SUCCESS) {
            /* NoSSD tracks stream resources without physical placement. */
            qemu_mutex_lock(&n->streams_lock);
            nvme_streams_open(ns, cmd);
            qemu_mutex_unlock(&n->streams_lock);
        }
        return status;
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nop_init(FemuCtrl *n, NvmeNamespace *ns, Error **errp)
{
    if (!n->ns_mgmt) {
        bb_init_ctrl_str(n, ns);
    }
}

int nvme_register_nossd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init_ctrl_name   = bb_init_ctrl_str,
        .init             = nop_init,
        .exit             = NULL,
        .rw_check_req     = NULL,
        .admin_cmd        = NULL,
        .io_cmd           = nop_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
