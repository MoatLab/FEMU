#include "../nvme.h"

static void bb_init_ctrl_str(FemuCtrl *n)
{
    static int fsid_vno = 0;
    const char *vnossd_mn = "FEMU NoSSD NVMe Controller";
    const char *vnossd_sn = "vNoSSD";

    nvme_set_ctrl_name(n, vnossd_mn, vnossd_sn, &fsid_vno);
}

static uint16_t nop_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
                           NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return nvme_rw(n, ns, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nop_init(FemuCtrl *n, Error **errp)
{
    bb_init_ctrl_str(n);
}

int nvme_register_nossd(FemuCtrl *n)
{
    n->ext_ops = (FemuExtCtrlOps) {
        .state            = NULL,
        .init             = nop_init,
        .exit             = NULL,
        .rw_check_req     = NULL,
        .admin_cmd        = NULL,
        .io_cmd           = nop_io_cmd,
        .get_log          = NULL,
    };

    return 0;
}
