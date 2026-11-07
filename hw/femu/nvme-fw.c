/*
 * Firmware Image Download and Firmware Commit (NVMe Base 2.3, 3.11, 5.2.8
 * and 5.2.9), with fw_slots of 2 or more. OCP 2.7 section 4.11 adds the
 * slot count, the read-only recovery slot and the security version floor.
 *
 *   Download --> staging (4 KiB units, a bitmap of the units held)
 *   Commit   --> check the staged image --> slot --> activate now, at the
 *                next Controller Level Reset, or not at all
 *
 * FEMU firmware has no code, so an image is a small header and a payload:
 *
 *   0  "FEMUFW01"   8  revision (8 ASCII)   16  security version (LE32)
 *   20 payload length (LE32)   24  CRC-32 of bytes 0..23 and the payload
 *   28 reserved, zero          32  payload
 *
 * Everything runs in the admin handler under the BQL, so the state changes
 * at once after a bounded check.
 */

#include "qemu/osdep.h"
#include "qemu/bitmap.h"
#include "qemu/units.h"
#include <zlib.h>
#include "./nvme.h"

#define FW_UNIT             4096
#define FW_MAX              (6 * MiB)       /* OCP FWUP-14 */
#define FW_UNITS            (FW_MAX / FW_UNIT)
#define FW_HDR              32

static const char fw_magic[8] = "FEMUFW01";

/* the factory image in slot 1: the revision Identify reported at realize */
void femu_fw_init(FemuCtrl *n)
{
    FemuFw *fw = &n->fw;

    memset(fw->slot, 0, sizeof(fw->slot));
    fw->slot[1].valid = true;
    memcpy(fw->slot[1].fr, n->id_ctrl.fr, sizeof(fw->slot[1].fr));
    fw->slot[1].svn = 0;
    fw->running = fw->slot[1];
    fw->running_slot = 1;
    fw->pending = 0;
    fw->floor = 0;
    memset(fw->floor_fr, 0, sizeof(fw->floor_fr));
    fw->fresh = false;
    if (n->fw_slots > 1 && !fw->stage) {
        fw->stage = g_malloc0(FW_MAX);
        fw->held = bitmap_new(FW_UNITS);
    }
}

void femu_fw_exit(FemuCtrl *n)
{
    g_free(n->fw.stage);
    n->fw.stage = NULL;
    g_free(n->fw.held);
    n->fw.held = NULL;
}

static void fw_drop_stage(FemuFw *fw)
{
    if (fw->held) {
        bitmap_zero(fw->held, FW_UNITS);
    }
    fw->fresh = false;
}

/*
 * OCP SMART-33, the lowest revision a host may roll back to. FEMU orders
 * revisions by their bytes, among the images it holds or runs at the floor.
 * No floor (0) permits every revision, so the field is zero.
 */
static void fw_floor_note(FemuFw *fw, const FemuFwImage *img)
{
    if (fw->floor && img->valid && img->svn == fw->floor &&
        (!fw->floor_fr[0] || memcmp(img->fr, fw->floor_fr, 8) < 0)) {
        memcpy(fw->floor_fr, img->fr, sizeof(fw->floor_fr));
    }
}

/* Identify FR follows the running image */
static void fw_run(FemuCtrl *n, uint8_t slot)
{
    FemuFw *fw = &n->fw;

    fw->running = fw->slot[slot];
    fw->running_slot = slot;
    memcpy(n->id_ctrl.fr, fw->running.fr, sizeof(n->id_ctrl.fr));
    /* OCP FWUP-20: a higher security version refreshes the recovery slot */
    if (fw->running.svn > fw->floor) {
        fw->floor = fw->running.svn;
        memset(fw->floor_fr, 0, sizeof(fw->floor_fr));
        if (n->ocp) {
            fw->slot[1] = fw->running;
        }
        for (int s = 1; s <= n->fw_slots; s++) {
            fw_floor_note(fw, &fw->slot[s]);
        }
    }
    fw_floor_note(fw, &fw->running);
}

/*
 * A Controller Level Reset or a power cycle: staging goes, and a pending
 * slot runs, unless its image is now below the floor.
 */
void femu_fw_reset(FemuCtrl *n)
{
    FemuFw *fw = &n->fw;

    if (n->fw_slots <= 1) {
        return;
    }
    fw_drop_stage(fw);
    if (fw->pending && fw->slot[fw->pending].valid &&
        fw->slot[fw->pending].svn >= fw->floor) {
        fw_run(n, fw->pending);
    }
    fw->pending = 0;
}

uint16_t femu_fw_download(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuFw *fw = &n->fw;
    uint64_t len = ((uint64_t)le32_to_cpu(cmd->cdw10) + 1) * 4;
    uint64_t off = (uint64_t)le32_to_cpu(cmd->cdw11) * 4;
    uint64_t first = off / FW_UNIT;
    uint64_t units = len / FW_UNIT;
    uint16_t status;

    if (off % FW_UNIT || len % FW_UNIT || off + len > FW_MAX) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    status = nvme_check_mdts(n, len);
    if (status) {
        return status;
    }
    /* the first Download after a Commit or a reset starts a new image */
    if (!fw->fresh) {
        fw_drop_stage(fw);
    }
    if (find_next_bit(fw->held, first + units, first) < first + units) {
        return NVME_FW_OVERLAP | NVME_DNR;
    }
    status = dma_write_prp(n, fw->stage + off, len,
                           le64_to_cpu(cmd->dptr.prp1),
                           le64_to_cpu(cmd->dptr.prp2));
    if (status) {
        return status;
    }
    bitmap_set(fw->held, first, units);
    fw->fresh = true;
    return NVME_SUCCESS;
}

/* the staged image, checked: gap-free from unit 0, header, CRC */
static uint16_t fw_check(FemuFw *fw, FemuFwImage *img)
{
    uint32_t plen, crc;
    uint64_t size;

    if (!test_bit(0, fw->held)) {
        return NVME_INVALID_FW_IMAGE | NVME_DNR;
    }
    plen = ldl_le_p(fw->stage + 20);
    size = ROUND_UP((uint64_t)FW_HDR + plen, FW_UNIT);
    if (memcmp(fw->stage, fw_magic, sizeof(fw_magic)) || size > FW_MAX ||
        ldl_le_p(fw->stage + 28) ||
        find_next_zero_bit(fw->held, FW_UNITS, 0) < size / FW_UNIT ||
        find_next_bit(fw->held, FW_UNITS, size / FW_UNIT) < FW_UNITS) {
        return NVME_INVALID_FW_IMAGE | NVME_DNR;
    }
    crc = crc32(0, fw->stage, 24);
    crc = crc32(crc, fw->stage + FW_HDR, plen);
    if (crc != ldl_le_p(fw->stage + 24)) {
        return NVME_INVALID_FW_IMAGE | NVME_DNR;
    }
    /* the revision goes to Identify FR: printable ASCII, space padded */
    for (int i = 0; i < 8; i++) {
        if (fw->stage[8 + i] < 0x20 || fw->stage[8 + i] > 0x7e) {
            return NVME_INVALID_FW_IMAGE | NVME_DNR;
        }
    }
    img->valid = true;
    memcpy(img->fr, fw->stage + 8, sizeof(img->fr));
    img->svn = ldl_le_p(fw->stage + 16);
    return NVME_SUCCESS;
}

/*
 * FS 0. For a new image: the lowest writable slot that does not run, or,
 * with one writable slot, that slot (CA 000b then fails as a sequence
 * error). To activate: the lowest slot that does not run and holds an
 * image, or 0.
 */
static uint8_t fw_pick_slot(FemuCtrl *n, bool image)
{
    for (uint8_t s = image ? 2 : 1; s <= n->fw_slots; s++) {
        if (s != n->fw.running_slot && (image || n->fw.slot[s].valid)) {
            return s;
        }
    }
    return image && n->fw_slots == 2 ? 2 : 0;
}

/*
 * PEL Firmware Commit event (Figure 235, revision 1): old and new revision,
 * CA, the FS the host sent, and the completion status.
 */
static void fw_pel(FemuCtrl *n, const char *old, const char *new, uint8_t ca,
                   uint8_t fs, uint16_t status)
{
    uint8_t ev[22] = { 0 };

    memcpy(ev, old, 8);
    memcpy(ev + 8, new, 8);
    ev[16] = ca;
    ev[17] = fs;
    ev[18] = (status >> 8) & 0x7;           /* SCT */
    ev[19] = status & 0xff;                 /* SC */
    femu_pel_log(n, NVME_PEL_FW_COMMIT, 1, ev, sizeof(ev));
}

static uint16_t fw_commit(FemuCtrl *n, uint8_t fs, uint8_t ca, bool *ran)
{
    FemuFw *fw = &n->fw;
    bool image = (ca == 0 || ca == 1 || ca == 3) && fw->fresh;
    FemuFwImage img = { 0 };
    uint8_t slot = fs;
    uint16_t status;

    if (ca > 3) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (ca != 2 && ca != 3 && !fw->fresh) {
        return NVME_INVALID_FW_IMAGE | NVME_DNR;
    }
    if (!slot) {
        slot = fw_pick_slot(n, image);
        if (!slot && !image) {
            return NVME_INVALID_FW_IMAGE | NVME_DNR;
        }
    }
    if (!slot || slot > n->fw_slots || (slot == 1 && image)) {
        return NVME_INVALID_FW_SLOT | NVME_DNR;
    }
    if (image) {
        status = fw_check(fw, &img);
        if (status) {
            return status;
        }
        memcpy(fw->req_fr, img.fr, sizeof(fw->req_fr));
        if (img.svn < fw->floor) {
            return NVME_FW_ACT_PROHIBITED | NVME_DNR;
        }
        if (ca == 0 && slot == fw->running_slot) {
            return NVME_CMD_SEQ_ERROR | NVME_DNR;
        }
        fw->slot[slot] = img;
        fw_floor_note(fw, &img);
    } else {
        if (!fw->slot[slot].valid) {
            return NVME_INVALID_FW_IMAGE | NVME_DNR;
        }
        memcpy(fw->req_fr, fw->slot[slot].fr, sizeof(fw->req_fr));
        if (fw->slot[slot].svn < fw->floor) {
            return NVME_FW_ACT_PROHIBITED | NVME_DNR;
        }
    }
    switch (ca) {
    case 1:
    case 2:
        fw->pending = slot;
        break;
    case 3:
        fw_run(n, slot);
        *ran = true;
        /* a pending image below the new floor can never run */
        if (fw->pending && fw->slot[fw->pending].svn < fw->floor) {
            fw->pending = 0;
        }
        break;
    }
    return NVME_SUCCESS;
}

uint16_t femu_fw_commit(FemuCtrl *n, NvmeCmd *cmd)
{
    FemuFw *fw = &n->fw;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    bool ran = false;
    uint16_t status;

    memcpy(fw->old_fr, fw->running.fr, sizeof(fw->old_fr));
    memcpy(fw->req_fr, fw->running.fr, sizeof(fw->req_fr));
    fw->reached = true;
    status = fw_commit(n, dw10 & 0x7, (dw10 >> 3) & 0x7, &ran);
    /* any Commit ends the download: the next Download starts over */
    fw->fresh = false;
    if (ran && (n->features.async_config & NVME_AEC_FW_ACTIVATION)) {
        nvme_enqueue_event(n, NVME_AER_TYPE_NOTICE, NVME_AER_INFO_FW_ACT,
                           NVME_LOG_FW_SLOT_INFO);
    }
    return status;
}

/*
 * Every completed Firmware Commit, also one aborted or refused before the
 * handler ran, logs one PEL event. A Commit that never reached the handler
 * names the running revision twice.
 */
void femu_fw_log_commit(FemuCtrl *n, NvmeCmd *cmd, uint16_t status)
{
    FemuFw *fw = &n->fw;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);

    if (n->fw_slots <= 1) {
        return;
    }
    if (!fw->reached) {
        memcpy(fw->old_fr, fw->running.fr, sizeof(fw->old_fr));
        memcpy(fw->req_fr, fw->running.fr, sizeof(fw->req_fr));
    }
    fw_pel(n, fw->old_fr, fw->req_fr, (dw10 >> 3) & 0x7, dw10 & 0x7, status);
    fw->reached = false;
}

/* AFI: bits 2:0 the running slot, 6:4 the slot for the next reset */
uint8_t femu_fw_afi(FemuCtrl *n)
{
    if (n->fw_slots <= 1) {
        return 0x1;
    }
    return n->fw.running_slot | n->fw.pending << 4;
}

void femu_fw_frs(FemuCtrl *n, uint8_t slot, char *frs)
{
    if (n->fw_slots <= 1) {
        if (slot == 1) {
            memcpy(frs, n->id_ctrl.fr, 8);
        }
        return;
    }
    if (slot <= n->fw_slots && n->fw.slot[slot].valid) {
        memcpy(frs, n->fw.slot[slot].fr, 8);
    }
}

bool femu_fw_pending(FemuCtrl *n)
{
    return n->fw_slots > 1 && n->fw.pending;
}
