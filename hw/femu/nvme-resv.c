/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Reservations (Base 2.3, 8.1.24): the Reservation Register, Acquire,
 * Release and Report commands, the access check of Figure 703, the Host
 * Identifier, Reservation Notification Mask and Reservation Persistence
 * features, and the Reservation Notification log (80h).
 *
 * A registrant is a host. A host with a non-zero Host Identifier is that
 * identifier, on every controller of the subsystem that uses it. A host
 * with Host Identifier 0 is one controller until its next reset: the reset
 * starts a new host (5.2.26.1.32), so its registrations go.
 *
 * Pollers run the commands and the check, and a femu-subsys shares a
 * namespace between controllers, so each namespace's state has a lock.
 * Lock order: namespace, then a controller's notice queue, then its AER
 * queue.
 */

#include "./nvme.h"
#include "qemu/cutils.h"

enum {
    RESV_WE = 1,                /* Write Exclusive */
    RESV_EA = 2,                /* Exclusive Access */
    RESV_WERO = 3,              /* Write Exclusive - Registrants Only */
    RESV_EARO = 4,
    RESV_WEAR = 5,              /* Write Exclusive - All Registrants */
    RESV_EAAR = 6,
};

/* notice types of log 80h; the mask feature uses the same bit numbers */
enum {
    RESV_NOTE_REG_PREEMPTED = 1,
    RESV_NOTE_RELEASED = 2,
    RESV_NOTE_PREEMPTED = 3,
};

#define RESV_CNTLID_NONE    0xffff

static bool resv_all_registrants(uint8_t rtype)
{
    return rtype == RESV_WEAR || rtype == RESV_EAAR;
}

static bool hostid_zero(const uint8_t *hostid)
{
    return buffer_is_zero(hostid, 16);
}

bool nvme_resv_opcode(uint8_t opc)
{
    return opc == NVME_CMD_RESV_REGISTER || opc == NVME_CMD_RESV_REPORT ||
           opc == NVME_CMD_RESV_ACQUIRE || opc == NVME_CMD_RESV_RELEASE;
}

/* the namespaces that take reservations: not Open-Channel, SLM or CP */
bool nvme_resv_ns(FemuCtrl *n, NvmeNamespace *ns)
{
    return n->reservations && ns->resv && ns->femu_mode != FEMU_OCSSD_MODE &&
           !NS_SLM(ns) && !NS_CP(ns);
}

/* the controllers that may hold a registrant: the subsystem's, or @n */
static FemuCtrl *resv_ctrl(FemuCtrl *n, int i)
{
    FemuCtrl *c;

    if (!nvme_ns_shared(n)) {
        return i == 0 ? n : NULL;
    }
    c = n->subsys->ctrls[i];
    /* a leaving controller is out of reach (nvme_resv_exit) */
    return c && !qatomic_read(&c->rn_gone) ? c : NULL;
}

static int resv_nr_ctrls(FemuCtrl *n)
{
    return nvme_ns_shared(n) ? NVME_MAX_CONTROLLERS : 1;
}

/* whether registrant @r is the host behind controller @c */
static bool resv_is_host(FemuCtrl *c, const NvmeRegistrant *r)
{
    if (!r->used) {
        return false;
    }
    if (hostid_zero(c->hostid)) {
        return hostid_zero(r->hostid) && r->ctrl == c &&
               r->epoch == c->host_epoch;
    }
    return r->ext == c->hostid_ext && !memcmp(r->hostid, c->hostid, 16);
}

static int resv_find(FemuCtrl *n, NvmeResv *rv)
{
    for (int i = 0; i < rv->nr; i++) {
        if (resv_is_host(n, &rv->reg[i])) {
            return i;
        }
    }
    return -1;
}

static bool resv_holds(NvmeResv *rv, int i)
{
    return i >= 0 && rv->rtype &&
           (rv->holder == i || resv_all_registrants(rv->rtype));
}

/*
 * Queue one notice on controller @c (log 80h) and raise its event. The
 * caller holds the namespace lock; the mask is the namespace's.
 */
static void resv_post(FemuCtrl *c, NvmeNamespace *ns, uint8_t type)
{
    uint32_t nsid = ns->id;
    NvmeResvNote *note;

    if (qatomic_read(&c->rn_gone) || (ns->resv->mask & (1 << type))) {
        return;
    }
    qemu_mutex_lock(&c->rn_lock);
    if (++c->rn_lpc == 0) {
        c->rn_lpc = 1;
    }
    if (c->rn_len < NVME_RESV_NOTES) {
        note = &c->rn_queue[(c->rn_head + c->rn_len++) % NVME_RESV_NOTES];
        note->lpc = c->rn_lpc;
        note->type = type;
        note->nsid = nsid;
    } else {
        /* the queue is full: the last page carries the count of the lost */
        c->rn_queue[(c->rn_head + c->rn_len - 1) % NVME_RESV_NOTES].lpc =
            c->rn_lpc;
    }
    /* under the notice lock, so a log read cannot drop it unseen */
    nvme_enqueue_event(c, NVME_AER_TYPE_IO_SPECIFIC, NVME_AER_INFO_RESV_LOG,
                       NVME_LOG_RESV_NOTIFY);
    qemu_mutex_unlock(&c->rn_lock);
}

/* tell every controller of the host of @r, unless it is the issuer's host */
static void resv_notify(FemuCtrl *n, NvmeNamespace *ns,
                        const NvmeRegistrant *r, uint8_t type)
{
    if (resv_is_host(n, r)) {
        return;
    }
    if (hostid_zero(r->hostid)) {
        if (resv_is_host(r->ctrl, r) && nvme_ns_attached(r->ctrl, ns)) {
            resv_post(r->ctrl, ns, type);
        }
        return;
    }
    for (int i = 0; i < resv_nr_ctrls(n); i++) {
        FemuCtrl *c = resv_ctrl(n, i);

        if (c && resv_is_host(c, r) && nvme_ns_attached(c, ns)) {
            resv_post(c, ns, type);
        }
    }
}

/* the reservation goes; registrants other than the issuer may hear of it */
static void resv_release(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv)
{
    uint8_t old = rv->rtype;

    qatomic_set(&rv->rtype, 0);
    rv->holder = -1;
    if (old == RESV_WE || old == RESV_EA) {
        return;
    }
    for (int i = 0; i < rv->nr; i++) {
        if (rv->reg[i].used) {
            resv_notify(n, ns, &rv->reg[i], RESV_NOTE_RELEASED);
        }
    }
}

/*
 * Unregister entry @i. A holder that leaves takes the reservation with it,
 * unless other registrants of an all-registrants type still hold it.
 */
static void resv_drop(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv, int i,
                      uint8_t note)
{
    NvmeRegistrant r = rv->reg[i];

    rv->reg[i].used = false;
    if (rv->rtype && resv_all_registrants(rv->rtype)) {
        int left = -1;

        for (int j = 0; j < rv->nr && left < 0; j++) {
            if (rv->reg[j].used) {
                left = j;
            }
        }
        rv->holder = left;
        if (left < 0) {
            qatomic_set(&rv->rtype, 0);
        }
    } else if (rv->holder == i) {
        qatomic_set(&rv->rtype, 0);
        rv->holder = -1;
    }
    if (note) {
        resv_notify(n, ns, &r, note);
    }
}

static void resv_gen(NvmeResv *rv)
{
    rv->gen++;                          /* FFFFFFFFh wraps to 0 */
}

/* Figure 703 for a read or write group command from @n's host */
static bool resv_allowed(NvmeResv *rv, int me, bool write)
{
    bool reg = me >= 0;

    if (!rv->rtype || resv_holds(rv, me)) {
        return true;
    }
    switch (rv->rtype) {
    case RESV_WE:
        return !write;
    case RESV_EA:
        return false;
    case RESV_WERO:
    case RESV_WEAR:
        return !write || reg;
    default:
        return reg;
    }
}

/*
 * The group of an I/O command (Base 2.3 Figure 703; NVM 1.2 Figure 178,
 * ZNS, KV 1.3 Figure 47): 2 write, 1 read, 0 all other commands. A Copy is
 * a write here; its sources are checked as reads where they are read.
 */
static int resv_group(NvmeNamespace *ns, uint8_t opc)
{
    if (opc == NVME_CMD_FLUSH) {
        return 2;
    }
    if (ns->csi == NVME_CSI_KV) {
        return opc == NVME_KV_CMD_STORE || opc == NVME_KV_CMD_DELETE ? 2 :
               opc == NVME_KV_CMD_RETRIEVE ? 1 : 0;
    }
    switch (opc) {
    case NVME_CMD_FLUSH:
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_UNCOR:
    case NVME_CMD_WRITE_ZEROES:
    case NVME_CMD_DSM:
    case NVME_CMD_COPY:
    case NVME_CMD_ZONE_MGMT_SEND:
    case NVME_CMD_ZONE_APPEND:
        return 2;
    case NVME_CMD_READ:
    case NVME_CMD_COMPARE:
    case NVME_CMD_VERIFY:
    case NVME_CMD_ZONE_MGMT_RECV:
        return 1;
    default:
        return 0;
    }
}

uint16_t nvme_resv_cmd_check(FemuCtrl *n, NvmeNamespace *ns, uint8_t opc)
{
    int group = resv_group(ns, opc);

    return group ? nvme_resv_check(n, ns, group == 2) : NVME_SUCCESS;
}

uint16_t nvme_resv_check(FemuCtrl *n, NvmeNamespace *ns, bool write)
{
    NvmeResv *rv = ns->resv;
    bool ok;

    if (!n->reservations || !rv || !qatomic_read(&rv->rtype)) {
        return NVME_SUCCESS;
    }
    qemu_mutex_lock(&rv->lock);
    ok = resv_allowed(rv, resv_find(n, rv), write);
    qemu_mutex_unlock(&rv->lock);
    return ok ? NVME_SUCCESS : NVME_NS_RESV_CONFLICT;
}

/*
 * The admin commands of the write group (Figure 703): Format NVM, Sanitize,
 * Namespace Management and Namespace Attachment, for each namespace they
 * change.
 */
uint16_t nvme_resv_admin_check(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    bool all;

    switch (cmd->opcode) {
    case NVME_ADM_CMD_FORMAT_NVM:
        all = nsid == NVME_NSID_BROADCAST;
        break;
    case NVME_ADM_CMD_SANITIZE:
        all = true;
        break;
    case NVME_ADM_CMD_NS_MGMT:
        /* a Delete of FFFFFFFFh deletes every namespace */
        all = nsid == NVME_NSID_BROADCAST;
        break;
    case NVME_ADM_CMD_NS_ATTACHMENT:
        all = false;
        break;
    default:
        return NVME_SUCCESS;
    }
    for (uint32_t i = 1; n->namespaces && i <= n->namespace_limit; i++) {
        NvmeNamespace *ns = nvme_ns_allocated(n, i);

        if ((all || i == nsid) && ns && nvme_resv_ns(n, ns) &&
            nvme_resv_check(n, ns, true)) {
            return NVME_NS_RESV_CONFLICT;
        }
    }
    return NVME_SUCCESS;
}

/* a new registrant for @n's host with @key */
static uint16_t resv_add(FemuCtrl *n, NvmeResv *rv, uint64_t key)
{
    int i;

    for (i = 0; i < rv->nr && rv->reg[i].used; i++) {
        continue;
    }
    /* a Register never fails for lack of room (8.1.24): the table grows */
    if (i == rv->nr) {
        rv->reg = g_renew(NvmeRegistrant, rv->reg, rv->nr * 2);
        memset(&rv->reg[rv->nr], 0, rv->nr * sizeof(NvmeRegistrant));
        rv->nr *= 2;
    }
    rv->reg[i] = (NvmeRegistrant) {
        .used = true,
        .ext = n->hostid_ext,
        .ctrl = n,
        .epoch = n->host_epoch,
        .key = key,
    };
    memcpy(rv->reg[i].hostid, n->hostid, 16);
    return NVME_SUCCESS;
}

static uint16_t resv_register(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv,
                              uint32_t dw10, uint64_t crkey, uint64_t nrkey)
{
    uint8_t rrega = dw10 & 0x7;
    bool iekey = dw10 & (1 << 3);
    uint8_t cptpl = dw10 >> 30;
    int me = resv_find(n, rv);
    uint16_t status = NVME_SUCCESS;

    if (rrega > 2 || cptpl == 1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    switch (rrega) {
    case 0:                             /* register; IEKEY is ignored */
        if (me < 0) {
            status = resv_add(n, rv, nrkey);
        } else if (rv->reg[me].key != nrkey) {
            return NVME_NS_RESV_CONFLICT;
        }
        break;
    case 1:                             /* unregister */
        if (me < 0 || (!iekey && rv->reg[me].key != crkey)) {
            return NVME_NS_RESV_CONFLICT;
        }
        if (resv_holds(rv, me) && !resv_all_registrants(rv->rtype)) {
            uint8_t old = rv->rtype;

            resv_drop(n, ns, rv, me, 0);
            /* released by a registrants-only holder: the others hear */
            if (old == RESV_WERO || old == RESV_EARO) {
                for (int i = 0; i < rv->nr; i++) {
                    if (rv->reg[i].used) {
                        resv_notify(n, ns, &rv->reg[i], RESV_NOTE_RELEASED);
                    }
                }
            }
        } else {
            resv_drop(n, ns, rv, me, 0);
        }
        break;
    case 2:                             /* replace */
        if (me < 0 && !iekey) {
            return NVME_NS_RESV_CONFLICT;
        }
        if (me < 0) {
            /* IEKEY replaces whatever the host had, also nothing */
            status = resv_add(n, rv, nrkey);
        } else if (!iekey && rv->reg[me].key != crkey) {
            return NVME_NS_RESV_CONFLICT;
        } else {
            rv->reg[me].key = nrkey;
        }
        break;
    }
    if (status) {
        return status;
    }
    if (cptpl >= 2) {
        rv->ptpl = cptpl == 3;
    }
    resv_gen(rv);
    return NVME_SUCCESS;
}

/*
 * Unregister the registrants with @key (all with @any); the issuer @me
 * stays only where 8.1.24.7 keeps it (@keep_me). Returns how many went.
 */
static int resv_drop_key(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv,
                         int me, bool keep_me, bool any, uint64_t key)
{
    int dropped = 0;

    for (int i = 0; i < rv->nr; i++) {
        if ((i != me || !keep_me) && rv->reg[i].used &&
            (any || rv->reg[i].key == key)) {
            resv_drop(n, ns, rv, i, RESV_NOTE_REG_PREEMPTED);
            dropped++;
        }
    }
    return dropped;
}

/*
 * A new reservation for @me. When the type changes from @old, the other
 * registrants hear that the reservation was released.
 */
static void resv_take(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv, int me,
                      uint8_t rtype, uint8_t old)
{
    qatomic_set(&rv->rtype, rtype);
    rv->holder = me;
    if (old && old != rtype) {
        for (int i = 0; i < rv->nr; i++) {
            if (i != me && rv->reg[i].used) {
                resv_notify(n, ns, &rv->reg[i], RESV_NOTE_RELEASED);
            }
        }
    }
}

static uint16_t resv_acquire(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv,
                             uint32_t dw10, uint64_t crkey, uint64_t prkey)
{
    uint8_t racqa = dw10 & 0x7;
    uint8_t rtype = (dw10 >> 8) & 0xff;
    uint8_t old = rv->rtype;
    int me = resv_find(n, rv);

    if (racqa > 2 || (dw10 & (1 << 3)) || rtype < RESV_WE ||
        rtype > RESV_EAAR) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (me < 0 || rv->reg[me].key != crkey) {
        return NVME_NS_RESV_CONFLICT;
    }
    if (racqa == 0) {
        if (!rv->rtype) {
            qatomic_set(&rv->rtype, rtype);
            rv->holder = me;
            return NVME_SUCCESS;
        }
        return resv_holds(rv, me) && rv->rtype == rtype ?
               NVME_SUCCESS : NVME_NS_RESV_CONFLICT;
    }

    /*
     * Preempt, and Preempt and Abort (8.1.24.7). Open gap: Preempt and
     * Abort neither aborts the preempted hosts' commands nor waits for
     * them before it completes.
     */
    if (!rv->rtype) {
        resv_drop_key(n, ns, rv, me, false, false, prkey);
    } else if (!resv_all_registrants(rv->rtype)) {
        if (prkey == rv->reg[rv->holder].key) {
            /* the holder's key: the issuer keeps its registration */
            resv_drop_key(n, ns, rv, me, true, false, prkey);
            resv_take(n, ns, rv, me, rtype, old);
        } else if (prkey) {
            resv_drop_key(n, ns, rv, me, false, false, prkey);
        } else {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    } else if (!prkey) {
        resv_drop_key(n, ns, rv, me, true, true, 0);
        resv_take(n, ns, rv, me, rtype, old);
    } else if (!resv_drop_key(n, ns, rv, me, false, false, prkey)) {
        return NVME_NS_RESV_CONFLICT;
    }
    resv_gen(rv);
    return NVME_SUCCESS;
}

static uint16_t resv_release_cmd(FemuCtrl *n, NvmeNamespace *ns,
                                 NvmeResv *rv, uint32_t dw10, uint64_t crkey)
{
    uint8_t rrela = dw10 & 0x7;
    uint8_t rtype = (dw10 >> 8) & 0xff;
    int me = resv_find(n, rv);

    if (rrela > 1 || (dw10 & (1 << 3))) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (me < 0 || rv->reg[me].key != crkey) {
        return NVME_NS_RESV_CONFLICT;
    }
    if (rrela == 1) {                   /* clear */
        qatomic_set(&rv->rtype, 0);
        rv->holder = -1;
        for (int i = 0; i < rv->nr; i++) {
            if (rv->reg[i].used) {
                NvmeRegistrant r = rv->reg[i];

                rv->reg[i].used = false;
                resv_notify(n, ns, &r, RESV_NOTE_PREEMPTED);
            }
        }
        resv_gen(rv);
        return NVME_SUCCESS;
    }
    if (!resv_holds(rv, me)) {
        return NVME_SUCCESS;            /* no reservation of this host */
    }
    if (rtype != rv->rtype) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    resv_release(n, ns, rv);
    return NVME_SUCCESS;
}

/* the controller of a registrant for Report, FFFFh when none is */
static uint16_t resv_cntlid(FemuCtrl *n, NvmeNamespace *ns,
                            const NvmeRegistrant *r)
{
    for (int i = 0; i < resv_nr_ctrls(n); i++) {
        FemuCtrl *c = resv_ctrl(n, i);

        if (c && resv_is_host(c, r) && nvme_ns_attached(c, ns)) {
            return c->cntlid;
        }
    }
    return RESV_CNTLID_NONE;
}

static uint16_t resv_report(FemuCtrl *n, NvmeNamespace *ns, NvmeResv *rv,
                            NvmeCmd *cmd)
{
    uint64_t len = ((uint64_t)le32_to_cpu(cmd->cdw10) + 1) * 4;
    bool eds = le32_to_cpu(cmd->cdw11) & 0x1;
    size_t hdr = eds ? 64 : 24;
    size_t ent = eds ? 64 : 24;
    g_autofree uint8_t *buf = NULL;
    size_t size;
    uint32_t nreg = 0;
    uint8_t *p;

    /* the layout must match the Host Identifier the host chose */
    if (!hostid_zero(n->hostid) && eds != n->hostid_ext) {
        return NVME_HOSTID_INCONSISTENT | NVME_DNR;
    }
    for (int i = 0; i < rv->nr; i++) {
        nreg += rv->reg[i].used;
    }
    /* REGSTRNT is 16 bits: the report holds at most that many */
    nreg = MIN(nreg, UINT16_MAX);
    size = hdr + (size_t)nreg * ent;
    buf = g_malloc0(size);
    stl_le_p(buf, rv->gen);
    buf[4] = rv->rtype;
    stw_le_p(buf + 5, nreg);
    buf[9] = rv->ptpl;
    p = buf + hdr;
    for (int i = 0; i < rv->nr && p < buf + size; i++) {
        const NvmeRegistrant *r = &rv->reg[i];

        if (!r->used) {
            continue;
        }
        stw_le_p(p, resv_cntlid(n, ns, r));
        p[2] = resv_holds(rv, i);
        if (eds) {
            stq_le_p(p + 8, r->key);
            memcpy(p + 16, r->hostid, 16);
        } else {
            memcpy(p + 8, r->hostid, 8);
            stq_le_p(p + 16, r->key);
        }
        p += ent;
    }
    return dma_read_cmd(n, cmd, buf, MIN(len, size));
}

/* the four reservation commands, from the I/O dispatch */
uint16_t nvme_resv_io(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd)
{
    NvmeResv *rv = ns->resv;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint8_t data[16] = { 0 };
    uint16_t status;

    switch (cmd->opcode) {
    case NVME_CMD_RESV_REGISTER:
    case NVME_CMD_RESV_ACQUIRE:
        status = dma_write_cmd(n, cmd, data, 16);
        break;
    case NVME_CMD_RESV_RELEASE:
        status = dma_write_cmd(n, cmd, data, 8);
        break;
    default:
        status = NVME_SUCCESS;
        break;
    }
    if (status) {
        return status;
    }

    qemu_mutex_lock(&rv->lock);
    switch (cmd->opcode) {
    case NVME_CMD_RESV_REGISTER:
        status = resv_register(n, ns, rv, dw10, ldq_le_p(data),
                               ldq_le_p(data + 8));
        break;
    case NVME_CMD_RESV_ACQUIRE:
        status = resv_acquire(n, ns, rv, dw10, ldq_le_p(data),
                              ldq_le_p(data + 8));
        break;
    case NVME_CMD_RESV_RELEASE:
        status = resv_release_cmd(n, ns, rv, dw10, ldq_le_p(data));
        break;
    default:
        status = resv_report(n, ns, rv, cmd);
        break;
    }
    qemu_mutex_unlock(&rv->lock);
    return status;
}

/*
 * Host Identifier (81h), Reservation Notification Mask (82h), Reservation
 * Persistence (83h). None is saveable; 82h and 83h are per namespace, and
 * FFFFFFFFh sets every namespace that takes reservations.
 */
bool nvme_resv_fid(uint8_t fid)
{
    return fid == NVME_HOST_IDENTIFIER || fid == NVME_RESV_NOTIFY_MASK ||
           fid == NVME_RESV_PERSISTENCE;
}

static NvmeNamespace *resv_feat_ns(FemuCtrl *n, uint32_t nsid)
{
    NvmeNamespace *ns = nvme_ns(n, nsid);

    return ns && nvme_resv_ns(n, ns) ? ns : NULL;
}

uint16_t nvme_resv_get_feature(FemuCtrl *n, NvmeCmd *cmd, NvmeCqe *cqe)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint8_t fid = NVME_GETSETFEAT_FID(dw10);
    uint8_t sel = NVME_GETFEAT_SELECT(dw10);
    NvmeNamespace *ns = NULL;
    uint32_t result = 0;

    if (fid != NVME_HOST_IDENTIFIER) {
        ns = resv_feat_ns(n, nsid);
        if (!ns) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }
    if (sel == NVME_GETFEAT_SELECT_CAP) {
        cqe->n.result = cpu_to_le32(NVME_FEAT_CAP_CHANGE |
                                    (ns ? NVME_FEAT_CAP_NS : 0));
        return NVME_SUCCESS;
    }
    if (sel > NVME_GETFEAT_SELECT_SAVED) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    /* nothing is saveable, so default and saved are the reset values */
    if (fid == NVME_HOST_IDENTIFIER) {
        uint8_t hostid[16] = { 0 };
        bool ext = le32_to_cpu(cmd->cdw11) & 0x1;

        if (sel == NVME_GETFEAT_SELECT_CURRENT) {
            memcpy(hostid, n->hostid, 16);
            result = n->hostid_ext;
        }
        cqe->n.result = cpu_to_le32(result);
        return dma_read_prp(n, hostid, ext ? 16 : 8,
                            le64_to_cpu(cmd->dptr.prp1),
                            le64_to_cpu(cmd->dptr.prp2));
    }
    if (sel == NVME_GETFEAT_SELECT_CURRENT) {
        qemu_mutex_lock(&ns->resv->lock);
        result = fid == NVME_RESV_NOTIFY_MASK ? ns->resv->mask :
                 ns->resv->ptpl;
        qemu_mutex_unlock(&ns->resv->lock);
    }
    cqe->n.result = cpu_to_le32(result);
    return NVME_SUCCESS;
}

/* a non-zero Host Identifier of the other size on another controller */
static bool resv_hostid_clash(FemuCtrl *n, bool ext)
{
    for (int i = 0; i < resv_nr_ctrls(n); i++) {
        FemuCtrl *c = resv_ctrl(n, i);

        if (c && c != n && !hostid_zero(c->hostid) && c->hostid_ext != ext) {
            return true;
        }
    }
    return false;
}

uint16_t nvme_resv_set_feature(FemuCtrl *n, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint8_t fid = NVME_GETSETFEAT_FID(dw10);

    if (NVME_SETFEAT_SAVE(dw10)) {
        return NVME_FID_NOT_SAVEABLE | NVME_DNR;
    }
    if (fid == NVME_HOST_IDENTIFIER) {
        uint8_t hostid[16] = { 0 };
        bool ext = dw11 & 0x1;
        uint16_t status;
        bool resume;

        status = dma_write_prp(n, hostid, ext ? 16 : 8,
                               le64_to_cpu(cmd->dptr.prp1),
                               le64_to_cpu(cmd->dptr.prp2));
        if (status) {
            return status;
        }
        if (!hostid_zero(n->hostid)) {
            return NVME_CMD_SEQ_ERROR | NVME_DNR;
        }
        if (resv_hostid_clash(n, ext)) {
            return NVME_HOSTID_INCONSISTENT | NVME_DNR;
        }
        /* pollers read the identity in every reservation command */
        resume = nvme_pause_pollers(n);
        memcpy(n->hostid, hostid, 16);
        n->hostid_ext = ext;
        nvme_resume_pollers(n, resume);
        return NVME_SUCCESS;
    }

    for (uint32_t i = 1; n->namespaces && i <= n->namespace_limit; i++) {
        NvmeNamespace *ns;

        if (nsid != NVME_NSID_BROADCAST && i != nsid) {
            continue;
        }
        ns = resv_feat_ns(n, i);
        if (!ns) {
            if (nsid != NVME_NSID_BROADCAST) {
                return NVME_INVALID_FIELD | NVME_DNR;
            }
            continue;
        }
        qemu_mutex_lock(&ns->resv->lock);
        if (fid == NVME_RESV_NOTIFY_MASK) {
            ns->resv->mask = dw11 & 0xe;
        } else {
            ns->resv->ptpl = dw11 & 0x1;
        }
        qemu_mutex_unlock(&ns->resv->lock);
    }
    if (nsid != NVME_NSID_BROADCAST && !resv_feat_ns(n, nsid)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

/*
 * Reservation Notification log (80h): the oldest page, which the read
 * takes off the queue; an empty queue reads as zeroes. A read without RAE
 * clears the event; with pages left, the next event follows.
 */
uint16_t nvme_resv_log(FemuCtrl *n, NvmeCmd *cmd, uint32_t len, uint64_t off,
                       bool rae)
{
    uint8_t page[64] = { 0 };
    bool more;
    uint16_t status;

    if (off >= sizeof(page)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_mutex_lock(&n->rn_lock);
    if (n->rn_len) {
        NvmeResvNote *note = &n->rn_queue[n->rn_head];

        stq_le_p(page, note->lpc);
        page[8] = note->type;
        page[9] = MIN(n->rn_len - 1, 255);
        stl_le_p(page + 12, note->nsid);
        n->rn_head = (n->rn_head + 1) % NVME_RESV_NOTES;
        n->rn_len--;
    }
    qemu_mutex_unlock(&n->rn_lock);

    status = dma_read_prp(n, page + off, MIN(sizeof(page) - off, len),
                          le64_to_cpu(cmd->dptr.prp1),
                          le64_to_cpu(cmd->dptr.prp2));
    if (!status && !rae) {
        /* clear and post again under the lock that posts new notices */
        qemu_mutex_lock(&n->rn_lock);
        more = n->rn_len;
        nvme_clear_ns_events(n, NVME_AER_TYPE_IO_SPECIFIC,
                             NVME_LOG_RESV_NOTIFY, 0, true);
        if (more) {
            nvme_enqueue_event(n, NVME_AER_TYPE_IO_SPECIFIC,
                               NVME_AER_INFO_RESV_LOG, NVME_LOG_RESV_NOTIFY);
        }
        qemu_mutex_unlock(&n->rn_lock);
        qemu_bh_schedule(n->aer_bh);
    }
    return status;
}

/* one namespace: no registrant, no reservation */
static void resv_clear(NvmeResv *rv)
{
    qatomic_set(&rv->rtype, 0);
    rv->holder = -1;
    for (int i = 0; i < rv->nr; i++) {
        rv->reg[i].used = false;
    }
}

void nvme_resv_ns_clear(NvmeNamespace *ns)
{
    if (ns->resv) {
        qemu_mutex_lock(&ns->resv->lock);
        resv_clear(ns->resv);
        ns->resv->ptpl = false;
        ns->resv->mask = 0;
        ns->resv->gen = 0;
        qemu_mutex_unlock(&ns->resv->lock);
    }
}

/* the Host Identifier 0 registrations of @n go, with what they held */
static void resv_drop_ctrl(FemuCtrl *n)
{
    for (uint32_t i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeResv *rv = n->namespaces[i].resv;

        if (!rv) {
            continue;
        }
        qemu_mutex_lock(&rv->lock);
        for (int j = 0; j < rv->nr; j++) {
            if (rv->reg[j].used && rv->reg[j].ctrl == n &&
                hostid_zero(rv->reg[j].hostid)) {
                resv_drop(n, &n->namespaces[i], rv, j, 0);
            }
        }
        qemu_mutex_unlock(&rv->lock);
    }
}

/*
 * Controller Level Reset: a Host Identifier 0 host becomes a new host, the
 * Host Identifier returns to 0, the notices go, and the Log Page Count
 * starts again at 0. Registrations of a non-zero Host Identifier, PTPL and
 * the masks are namespace state, and stay.
 */
void nvme_resv_ctrl_reset(FemuCtrl *n)
{
    if (!n->reservations) {
        return;
    }
    resv_drop_ctrl(n);
    n->host_epoch++;
    memset(n->hostid, 0, sizeof(n->hostid));
    n->hostid_ext = false;
    qemu_mutex_lock(&n->rn_lock);
    n->rn_head = 0;
    n->rn_len = 0;
    n->rn_lpc = 0;
    qemu_mutex_unlock(&n->rn_lock);
}

/* a power loss keeps the state of a namespace only with PTPL set */
void nvme_resv_power_loss(FemuCtrl *n)
{
    for (uint32_t i = 0; n->reservations && i < n->namespace_limit; i++) {
        NvmeResv *rv = n->namespaces[i].resv;

        if (rv) {
            qemu_mutex_lock(&rv->lock);
            if (!rv->ptpl) {
                resv_clear(rv);
            }
            qemu_mutex_unlock(&rv->lock);
        }
    }
}

bool nvme_resv_check_props(FemuCtrl *n, Error **errp)
{
    if (n->reservations && OCSSD(n)) {
        error_setg(errp, "reservations do not work with Open-Channel");
        return false;
    }
    /* every controller of a subsystem supports them alike (8.1.24) */
    for (int i = 0; n->subsys && i < NVME_MAX_CONTROLLERS; i++) {
        FemuCtrl *c = n->subsys->ctrls[i];

        if (c && c != n && c->reservations != n->reservations) {
            error_setg(errp, "reservations must be the same on every "
                       "controller of a femu-subsys");
            return false;
        }
    }
    return true;
}

/*
 * Every namespace slot gets its state at realize, so a namespace created
 * later has it too. With a shared namespace array the first controller
 * makes it; the controller that owns the array frees it.
 */
void nvme_resv_realize(FemuCtrl *n)
{
    int nr = 2 * resv_nr_ctrls(n);

    if (!n->reservations) {
        return;
    }
    for (uint32_t i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && !NS_SLM(ns) && !NS_CP(ns)) {
            ns->id_ns.rescap = NVME_RESCAP_ALL;
        }
        if (ns->resv) {
            continue;
        }
        ns->resv = g_new0(NvmeResv, 1);
        ns->resv->reg = g_new0(NvmeRegistrant, nr);
        ns->resv->nr = nr;
        ns->resv->holder = -1;
        qemu_mutex_init(&ns->resv->lock);
    }
}

/*
 * A leaving controller takes no more notices. Peers run reservation
 * commands on shared namespaces under the subsystem's namespace lock, so
 * taking it waits out any notice on its way here.
 */
void nvme_resv_exit(FemuCtrl *n)
{
    if (!n->reservations) {
        return;
    }
    if (nvme_ns_shared(n)) {
        qemu_mutex_lock(&n->subsys->ns_lock);
    }
    qatomic_set(&n->rn_gone, true);
    if (nvme_ns_shared(n)) {
        qemu_mutex_unlock(&n->subsys->ns_lock);
    }
    resv_drop_ctrl(n);
    if (n->shared_storage) {
        return;
    }
    for (uint32_t i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeResv *rv = n->namespaces[i].resv;

        if (rv) {
            qemu_mutex_destroy(&rv->lock);
            g_free(rv->reg);
            g_free(rv);
            n->namespaces[i].resv = NULL;
        }
    }
}
