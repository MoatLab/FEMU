#include "./nvme.h"
#include "qemu/range.h"
#include "system/accel-irq.h"

static void nvme_isr_notify_legacy(void *opaque);

static int nvme_add_kvm_msi_virq(FemuCtrl *n, NvmeCQueue *cq)
{
    int virq;
    int vector_n;
    AccelRouteChange c;

    /* only an MSI-X vector can have a route; others are notified directly */
    if (!msix_enabled(&(n->parent_obj))) {
        return -1;
    }
    /* the route lifecycle below is KVM only; others notify directly */
    if (!kvm_msi_via_irqfd_enabled()) {
        return -1;
    }

    if (event_notifier_init(&cq->guest_notifier, 0)) {
        femu_err("Initiated guest notifier failed");
        return -1;
    }
    event_notifier_set_handler(&cq->guest_notifier, NULL);

    vector_n = cq->vector;

    c = accel_irqchip_begin_route_changes();
    virq = accel_irqchip_add_msi_route(&c, vector_n, &n->parent_obj);
    if (virq < 0) {
        femu_debug("no KVM route for MSI-X vector %d\n", vector_n);
        event_notifier_cleanup(&cq->guest_notifier);
        return -1;
    }
    accel_irqchip_commit_route_changes(&c);
    cq->virq = virq;
    cq->msg = msix_get_message(&n->parent_obj, vector_n);
    femu_debug("%s,cq[%d]->virq=%d\n", __func__, cq->cqid, virq);

    return 0;
}

/*
 * Stop the irqfd fast path of @cq. Called with the BQL held.
 *
 * A poller may have read irqfd_on just before it went false, so wait for
 * it to leave. Then remove the irqfd: KVM must not deliver through a mask
 * or an old route. A signal that came after KVM stopped reading the
 * eventfd stays in it; with @drain, send it through the PCI core, which
 * holds the vector pending while it is masked.
 */
static void nvme_irqfd_stop(NvmeCQueue *cq, bool drain)
{
    qatomic_set(&cq->irqfd_on, false);
    /*
     * Order the irqfd_on store before the irqfd_users loads. Pairs with
     * smp_mb__after_rmw() in nvme_isr_notify_io(): a poller that has not
     * yet been counted here sees irqfd_on false.
     */
    smp_mb();
    while (qatomic_read(&cq->irqfd_users)) {
        cpu_relax();
    }

    /* a removal that fails keeps the flag, so the next stop tries again */
    if (cq->irqfd_attached) {
        if (kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state,
                                                  &cq->guest_notifier,
                                                  cq->virq)) {
            femu_err("remove_irqfd_notifier_gsi failed");
        } else {
            cq->irqfd_attached = false;
        }
    }

    if (event_notifier_test_and_clear(&cq->guest_notifier) && drain) {
        nvme_isr_notify_legacy(cq);
    }
}

/*
 * Make the irqfd of @cq match the MSI-X state. Called with the BQL held,
 * after each change that can matter: a vector mask or unmask, a write of
 * the MSI-X control byte, and the creation of the queue.
 *
 * The fast path is on only while MSI-X is enabled, the vector and the
 * function are not masked, the route holds the vector's current message,
 * and the irqfd is attached. In every other state the queue notifies
 * through the PCI core.
 */
static void nvme_irqfd_sync(FemuCtrl *n, NvmeCQueue *cq)
{
    PCIDevice *pci = &n->parent_obj;
    MSIMessage msg;

    if (!cq->irq_enabled || cq->virq <= 0) {
        return;
    }
    if (!msix_enabled(pci) || msix_is_masked(pci, cq->vector)) {
        nvme_irqfd_stop(cq, true);
        return;
    }

    msg = msix_get_message(pci, cq->vector);
    if (cq->msg.data != msg.data || cq->msg.address != msg.address) {
        nvme_irqfd_stop(cq, true);
        if (kvm_irqchip_update_msi_route(kvm_state, cq->virq, msg, pci) < 0) {
            femu_err("MSI irq update vector %u failed", cq->vector);
            return;
        }
        kvm_irqchip_commit_routes(kvm_state);
        cq->msg = msg;
    }

    if (!cq->irqfd_attached) {
        if (kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, &cq->guest_notifier,
                                               NULL, cq->virq) < 0) {
            femu_err("MSI add irqfd gsi vector %u failed", cq->vector);
            return;
        }
        cq->irqfd_attached = true;
    }
    qatomic_set(&cq->irqfd_on, true);
}

/* sync every queue on @vector, or every queue when @vector is negative */
static void nvme_irqfd_sync_vector(FemuCtrl *n, int vector)
{
    /* a config write can come before realize allocates the queues */
    if (!n->cq) {
        return;
    }
    for (uint32_t qid = 1; qid <= n->nr_io_queues; qid++) {
        NvmeCQueue *cq = n->cq[qid];

        if (cq && (vector < 0 || cq->vector == vector)) {
            nvme_irqfd_sync(n, cq);
        }
    }
}

/*
 * A config write that reaches the MSI-X Enable or Function Mask bit. The
 * PCI core sends no mask notifier when MSI-X goes off, and none when it
 * comes back on with the function masked, so sync every queue here.
 */
void nvme_irqfd_config_written(FemuCtrl *n, uint32_t addr, int len)
{
    PCIDevice *pci = &n->parent_obj;

    if (msix_present(pci) &&
        range_covers_byte(addr, len, pci->msix_cap + PCI_MSIX_FLAGS + 1)) {
        nvme_irqfd_sync_vector(n, -1);
    }
}

void nvme_remove_kvm_msi_virq(NvmeCQueue *cq)
{
    /* the queue goes away: a stranded signal has no queue to notify */
    nvme_irqfd_stop(cq, false);
    kvm_irqchip_release_virq(kvm_state, cq->virq);
    event_notifier_set_handler(&cq->guest_notifier, NULL);
    event_notifier_cleanup(&cq->guest_notifier);
    cq->virq = -1;
}

static int nvme_set_guest_notifier(FemuCtrl *n, EventNotifier *notifier,
                                   uint32_t qid)
{
    return 0;
}

static void nvme_clear_guest_notifier(FemuCtrl *n)
{
    NvmeCQueue *cq;
    int qid;

    /*
     * Keep going past a queue the guest has deleted -- stopping there left the
     * routes of every queue above it in place -- and release only a route that
     * was really taken. A queue whose route could not be added keeps the id it
     * was allocated with, and releasing that releases an interrupt this device
     * does not own.
     */
    for (qid = 1; qid <= n->nr_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        if (cq->irq_enabled && cq->virq > 0) {
            nvme_remove_kvm_msi_virq(cq);
        }
    }

    if (n->vector_poll_started) {
        msix_unset_vector_notifiers(&n->parent_obj);
        n->vector_poll_started = false;
    }
}

static int nvme_vector_unmask(PCIDevice *dev, unsigned vector, MSIMessage msg)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);

    /* a queue that cannot use its irqfd notifies through the PCI core */
    nvme_irqfd_sync_vector(n, vector);
    return 0;
}

static void nvme_vector_mask(PCIDevice *dev, unsigned vector)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);

    nvme_irqfd_sync_vector(n, vector);
}

static void nvme_vector_poll(PCIDevice *dev, unsigned int vector_start, unsigned
                             int vector_end)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t vector;

    for (uint32_t qid = 1; qid <= n->nr_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq || !cq->irq_enabled || cq->virq <= 0) {
            continue;
        }

        vector = cq->vector;
        if (vector < vector_end && vector >= vector_start) {
            e = &cq->guest_notifier;
            if (!msix_is_masked(dev, vector)) {
                continue;
            }

            if (event_notifier_test_and_clear(e)) {
                msix_set_pending(dev, vector);
            }
        }
    }
}

static bool nvme_irq_by_pin(FemuCtrl *n)
{
    PCIDevice *pci = &n->parent_obj;

    return !msix_enabled(pci) && !msi_enabled(pci);
}

/*
 * The pin is level triggered: it stays asserted while an interrupt-enabled
 * completion queue holds entries the host has not consumed and INTMS does not
 * mask it, and drops once the host has caught up. Called with the BQL held.
 */
void nvme_irq_update(FemuCtrl *n)
{
    bool pending = false;
    int qid;

    if (!nvme_irq_by_pin(n)) {
        return;
    }

    for (qid = 0; qid <= n->nr_io_queues && !pending; qid++) {
        NvmeCQueue *cq = n->cq[qid];

        if (!cq || !cq->irq_enabled) {
            continue;
        }
        if (qid) {
            nvme_update_cq_head(cq);
        }
        pending = cq->head != cq->tail;
    }

    n->irq_status = pending ? 1 : 0;
    if (~n->bar.intms & n->irq_status) {
        pci_irq_assert(&n->parent_obj);
    } else {
        pci_irq_deassert(&n->parent_obj);
    }
}

/* INTMS or INTMC was written; unmasked holds the bits INTMC just cleared */
void nvme_irq_mask_changed(FemuCtrl *n, uint32_t unmasked)
{
    PCIDevice *pci = &n->parent_obj;
    uint32_t held;
    int v;

    if (msix_enabled(pci)) {
        return;
    }
    if (!msi_enabled(pci)) {
        nvme_irq_update(n);
        return;
    }

    /* an MSI raised while its vector was masked is sent once it is not */
    held = n->irq_status & unmasked;
    n->irq_status &= ~held;
    for (v = 0; v < 32; v++) {
        if (held & (1U << v)) {
            msi_notify(pci, v);
        }
    }
}

static void nvme_isr_notify_legacy(void *opaque)
{
    NvmeCQueue *cq = opaque;
    FemuCtrl *n = cq->ctrl;
    PCIDevice *pci = &n->parent_obj;

    if (!cq->irq_enabled) {
        return;
    }

    if (msix_enabled(pci)) {
        msix_notify(pci, cq->vector);
    } else if (msi_enabled(pci)) {
        if (cq->vector >= msi_nr_vectors_allocated(pci)) {
            return;
        }
        if (n->bar.intms & (1U << cq->vector)) {
            n->irq_status |= 1U << cq->vector;
        } else {
            msi_notify(pci, cq->vector);
        }
    } else {
        nvme_irq_update(n);
    }
}

void nvme_isr_notify_admin(void *opaque)
{
    NvmeCQueue *cq = opaque;
    FemuCtrl *n = cq->ctrl;

    /* I/O queues that share the vector get this interrupt too */
    if (cq->irq_enabled && n->features.ic_vec &&
        cq->vector <= n->nr_io_queues) {
        NvmeIcVector *v = &n->features.ic_vec[cq->vector];

        qemu_spin_lock(&v->lock);
        v->pending = 0;
        v->urgent = false;
        qemu_spin_unlock(&v->lock);
    }
    nvme_isr_notify_legacy(opaque);
}

/*
 * Signal @cq's vector now, on a thread that holds the BQL: no bottom half
 * that a queue delete could cancel before it runs.
 */
void nvme_isr_notify_now(NvmeCQueue *cq)
{
    nvme_isr_notify_legacy(cq);
}

void nvme_isr_notify_io(void *opaque)
{
    NvmeCQueue *cq = opaque;

    if (!cq->irq_enabled) {
        return;
    }

    /*
     * The queue's own KVM route, while nvme_irqfd_sync() allows it. The
     * user count lets nvme_irqfd_stop() wait for a signal in flight.
     * Otherwise the PCI core notifies, and holds the vector pending while
     * it is masked.
     */
    if (cq->virq > 0) {
        qatomic_inc(&cq->irqfd_users);
        smp_mb__after_rmw();
        if (qatomic_read(&cq->irqfd_on)) {
            event_notifier_set(&cq->guest_notifier);
            qatomic_dec(&cq->irqfd_users);
            return;
        }
        qatomic_dec(&cq->irqfd_users);
    }

    /*
     * Without one, the notification goes through the PCI core, which needs the
     * BQL. A poller thread does not hold it, so leave the rest to a bottom
     * half on the main loop.
     */
    qemu_bh_schedule(cq->irq_bh);
}

void nvme_cq_irq_init(NvmeCQueue *cq)
{
    cq->irq_bh = qemu_bh_new(nvme_isr_notify_legacy, cq);
}

void nvme_cq_irq_cleanup(NvmeCQueue *cq)
{
    if (cq->irq_bh) {
        qemu_bh_delete(cq->irq_bh);
        cq->irq_bh = NULL;
    }
}

int nvme_setup_virq(FemuCtrl *n, NvmeCQueue *cq)
{
    int ret;

    if (cq->cqid && cq->irq_enabled) {
        ret = nvme_add_kvm_msi_virq(n, cq);
        if (ret < 0) {
            return -1;
        }

        ret = nvme_set_guest_notifier(n, &cq->guest_notifier, cq->cqid);
        if (ret < 0) {
            femu_err("nvme: set guest notifier failed\n");
            return -1;
        }
    }

    if (cq->irq_enabled && !n->vector_poll_started) {
        /* the flag tells teardown to unset them, so set it on success only */
        if (msix_set_vector_notifiers(&n->parent_obj, nvme_vector_unmask,
                                      nvme_vector_mask, nvme_vector_poll)) {
            femu_err("nvme: msix_set_vector_notifiers failed\n");
            return -1;
        }
        n->vector_poll_started = true;
        return 0;
    }

    /*
     * The notifiers act only when a vector changes. A host that unmasks its
     * vectors before it creates the queues (FreeBSD does) sends no unmask
     * for this queue, so sync it here.
     */
    if (cq->cqid) {
        nvme_irqfd_sync(n, cq);
    }

    return 0;
}

int nvme_clear_virq(FemuCtrl *n)
{
    nvme_clear_guest_notifier(n);

    return 0;
}
