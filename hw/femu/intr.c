#include "./nvme.h"

static int nvme_add_kvm_msi_virq(FemuCtrl *n, NvmeCQueue *cq)
{
    int virq;
    int vector_n;
    KVMRouteChange c;

    if (!msix_enabled(&(n->parent_obj))) {
        femu_err("MSIX is mandatory for the device");
        return -1;
    }

    if (event_notifier_init(&cq->guest_notifier, 0)) {
        femu_err("Initiated guest notifier failed");
        return -1;
    }
    event_notifier_set_handler(&cq->guest_notifier, NULL);

    vector_n = cq->vector;

    c = kvm_irqchip_begin_route_changes(kvm_state);
    virq = kvm_irqchip_add_msi_route(&c, vector_n, &n->parent_obj);
    if (virq < 0) {
        femu_err("Route MSIX vector to KVM failed");
        event_notifier_cleanup(&cq->guest_notifier);
        return -1;
    }
    kvm_irqchip_commit_route_changes(&c);
    cq->virq = virq;
    femu_debug("%s,cq[%d]->virq=%d\n", __func__, cq->cqid, virq);

    return 0;
}

static void nvme_remove_kvm_msi_virq(NvmeCQueue *cq)
{
    kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, &cq->guest_notifier, cq->virq);
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

    for (qid = 1; qid <= n->nr_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            break;
        }

        if (cq->irq_enabled) {
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
    NvmeCQueue *cq;
    EventNotifier *e;
    int qid;
    int ret;

    for (qid = 1; qid <= n->nr_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        e = &cq->guest_notifier;
        if (cq->vector == vector) {
            if (cq->msg.data != msg.data || cq->msg.address != msg.address) {
                ret = kvm_irqchip_update_msi_route(kvm_state, cq->virq, msg, dev);
                if (ret < 0) {
                    femu_err("MSI irq update vector %u failed", vector);
                    return ret;
                }

                kvm_irqchip_commit_routes(kvm_state);

                cq->msg = msg;
            }

            ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, e,
                                                     NULL, cq->virq);
            if (ret < 0) {
                femu_err("MSI add irqfd gsi vector %u failed, ret %d", vector, ret);
                return ret;
            }
        }
    }

    return 0;
}

static void nvme_vector_mask(PCIDevice *dev, unsigned vector)
{
    FemuCtrl *n = container_of(dev, FemuCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    int ret;

    for (uint32_t qid = 1; qid <= n->nr_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }

        if (cq->vector == vector) {
            e = &cq->guest_notifier;
            ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e, cq->virq);
            if (ret != 0) {
                femu_err("remove_irqfd_notifier_gsi failed");
            }
            return;
        }
    }
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
        if (!cq) {
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

static void nvme_isr_notify_legacy(void *opaque)
{
    NvmeCQueue *cq = opaque;
    FemuCtrl *n = cq->ctrl;

    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), cq->vector);
        } else if (msi_enabled(&(n->parent_obj))) {
            if (!(n->bar.intms & (1 << cq->vector))) {
                msi_notify(&(n->parent_obj), cq->vector);
            }
        } else {
            pci_irq_pulse(&n->parent_obj);
        }
    }
}

void nvme_isr_notify_admin(void *opaque)
{
    return nvme_isr_notify_legacy(opaque);
}

void nvme_isr_notify_io(void *opaque)
{
    NvmeCQueue *cq = opaque;

    /* Coperd: utilize irqfd mechanism */
    if (cq->irq_enabled && cq->virq) {
        event_notifier_set(&cq->guest_notifier);
        return;
    }

    /* Coperd: fall back */
    nvme_isr_notify_legacy(opaque);
}

int nvme_setup_virq(FemuCtrl *n, NvmeCQueue *cq)
{
    int ret;

    if (cq->cqid && cq->irq_enabled) {
        ret = nvme_add_kvm_msi_virq(n, cq);
        if (ret < 0) {
            femu_err("nvme: add kvm msix virq failed\n");
            return -1;
        }

        ret = nvme_set_guest_notifier(n, &cq->guest_notifier, cq->cqid);
        if (ret < 0) {
            femu_err("nvme: set guest notifier failed\n");
            return -1;
        }
    }

    if (cq->irq_enabled && !n->vector_poll_started) {
        n->vector_poll_started = true;
        if (msix_set_vector_notifiers(&n->parent_obj, nvme_vector_unmask,
                                      nvme_vector_mask, nvme_vector_poll)) {
            femu_err("nvme: msix_set_vector_notifiers failed\n");
            return -1;
        }
    }

    return 0;
}

int nvme_clear_virq(FemuCtrl *n)
{
    nvme_clear_guest_notifier(n);

    return 0;
}
