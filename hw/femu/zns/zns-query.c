/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Zoned namespace state for query-femu. The pollers change zone state under
 * the namespace's zone lock, so a copy taken under that lock describes one
 * point in time. The main loop must not wait for the lock: a poller can hold
 * it for a whole Report Zones transfer. It only tries the lock, and the
 * command sleeps and tries again when a poller has it. The state counts are
 * kept with each state change, so the copy reads only the zones it lists.
 */
#include "qemu/osdep.h"
#include "zns.h"
#include "../femu-query.h"

static FemuZoneState zns_query_state(NvmeZone *zone)
{
    switch (zns_get_zone_state(zone)) {
    case NVME_ZONE_STATE_EMPTY:
        return FEMU_ZONE_STATE_EMPTY;
    case NVME_ZONE_STATE_IMPLICITLY_OPEN:
        return FEMU_ZONE_STATE_IMPLICITLY_OPEN;
    case NVME_ZONE_STATE_EXPLICITLY_OPEN:
        return FEMU_ZONE_STATE_EXPLICITLY_OPEN;
    case NVME_ZONE_STATE_CLOSED:
        return FEMU_ZONE_STATE_CLOSED;
    case NVME_ZONE_STATE_READ_ONLY:
        return FEMU_ZONE_STATE_READ_ONLY;
    case NVME_ZONE_STATE_FULL:
        return FEMU_ZONE_STATE_FULL;
    case NVME_ZONE_STATE_OFFLINE:
        return FEMU_ZONE_STATE_OFFLINE;
    default:
        /* zns_set_zone_state() is only given the states above */
        g_assert_not_reached();
    }
}

bool zns_query_collect(NvmeNamespace *ns, FemuQueryZoned *q)
{
    const uint32_t *st = ns->zns->zone_states;
    uint32_t i;

    if (qemu_mutex_trylock(&ns->zns->zone_lock)) {
        return false;
    }

    q->lba_size = 1U << zns_ns_lbads(ns);
    q->zone_size = ns->zone_size;
    q->zone_cap = ns->zone_capacity;
    q->max_open = ns->max_open_zones;
    q->max_active = ns->max_active_zones;
    q->num_zones = ns->num_zones;
    q->counts[FEMU_ZONE_STATE_EMPTY] = st[NVME_ZONE_STATE_EMPTY];
    q->counts[FEMU_ZONE_STATE_IMPLICITLY_OPEN] =
        st[NVME_ZONE_STATE_IMPLICITLY_OPEN];
    q->counts[FEMU_ZONE_STATE_EXPLICITLY_OPEN] =
        st[NVME_ZONE_STATE_EXPLICITLY_OPEN];
    q->counts[FEMU_ZONE_STATE_CLOSED] = st[NVME_ZONE_STATE_CLOSED];
    q->counts[FEMU_ZONE_STATE_READ_ONLY] = st[NVME_ZONE_STATE_READ_ONLY];
    q->counts[FEMU_ZONE_STATE_FULL] = st[NVME_ZONE_STATE_FULL];
    q->counts[FEMU_ZONE_STATE_OFFLINE] = st[NVME_ZONE_STATE_OFFLINE];

    q->nr_zones = 0;
    for (i = q->offset; q->zones && i < ns->num_zones &&
         q->nr_zones < q->max_zones; i++) {
        NvmeZone *zone = &ns->zone_array[i];
        FemuQueryZone *z = &q->zones[q->nr_zones++];

        z->index = i;
        z->slba = zone->d.zslba;
        z->cap = zone->d.zcap;
        z->state = zns_query_state(zone);
        z->type = zone->d.zt == NVME_ZONE_TYPE_CONVENTIONAL ?
                  FEMU_ZONE_TYPE_CONVENTIONAL : FEMU_ZONE_TYPE_SEQUENTIAL;
        /* the write pointer Report Zones gives, not the reservation one */
        z->wp_valid = zns_wp_is_valid(zone);
        z->wp = zone->d.wp;
        z->zrwa = zone->d.za & NVME_ZA_ZRWA_VALID;
    }

    qemu_mutex_unlock(&ns->zns->zone_lock);
    return true;
}
