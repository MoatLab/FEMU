/* AUTOMATICALLY GENERATED, DO NOT MODIFY */

/*
 * schema-defined QAPI event functions
 *
 * Copyright (c) 2014 Wenchao Xia
 *
 * Authors:
 *  Wenchao Xia  <wenchaoqemu@gmail.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QAPI_EVENT_H
#define QAPI_EVENT_H

#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi-types.h"


void qapi_event_send_acpi_device_ost(ACPIOSTInfo *info, Error **errp);

void qapi_event_send_balloon_change(int64_t actual, Error **errp);

void qapi_event_send_block_image_corrupted(const char *device, bool has_node_name, const char *node_name, const char *msg, bool has_offset, int64_t offset, bool has_size, int64_t size, bool fatal, Error **errp);

void qapi_event_send_block_io_error(const char *device, const char *node_name, IoOperationType operation, BlockErrorAction action, bool has_nospace, bool nospace, const char *reason, Error **errp);

void qapi_event_send_block_job_cancelled(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, Error **errp);

void qapi_event_send_block_job_completed(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, bool has_error, const char *error, Error **errp);

void qapi_event_send_block_job_error(const char *device, IoOperationType operation, BlockErrorAction action, Error **errp);

void qapi_event_send_block_job_ready(BlockJobType type, const char *device, int64_t len, int64_t offset, int64_t speed, Error **errp);

void qapi_event_send_block_write_threshold(const char *node_name, uint64_t amount_exceeded, uint64_t write_threshold, Error **errp);

void qapi_event_send_device_deleted(bool has_device, const char *device, const char *path, Error **errp);

void qapi_event_send_device_tray_moved(const char *device, const char *id, bool tray_open, Error **errp);

void qapi_event_send_dump_completed(DumpQueryResult *result, bool has_error, const char *error, Error **errp);

void qapi_event_send_guest_panicked(GuestPanicAction action, bool has_info, GuestPanicInformation *info, Error **errp);

void qapi_event_send_mem_unplug_error(const char *device, const char *msg, Error **errp);

void qapi_event_send_migration(MigrationStatus status, Error **errp);

void qapi_event_send_migration_pass(int64_t pass, Error **errp);

void qapi_event_send_nic_rx_filter_changed(bool has_name, const char *name, const char *path, Error **errp);

void qapi_event_send_powerdown(Error **errp);

void qapi_event_send_quorum_failure(const char *reference, int64_t sector_num, int64_t sectors_count, Error **errp);

void qapi_event_send_quorum_report_bad(QuorumOpType type, bool has_error, const char *error, const char *node_name, int64_t sector_num, int64_t sectors_count, Error **errp);

void qapi_event_send_reset(Error **errp);

void qapi_event_send_resume(Error **errp);

void qapi_event_send_rtc_change(int64_t offset, Error **errp);

void qapi_event_send_shutdown(Error **errp);

void qapi_event_send_spice_connected(SpiceBasicInfo *server, SpiceBasicInfo *client, Error **errp);

void qapi_event_send_spice_disconnected(SpiceBasicInfo *server, SpiceBasicInfo *client, Error **errp);

void qapi_event_send_spice_initialized(SpiceServerInfo *server, SpiceChannel *client, Error **errp);

void qapi_event_send_spice_migrate_completed(Error **errp);

void qapi_event_send_stop(Error **errp);

void qapi_event_send_suspend(Error **errp);

void qapi_event_send_suspend_disk(Error **errp);

void qapi_event_send_vnc_connected(VncServerInfo *server, VncBasicInfo *client, Error **errp);

void qapi_event_send_vnc_disconnected(VncServerInfo *server, VncClientInfo *client, Error **errp);

void qapi_event_send_vnc_initialized(VncServerInfo *server, VncClientInfo *client, Error **errp);

void qapi_event_send_vserport_change(const char *id, bool open, Error **errp);

void qapi_event_send_wakeup(Error **errp);

void qapi_event_send_watchdog(WatchdogExpirationAction action, Error **errp);

typedef enum QAPIEvent {
    QAPI_EVENT_ACPI_DEVICE_OST = 0,
    QAPI_EVENT_BALLOON_CHANGE = 1,
    QAPI_EVENT_BLOCK_IMAGE_CORRUPTED = 2,
    QAPI_EVENT_BLOCK_IO_ERROR = 3,
    QAPI_EVENT_BLOCK_JOB_CANCELLED = 4,
    QAPI_EVENT_BLOCK_JOB_COMPLETED = 5,
    QAPI_EVENT_BLOCK_JOB_ERROR = 6,
    QAPI_EVENT_BLOCK_JOB_READY = 7,
    QAPI_EVENT_BLOCK_WRITE_THRESHOLD = 8,
    QAPI_EVENT_DEVICE_DELETED = 9,
    QAPI_EVENT_DEVICE_TRAY_MOVED = 10,
    QAPI_EVENT_DUMP_COMPLETED = 11,
    QAPI_EVENT_GUEST_PANICKED = 12,
    QAPI_EVENT_MEM_UNPLUG_ERROR = 13,
    QAPI_EVENT_MIGRATION = 14,
    QAPI_EVENT_MIGRATION_PASS = 15,
    QAPI_EVENT_NIC_RX_FILTER_CHANGED = 16,
    QAPI_EVENT_POWERDOWN = 17,
    QAPI_EVENT_QUORUM_FAILURE = 18,
    QAPI_EVENT_QUORUM_REPORT_BAD = 19,
    QAPI_EVENT_RESET = 20,
    QAPI_EVENT_RESUME = 21,
    QAPI_EVENT_RTC_CHANGE = 22,
    QAPI_EVENT_SHUTDOWN = 23,
    QAPI_EVENT_SPICE_CONNECTED = 24,
    QAPI_EVENT_SPICE_DISCONNECTED = 25,
    QAPI_EVENT_SPICE_INITIALIZED = 26,
    QAPI_EVENT_SPICE_MIGRATE_COMPLETED = 27,
    QAPI_EVENT_STOP = 28,
    QAPI_EVENT_SUSPEND = 29,
    QAPI_EVENT_SUSPEND_DISK = 30,
    QAPI_EVENT_VNC_CONNECTED = 31,
    QAPI_EVENT_VNC_DISCONNECTED = 32,
    QAPI_EVENT_VNC_INITIALIZED = 33,
    QAPI_EVENT_VSERPORT_CHANGE = 34,
    QAPI_EVENT_WAKEUP = 35,
    QAPI_EVENT_WATCHDOG = 36,
    QAPI_EVENT__MAX = 37,
} QAPIEvent;

extern const char *const QAPIEvent_lookup[];

#endif
