/*
 * QEMU migration vmstate registration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef MIGRATION_REGISTER_H
#define MIGRATION_REGISTER_H

#include "hw/core/vmstate-if.h"

typedef struct MigPendingData {
    /* Amount of pending bytes can be transferred in precopy or stopcopy */
    uint64_t precopy_bytes;
    /* Amount of pending bytes can be transferred in postcopy */
    uint64_t postcopy_bytes;
    /* Amount of pending bytes can be transferred only in stopcopy */
    uint64_t stopcopy_bytes;
    /* Number of new pending switchover ACKs */
    uint32_t switchover_ack_pending;
    /*
     * Total pending data, modules do not need to update this field, it
     * will be automatically calculated by migration core API.
     */
    uint64_t total_bytes;
} MigPendingData;

/**
 * struct SaveVMHandlers: handler structure to finely control
 * migration of complex subsystems and devices, such as RAM, block and
 * VFIO.
 */
typedef struct SaveVMHandlers {

    /* The following handlers run inside the BQL. */

    /**
     * @save_state
     *
     * Saves state section on the source using the latest state format
     * version.
     *
     * Legacy method. Should be deprecated when all users are ported
     * to VMStateDescription.
     *
     * @f: QEMUFile where to send the data
     * @opaque: data pointer passed to register_savevm_live()
     */
    void (*save_state)(QEMUFile *f, void *opaque);

    /**
     * @save_prepare
     *
     * Called early, even before migration starts, and can be used to
     * perform early checks.
     *
     * @opaque: data pointer passed to register_savevm_live()
     * @errp: pointer to Error*, to store an error if it happens.
     *
     * Returns zero to indicate success and negative for error
     */
    int (*save_prepare)(void *opaque, Error **errp);

    /**
     * @save_setup
     *
     * Initializes the data structures on the source and transmits
     * first section containing information on the device
     *
     * @f: QEMUFile where to send the data
     * @opaque: data pointer passed to register_savevm_live()
     * @errp: pointer to Error*, to store an error if it happens.
     *
     * Returns zero to indicate success and negative for error
     */
    int (*save_setup)(QEMUFile *f, void *opaque, Error **errp);

    /**
     * @save_cleanup
     *
     * Uninitializes the data structures on the source.
     * Note that this handler can be called even if save_setup
     * wasn't called earlier.
     *
     * @opaque: data pointer passed to register_savevm_live()
     */
    void (*save_cleanup)(void *opaque);

    /**
     * @save_complete
     *
     * Transmits the last section for the device containing any
     * remaining data at the end phase of migration.
     *
     * For precopy, this will be invoked _during_ the switchover phase
     * after source VM is stopped.
     *
     * For postcopy, this will be invoked _after_ the switchover phase
     * (except some very unusual cases, like PMEM ramblocks), while
     * destination VM can be running.
     *
     * @f: QEMUFile where to send the data
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns zero to indicate success and negative for error
     */
    int (*save_complete)(QEMUFile *f, void *opaque);

    /**
     * @save_complete_precopy_thread (invoked in a separate thread)
     *
     * Called at the end of a precopy phase from a separate worker thread
     * in configurations where multifd device state transfer is supported
     * in order to perform asynchronous transmission of the remaining data in
     * parallel with @save_complete handlers.
     * When postcopy is enabled, devices that support postcopy will skip this
     * step.
     *
     * @d: a #SaveCompletePrecopyThreadData containing parameters that the
     * handler may need, including this device section idstr and instance_id,
     * and opaque data pointer passed to register_savevm_live().
     * @errp: pointer to Error*, to store an error if it happens.
     *
     * Returns true to indicate success and false for errors.
     */
    SaveCompletePrecopyThreadHandler save_complete_precopy_thread;

    /* This runs both outside and inside the BQL.  */

    /**
     * @is_active
     *
     * Will skip a state section if not active
     *
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns true if state section is active else false
     */
    bool (*is_active)(void *opaque);

    /**
     * @has_postcopy
     *
     * Checks if a device supports postcopy
     *
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns true for postcopy support else false
     */
    bool (*has_postcopy)(void *opaque);

    /**
     * @is_active_iterate
     *
     * As #SaveVMHandlers.is_active(), will skip an inactive state
     * section in qemu_savevm_state_iterate.
     *
     * For example, it is needed for only-postcopy-states, which needs
     * to be handled by qemu_savevm_state_setup() and
     * qemu_savevm_state_pending(), but do not need iterations until
     * not in postcopy stage.
     *
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns true if state section is active else false
     */
    bool (*is_active_iterate)(void *opaque);

    /**
     * @save_query_pending
     *
     * This estimates the remaining data to transfer on the source side.
     *
     * When @exact is true, a module must report accurate results.  When
     * @exact is false, a module may report estimates.
     *
     * It's highly recommended that modules implement a faster version of
     * the query path (for example, by proper caching on the counters) if
     * an accurate query will be time-consuming.
     *
     * @opaque: data pointer passed to register_savevm_live()
     * @pending: pointer to a MigPendingData struct
     * @exact: set to true for an accurate (slow) query
     * @final: set to true for the final query during switchover. When final is
     * true, the query is called with BQL locked. Otherwise, it's called with
     * BQL unlocked.
     */
    void (*save_query_pending)(void *opaque, MigPendingData *pending,
                               bool exact, bool final);

    /* This runs outside the BQL in the migration case, and
     * within the lock in the savevm case.  The callback had better only
     * use data that is local to the migration thread or protected
     * by other locks.
     */

    /**
     * @save_live_iterate
     *
     * Should send a chunk of data until the point that stream
     * bandwidth limits tell it to stop. Each call generates one
     * section.
     *
     * @f: QEMUFile where to send the data
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns 0 to indicate that there is still more data to send,
     *         1 that there is no more data to send and
     *         negative to indicate an error.
     */
    int (*save_live_iterate)(QEMUFile *f, void *opaque);

    /* This runs outside the BQL!  */

    /**
     * @save_postcopy_prepare
     *
     * This hook will be invoked on the source side right before switching
     * to postcopy (before VM stopped).
     *
     * @f:      QEMUFile where to send the data
     * @opaque: Data pointer passed to register_savevm_live()
     * @errp:   Error** used to report error message
     *
     * Returns: true if succeeded, false if error occured.  When false is
     * returned, @errp must be set.
     */
    bool (*save_postcopy_prepare)(QEMUFile *f, void *opaque, Error **errp);

    /**
     * @load_state
     *
     * Load sections generated by any of the save functions that
     * generate sections.
     *
     * Legacy method. Should be deprecated when all users are ported
     * to VMStateDescription.
     *
     * @f: QEMUFile where to receive the data
     * @opaque: data pointer passed to register_savevm_live()
     * @version_id: the maximum version_id supported
     *
     * Returns zero to indicate success and negative for error
     */
    int (*load_state)(QEMUFile *f, void *opaque, int version_id);

    /**
     * @load_state_buffer (invoked outside the BQL)
     *
     * Load device state buffer provided to qemu_loadvm_load_state_buffer().
     *
     * @opaque: data pointer passed to register_savevm_live()
     * @buf: the data buffer to load
     * @len: the data length in buffer
     * @errp: pointer to Error*, to store an error if it happens.
     *
     * Returns true to indicate success and false for errors.
     */
    bool (*load_state_buffer)(void *opaque, char *buf, size_t len,
                              Error **errp);

    /**
     * @load_setup
     *
     * Initializes the data structures on the destination.
     *
     * @f: QEMUFile where to receive the data
     * @opaque: data pointer passed to register_savevm_live()
     * @errp: pointer to Error*, to store an error if it happens.
     *
     * Returns zero to indicate success and negative for error
     */
    int (*load_setup)(QEMUFile *f, void *opaque, Error **errp);

    /**
     * @load_cleanup
     *
     * Uninitializes the data structures on the destination.
     * Note that this handler can be called even if load_setup
     * wasn't called earlier.
     *
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns zero to indicate success and negative for error
     */
    int (*load_cleanup)(void *opaque);

    /**
     * @resume_prepare
     *
     * Called when postcopy migration wants to resume from failure
     *
     * @s: Current migration state
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns zero to indicate success and negative for error
     */
    int (*resume_prepare)(MigrationState *s, void *opaque);

    /**
     * @switchover_start
     *
     * Notifies that the switchover has started. Called only on
     * the destination.
     *
     * @opaque: data pointer passed to register_savevm_live()
     *
     * Returns zero to indicate success and negative for error
     */
    int (*switchover_start)(void *opaque);
} SaveVMHandlers;

/**
 * register_savevm_live: Register a set of custom migration handlers
 *
 * @idstr: state section identifier
 * @instance_id: instance id
 * @version_id: version id supported
 * @ops: SaveVMHandlers structure
 * @opaque: data pointer passed to SaveVMHandlers handlers
 */
int register_savevm_live(const char *idstr,
                         uint32_t instance_id,
                         int version_id,
                         const SaveVMHandlers *ops,
                         void *opaque);

/**
 * unregister_savevm: Unregister custom migration handlers
 *
 * @obj: object associated with state section
 * @idstr:  state section identifier
 * @opaque: data pointer passed to register_savevm_live()
 */
void unregister_savevm(VMStateIf *obj, const char *idstr, void *opaque);

#endif
