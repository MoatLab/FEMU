.. _secvar-driver-api:

Secvar Drivers
==============

This document will attempt to define the expected behavior of the two secvar
drivers, and how a developer should implement a new one.


Storage vs Backend drivers
--------------------------

There are two types of drivers for secure variable support, storage and backend
drivers. Storage drivers are the most simple: they control how and where secure
variables are stored for a given platform. Backend drivers on the other hand,
can be bit more complex. They control the overall scheme of OS secureboot --
from what variables are used, what format the variables are intended to be, how
they are updated, and how to determine the platform's OS secure boot state.

These drivers are intended to be as self-contained as possible, so that ideally
any combination of storage and backend drivers in the future should be
compatible.


Storage Driver API
------------------

The storage driver is expected to:
 * persist secure variables in a tamper-resistant manner
 * handle two logical types of variable lists (referred to as "banks")
   * the "variable bank" stores the active list of variables
   * the "update bank" stores proposed updates to the variable bank
 * handle variables using a specific secvar flag in a sensible manner

Storage drivers must implement the following hooks for secvar to properly
utilize:

.. code-block:: c

  struct secvar_storage_driver {
      int (*load_bank)(struct list_head *bank, int section);
      int (*write_bank)(struct list_head *bank, int section);
      int (*store_init)(void);
      void (*lock)(void);
      uint64_t max_var_size;
  };

The following subsections will give a summary of each hook, when they are used,
and their expected behavior.


store_init
^^^^^^^^^^

The ``store_init`` hook is called at the beginning of secure variable
intialization. This hook should perform any initialization logic required for
the other hooks to operate.

IMPORTANT: If this hook returns an error (non-zero) code, secvar will
immediately halt the boot. When implementing this hook, consider the
implications of any errors in initialization, and whether they may affect the
secure state. For example, if secure state is indeterminable due to some
hardware failure, this is grounds for a halt.

This hook should only be called once. Subsequent calls should have no effect,
or raise an error.


load_bank
^^^^^^^^^

The ``load_bank`` hook should load variables from persistent storage into the
in-memory linked lists, for the rest of secvar to operate on.

The ``bank`` parameter should be an initialized linked list. This list may not
be empty, and this hook should only append variables to the list.

The variables this hook loads should depend on the ``section`` flag:
 * if ``SECVAR_VARIABLE_BANK``, load the active variables
 * if ``SECVAR_UPDATE_BANK``, load the proposed updates

This hook is called twice at the beginning of secure variable initialization,
one for loading each bank type into their respective lists. This hook may be
called again afterwards (e.g. a reset mechanism by a backend).


write_bank
^^^^^^^^^^

The ``write_bank`` hook should persist variables using some non-volatile
storage (e.g. flash).

The ``bank`` parameter should be an initialized linked list. This list may be
empty. It is up to the storage driver to determine how to handle this, but it is
strongly recommended to zeroize the storage location.

The ``section`` parameter indicates which list of variables is to be written
following the same pattern as in ``load_bank``.

This hook is called for the variable bank if the backend driver reports that
updates were processed. This hook is called for the update bank in all cases
EXCEPT where no updates were found by the backend (this includes error cases).

This hook should not be called more than once for the variable bank. This hook
is called once in the secvar initialization procedure, and then each time 
``opal_secvar_enqueue_update()`` is successfully called.


lock
^^^^

The ``lock`` hook may perform any write-lock protections as necessary by the
platform. This hook is unconditionally called after the processing step
performed in the main secure variable logic, and should only be called once.
Subsequent calls should have no effect, or raise an error.

This hook MUST also be called in any error cases that may interrupt the regular
secure variable initialization flow, to prevent leaving the storage mechanism
open to unauthorized writes.

This hook MUST halt the boot if any internal errors arise that may compromise
the protection of the storage.

If locking is not applicable to the storage mechanism, this hook may be
implemented as a no-op.


max_var_size
^^^^^^^^^^^^

The ``max_var_size`` field is not a function hook, but a value to be referenced
by other components to determine the maximum variable size. As this driver is
responsible for persisting variables somewhere, it has the option to determine
the maximum size to use.


A Quick Note on Secvar Flags
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

While "communication" between the storage and backend drivers has been
minimized as best as possible, there are a few cases where the storage driver
may need to take a few hints from the backend.

The ``flags`` field in ``struct secvar_node`` may contain one of the following
values:

.. code-block:: c

  #define SECVAR_FLAG_VOLATILE		0x1
  #define SECVAR_FLAG_PROTECTED 	0x2

At time of writing this document, the flags are mutually exclusive, however
this may change in the future.

``VOLATILE`` indicates that the storage driver should NOT persist this variable
to storage.

``PROTECTED`` indicates that this variable has a heightened importance than
other variables, and if applicable to the storage driver, stored in a more
secure/tamper-resistant region (e.g. store variables important to secureboot
state in TPM NV rather than PNOR on p9).


Backend Driver API
------------------

The backend driver at the core defines how secure variables are defined and
processed, and by extension, also how operate the platform's secure boot modes.

.. code-block:: c

  struct secvar_backend_driver {
      int (*pre_process)(struct list_head *variable_bank
                         struct list_head *update_bank);
      int (*process)(struct list_head *variable_bank
                     struct list_head *update_bank);
      int (*post_process)(struct list_head *variable_bank
                          struct list_head *update_bank);
      int (*validate)(struct secvar *var);
      const char *compatible;
  };

The following subsections will give a summary of each hook, when they are used,
and their expected behaviors.


pre_process
^^^^^^^^^^^

The ``pre_process`` hook is an optional hook that a backend driver may implement
to handle any early logic prior to processing. If this hook is set to ``NULL``,
it is skipped.

As this hook is called just after loading the variables from the storage driver
but just before ``process``, this hook is provided for convenience to do any
early initialization logic as necessary.

Any error code returned by this hook will be treated as a failure, and halt
secure variable initialization.

Example usage:
 * initialize empty variables that were not loaded from storage
 * allocate any internal structures that may be needed for processing


process
^^^^^^^

The ``process`` hook is the only required hook, and should contain all variable
update process logic. Unlike the other two hooks, this hook must be defined, or
secure variable initialization will halt.

This hook is expected to iterate through any variables contained in the
``update_bank`` list argument, and perform any action on the
``variable_bank`` list argument as the backend seems appropriate for the given
update (e.g. add/remove/update variable)

NOTE: the state of these bank lists will be written to persistent storage as-is,
so for example, if the update bank should be cleared, it should be done prior to
returning from this hook.

Unlike the other two hooks, this hook may return a series of return codes
indicating various status situations. This return code is exposed in the device
tree at ``secvar/update-status``. See the table below for an expected definition
of the return code meanings. Backends SHOULD document any deviations or
extensions to these definitions for their specific implementation.

To prevent excessive writes to flash, the main secure variable flow will only
perform writes when the ``process`` hook returns a status that declares
something has been changed. The variable bank is only written to storage if
``process`` returns ``OPAL_SUCCESS``.

On the other hand, the update bank is written to storage if the return code is
anything other than ``OPAL_EMPTY`` (which signals that there were no updates to
process). This includes all error cases, therefore the backend is responsible
for emptying the update bank prior to exiting with an error, if the bank is to
be cleared.


Status codes
""""""""""""

+-----------------+-----------------------------------------------+
| update-status   | Generic Reason                                |
+-----------------+-----------------------------------------------+
| OPAL_SUCCESS    | Updates were found and processed successfully |
+-----------------+-----------------------------------------------+
| OPAL_EMPTY      | No updates were found, none processed         |
+-----------------+-----------------------------------------------+
| OPAL_PARAMETER  | Malformed, or unexpected update data blob     |
+-----------------+-----------------------------------------------+
| OPAL_PERMISSION | Update failed to apply, possible auth failure |
+-----------------+-----------------------------------------------+
| OPAL_HARDWARE   | Misc. storage-related error                   |
+-----------------+-----------------------------------------------+
| OPAL_RESOURCE   | Out of space (reported by storage)            |
+-----------------+-----------------------------------------------+
| OPAL_NO_MEM     | Out of memory                                 |
+-----------------+-----------------------------------------------+

See also: ``device-tree/ibm,opal/secvar/secvar.rst``.


post_process
^^^^^^^^^^^^

The ``post_process`` hook is an optional hook that a backend driver may
implement to handle any additional logic after the processing step. Like
``pre_process``, it may be set to ``NULL`` if unused.

This hook is called AFTER performing any writes to storage, and AFTER locking
the persistant storage. Any changes to the variable bank list in this hook will
NOT be persisted to storage.

Any error code returned by this hook will be treated as a failure, and halt
secure variable initialization.

Example usage:
 * determine secure boot state (and set ``os-secure-enforcing``)
 * remove any variables from the variable bank that do not need to be exposed
 * append any additional volatile variables


validate
^^^^^^^^

!!NOTE!! This is not currently implemented, and the detail below is subject to
change.

The ``validate`` hook is an optional hook that a backend may implement to check
if a single variable is valid. If implemented, this hook is called during
``opal_secvar_enqueue_update`` to provide more immediate feedback to the caller
on proposed variable validity.

This hook should return ``OPAL_SUCCESS`` if the validity check passes. Any
other return code is treated as a failure, and will be passed through the
``enqueue_update`` call.

Example usage:
 * check for valid payload data structure
 * check for valid signature format
 * validate the signature against current variables
 * implement a variable white/blacklist


compatible
^^^^^^^^^^

The compatible field is a required field that declares the compatibility of
this backend driver. This compatible field is exposed in the
``secvar/compatible`` device tree node for subsequent kernels, etc to
determine how to interact with the secure variables.
