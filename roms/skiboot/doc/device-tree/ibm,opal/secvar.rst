.. _device-tree/ibm,opal/secvar:

Secvar Binding
==============

This device tree binding describes the status of secure variable support,
including any size values, or values relating to the secure state of the
system.


/ibm,opal/secvar node bindings
------------------------------

Node: secvar

Description: Container of secvar related properties.

The node name must be "secvar".

It is implemented as a child of the node "/ibm,opal".

The node is optional, will be defined if the platform supports secure
variables. It will not be created if the system does not.

Properties:

- compatible

  Usage:
    required
  Value type:
    string

  Definition:

  This property defines the compatibility of the current running
  backend. This defines the binary format of the data buffers passed
  via the related secvar OPAL API functions. This also defines the
  expected behavior of how updates should be processed, such as how
  key updates should be signed, what the key hierarchy is, what
  algorithms are in use, etc.

  This value also determines how a user can signal a desire to require
  all further images to require signature validations. See the
  "On Enforcing Secure Mode" section below.

  This property also contains a generic "ibm,secvar-backend" compatible,
  which defines the basic-level compatibility of the secvar implementation.
  This includes the basic behavior of the API (excluding the data format),
  and the expected device tree properties contained in this node.

- format

  Usage:
    required
  Value type:
    string

  This property defines the format of data passed in and out of the secvar
  API. In most cases, this should be the same string as the backend-specific
  string in compatible.

  The format defined by this string should be documented by the corresponding
  backend.

- status

  Usage:
    required
  Value type:
    string

  Definition:

  This property states the general status of secure variable support. This
  will be set to "okay" if the secvar OPAL API should be working as expected,
  and there were no unrecoverable faults in the basic secure variable
  initialization logic.

  This property may be set to "fail" if the platform does not properly
  select the drivers to use. Failures may also occur if the storage devices
  are inaccessible for some reason.

  Failures are NOT caused by malformed data loaded or processed in either
  storage or backend drivers, as these are faults correctable by a user.

- update-status

  Usage:
    required
  Value type:
    <u64>

  Definition:

  This property should contain the status code of the update processing
  logic, as returned by the backend. This value is intended to be
  consumed by userspace tools to confirm updates were processed as
  intended.

  The value contained in this property should adhere to the table below.
  Any additional error states that may be specific to a backend should
  be stored in the backend node.


- max-var-size

  Usage:
    required
  Value type:
    <u64>

  Definition:

  This is the maximum buffer size accepted for secure variables. The API
  will reject updates larger than this value, and storage drivers must
  reject loading variables larger than this value.

  As this may depend on the persistant storage devices in use, this
  value is determined by the storage driver, and may differ across
  platforms.

- max-var-key-len

  Usage:
    required
  Value type:
    <u64>

  Definition:

  This is the maximum size permitted for the key of a variable. As the
  value is a constant, it should be the same across platforms unless
  changed in code.


Example
-------

.. code-block:: dts

	/ibm,opal/secvar {
		compatible = "ibm,secvar-backend" "ibm,edk2-compat-v1";

                status = "okay";
                max-var-size = <0x1000>;
                max-var-key-len = <0x400>
	};

Update Status Code Table
------------------------

The update status property should be set by the backend driver to a value
that best fits its error condition. The following table defines the
general intent of each error code, check backend specific documentation
for more detail.

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
| OPAL_RESOURCE   | Out of space (reported by storage             |
+-----------------+-----------------------------------------------+
| OPAL_NO_MEM     | Out of memory                                 |
+-----------------+-----------------------------------------------+


On Enforcing Secure Mode
------------------------

The os-secureboot-enforcing property in /ibm,secureboot/ is created by the
backend if the owner has expressed a desire for boot loaders, kernels, etc
to require any images to be signed by an appropriate key stored in secure
variables. As this property is created by the backend, it is up to the
backend to define what the required state of the secure variables should
be to enter this mode.

For example, we may want to only enable secure boot if we have a top-
level "Platform Key", so this property is created by the backend if
by the end of update processing, a "PK" variable exists. By enrolling a
PK, the system will be in "secure mode" until the PK is deleted.
