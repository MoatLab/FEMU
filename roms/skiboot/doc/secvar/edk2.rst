.. _secvar/edk2:

Skiboot edk2-compatible Secure Variable Backend
===============================================

Overview
--------

The edk2 secure variable backend for skiboot borrows from edk2 concepts
such as the three key hierarchy (PK, KEK, and db), and a similar
structure. In general, variable updates must be signed with a key
of a higher level. So, updates to the db must be signed with a key stored
in the KEK; updates to the KEK must be signed with the PK. Updates to the
PK must be signed with the previous PK (if any).

Variables are stored in the efi signature list format, and updates are a
signed variant that includes an authentication header.

If no PK is currently enrolled, the system is considered to be in "Setup
Mode". Any key can be enrolled without signature checks. However, once a
PK is enrolled, the system switches to "User Mode", and each update must
now be signed according to the hierarchy. Furthermore, when in "User
Mode", the backend initialized the ``os-secure-mode`` device tree flag,
signaling to the kernel that we are in secure mode.

Updates are processed sequentially, in the order that they were provided
in the update queue. If any update fails to validate, appears to be
malformed, or any other error occurs, NO updates will not be applied.
This includes updates that may have successfully applied prior to the
error. The system will continue in an error state, reporting the error
reason via the ``update-status`` device tree property.

P9 Special Case for the Platform Key
------------------------------------

Due to the powerful nature of the platform key and the lack of lockable
flash, the edk2 backend will store the PK in TPM NV rather than PNOR on
P9 systems. (TODO expand on this)

Update Status Return Codes
--------------------------

TODO, edk2 driver needs to actually return these properly first


Device Tree Bindings
--------------------

TODO
