.. _stb-overview:

Secure and Trusted Boot Library (LibSTB) Documentation
======================================================

*LibSTB* provides APIs to support Secure Boot and Trusted Boot in skiboot.

``Secure Boot: verify and enforce.``
        When the system is booting in secure mode, Secure Boot MUST ensure that
        only trusted code is executed during system boot by verifying if the
        code is signed with trusted keys and halting the system boot if the
        verification fails.

``Trusted Boot: measure and record.``
        When the system is booting in trusted mode, Trusted Boot MUST create
        artifacts during system boot to prove that a particular chain of events
        have happened during boot. Interested parties can subsequently assess
        the artifacts to check whether or not only trusted events happened and
        then make security decisions. These artifacts comprise a log of
        measurements and the digests extended into the TPM PCRs. Platform
        Configuration Registers (PCRs) are registers in the Trusted Platform
        Module (TPM) that are shielded from direct access by the CPU.

In order to support Secure and Trusted Boot, the flash driver calls libSTB to
verify and measure the code it fetches from PNOR.

LibSTB is initialized by calling *secureboot_init()*, see ``libstb/secureboot.h``.

Secure Boot
-----------

``Requirements:``
        #. CVC-verify service to verify signed firmware code.

Secure boot is initialized by calling *secureboot_init()* and its API is quite
simple, see ``libstb/secureboot.h``.

The flash driver calls ``secureboot_verify()`` to verify if the fetched firmware
blob is properly signed with keys trusted by the platform owner. This
verification is performed only when the system is booting in secure mode. If
the verification fails, it enforces a halt of the system boot.

The verification itself is performed by the :ref:`container-verification-code`,
precisely the *CVC-verify* service, which requires both the fetched code and the
hardware key hash trusted by the platform owner.

The secure mode status, hardware key hash and hardware key hash size
information is found in the device tree, see
:ref:`doc/device-tree/ibm,secureboot.rst <device-tree/ibm,secureboot>`.

.. _signing-firmware-code:

Signing Firmware Code
^^^^^^^^^^^^^^^^^^^^^

Fimware code is signed using the ``sb-signing-utils`` utilities by running it
standalone or just calling op-build. The latter will automatically sign the
various firmware components that comprise the PNOR image if SECUREBOOT is
enabled for the platform.

The signing utilities also allow signing firmware code using published hardware
keys (a.k.a. imprint keys, only for development) or production hardware keys,
see `sb-signing-utils`_.

The hardware keys are the root keys. The signing tool uses three hardware keys
to sign up to three firmware keys, which are then used to sign the firmware
code. The resulting signed firmware code is then assembled following the secure
boot container format. All the information required to verify the signatures is
placed in the first 4K reserved for the container header (e.g.  public keys,
hashes and signatures). The firmware code itself is placed in the container
payload.

.. _sb-signing-utils: https://github.com/open-power/sb-signing-utils

.. _container-verification-code:

Container Verification Code
---------------------------

The *Container Verification Code* (a.k.a. ROM code) is stored in a secure
memory region and it provides basic Secure and Trusted Boot services for the
entire firmware stack. See `doc/device-tree/ibm,secureboot.rst
<device-tree/ibm,secureboot>` and `doc/device-tree/ibm,cvc.rst
<device-tree/ibm,cvc>`.

LibSTB uses function wrappers to call into each CVC service, see
``libstb/cvc.h``.

CVC-verify Service
^^^^^^^^^^^^^^^^^^

.. code-block:: c

        int call_cvc_verify(void *buf, size_t size, const void *hw_key_hash,
                            size_t hw_key_hash_size, __be64 *log)

This function wrapper calls into the *CVC-verify*, which verifies if the
firmware code provided in ``@buf`` is properly signed with the keys trusted by
the platform owner. Its parameters are documented in ``libstb/cvc.h``.

``@hw_key_hash`` is used to check if the firware keys used to sign
the firmware blob can be trusted.

``@log`` is optional. If the verification fails, the caller can interpret
it to find out what checks has failed.

Enforcement is caller's responsibility.

CVC-sha512 Service
^^^^^^^^^^^^^^^^^^

.. code-block:: c

        int call_cvc_sha512(const uint8_t *data, size_t data_len, uint8_t *digest,
                            size_t digest_size)

This function wrapper calls into the *CVC-sha512*, which calculates the
sha512 hash of what is provided in @data. Its parameters are documented in
``libstb/cvc.h``.

Trusted Boot
------------

``Requirements:``
        #. TPM device and TPM driver. See devices supported in
           :ref:`doc/device-tree/tpm.rst <device-tree/tpm>`.
        #. TCG Software Stack (TSS) to send commands to the TPM device.
        #. Firmware Event Log driver to add new events to the log. Event log
           address and size information is found in the device tree, see
           :ref:`doc/device-tree/tpm.rst <device-tree/tpm>`.
        #. CVC-sha512 service to calculate the sha512 hash of the data that
           will be measured.

The Trusted Boot API is quite simple, see ``libstb/trustedboot.h``.

The flash driver calls ``trustedboot_measure()`` to measure the firmware code
fetched from PNOR and also record its measurement in two places. This is
performed only when the system is booting in trusted mode (information found in
the device tree, see :ref:`doc/device-tree/ibm,secureboot.rst <device-tree/ibm,secureboot>`).

Once the firmware code is measured by calling the *CVC-sha512* service, its
measurement is first recorded in a TPM PCR statically defined for each event.
In order to record it, the skiboot TCG Software Stack (TSS) API is called to
extend the measurement into the PCR number of both the sha1 and sha256 banks.
The skiboot TSS is a light TSS implementation and its source code is shared
between hostboot and skiboot, see ``libstb/tss/trustedbootCmds.H``.

PCR extend is an TPM operation that uses a hash function to combine a new
measurement with the existing digest saved in the PCR. Basically, it
concatenates the existing PCR value with the received measurement, and then
records the hash of this new string in the PCR.

The measurement is also recorded in the event log. The ``TpmLogMgr_addEvent()``
function is called to add the measurement to the log, see
``libstb/tss/tpmLogMgr.H``.

When the system boot is complete, each non-zero PCR value represents one or more
events measured during the boot in chronological order. Interested parties
can make inferences about the system's state by using an attestation tool to
remotely compare the PCR values of a TPM against known good values, and also
identify unexpected events by replaying the Event Log against known good Event
Log entries.
