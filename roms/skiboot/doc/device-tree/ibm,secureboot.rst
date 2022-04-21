.. _device-tree/ibm,secureboot:

ibm,secureboot
==============

The ``ìbm,secureboot`` node provides secure boot and trusted boot information
up to the target OS. Further information can be found in :ref:`stb-overview`.

Required properties
-------------------

.. code-block:: none

    compatible:         Either one of the following values:

                        ibm,secureboot-v1  :  The container-verification-code
                                              is stored in a secure ROM memory.

                        ibm,secureboot-v2  :  The container-verification-code
                                              is stored in a reserved memory.
                                              It described by the ibm,cvc child
                                              node.

    secure-enabled:     this property exists when the firmware stack is booting
                        in secure mode (hardware secure boot jumper asserted).

    trusted-enabled:    this property exists when the firmware stack is booting
                        in trusted mode.

    hw-key-hash:        hash of the three hardware public keys trusted by the
                        platformw owner. This is used to verify if a firmware
                        code is signed with trusted keys.

    hw-key-hash-size:   hw-key-hash size

    os-secureboot-enforcing:
                        this property is created by the secure variable backend
                        if it detects a desire by the owner to requre any
                        images (e.g. kernels) to be signed by an appropriate
                        key stored in secure variables.

    physical-presence-asserted:
                        this property exists to indicate the physical presence
                        of user to request key clearance.

    clear-os-keys:      this property exists when the firmware indicates that
                        physical presence is asserted to clear only Host OS
                        secure boot keys.

    clear-all-keys:     this property exists when the firmware indicates that
                        physical presence is asserted to clear all sensistive
                        data controlled by platform firmware.

    clear-mfg-keys:     this property exists only during manufacturing process
                        when the firmware indicates to clear all senstive data
                        during manufacturing. It is only valid on development
                        drivers.

Obsolete properties
-------------------

.. code-block:: none

    hash-algo:          Superseded by the hw-key-hash-size property in
                        'ibm,secureboot-v2'.

Example
-------

.. code-block:: dts

    ibm,secureboot {
        compatible = "ibm,secureboot-v2";
        secure-enabled;
        trusted-enabled;
        hw-key-hash-size = <0x40>;
        hw-key-hash = <0x40d487ff 0x7380ed6a 0xd54775d5 0x795fea0d 0xe2f541fe
                       0xa9db06b8 0x466a42a3 0x20e65f75 0xb4866546 0x0017d907
                       0x515dc2a5 0xf9fc5095 0x4d6ee0c9 0xb67d219d 0xfb708535
                       0x1d01d6d1>;
        phandle = <0x100000fd>;
        linux,phandle = <0x100000fd>;
    };
