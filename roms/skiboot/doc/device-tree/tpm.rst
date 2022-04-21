.. _device-tree/tpm:

Trusted Platform Module (TPM)
=============================

The tpm node describes a TPM device present in the platform. It also includes
event log information.

Required properties
-------------------

All these properties are consumed by skiboot and the linux kernel (tpm and
vtpm codes)

::

    compatible :       should have "nuvoton,npct650"

    linux,sml-base:    64-bit base address of the reserved memory allocated for firmware event log.
                       sml stands for shared memory log.

    linux,sml-size:    size of the memory allocated for firmware event log.


Optional properties
-------------------

::

    status:            indicates whether the device is enabled or disabled. "okay" for
                       enabled and "disabled" for disabled.

Example
-------

.. code-block:: dts

    tpm@57 {
    	reg = <0x57>;
    	compatible = "nuvoton,npct650", "nuvoton,npct601";
    	linux,sml-base = <0x7f 0xfd450000>;
    	linux,sml-size = <0x10000>;
    	status = "okay";
    	phandle = <0x10000017>;
    	linux,phandle = <0x10000017>;
    };

