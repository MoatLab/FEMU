.. _device-tree/ibm,opal/sysparams:

sysparams
=========

.. code-block:: c

   /* System parameter permission */
   enum OpalSysparamPerm {
	OPAL_SYSPARAM_READ  = 0x1,
	OPAL_SYSPARAM_WRITE = 0x2,
	OPAL_SYSPARAM_RW    = (OPAL_SYSPARAM_READ | OPAL_SYSPARAM_WRITE),
   };


.. code-block:: dts

   sysparams {
		compatible = "ibm,opal-sysparams";
                param-id = <0xf0000001 0xf0000003 0xf0000012 0xf0000016 0xf000001d 0xf0000023 0xf0000024 0xf0000025 0xf0000026 0xf0000027>;
                param-name = "surveillance", "hmc-management", "cupd-policy", "plat-hmc-managed", "fw-license-policy", "world-wide-port-num", "default-boot-device", "next-boot-device", "console-select", "boot-device-path";
                param-perm = [03 01 03 03 03 02 03 03 03 03];
                phandle = <0x10000032>;
                param-len = <0x4 0x4 0x4 0x4 0x4 0xc 0x1 0x1 0x1 0x30>;
                linux,phandle = <0x10000032>;
   };

Device tree node for system parameters accessible through the
:ref:`opal-sysparams` calls :ref:`OPAL_GET_PARAM` and :ref:`OPAL_SET_PARAM`.

While many systems and platforms will support parameters and configuration via
either nvram or over IPMI, some platforms may have parameters that need to be
set a different way.

Some parameters may be set Read Only, so the `param-perm` property indicates
permissions.

Currently, this is only something that exists on FSP based systems.
