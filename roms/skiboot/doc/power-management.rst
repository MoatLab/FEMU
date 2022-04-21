Power Management
================

See :ref:`power-mgt-devtree` for device tree structure describing power management facilities.

Debugging
---------

There exist a few debug knobs that can be set via nvram settings. These are
**not** ABI and may be changed or removed at *any* time.

Disabling specific stop states
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
On boot, specific stop states can be disabled via setting a mask. For example,
to disable all but stop 0,1,2, use ~0xE0000000. ::

  nvram -p ibm,skiboot --update-config opal-stop-state-disable-mask=0x1FFFFFFF
