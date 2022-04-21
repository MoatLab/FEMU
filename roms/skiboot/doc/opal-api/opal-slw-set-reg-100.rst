.. _OPAL_SLW_SET_REG:

OPAL_SLW_SET_REG
================

.. code-block:: c

   #define OPAL_SLW_SET_REG			100

   int64_t opal_slw_set_reg(uint64_t cpu_pir, uint64_t sprn, uint64_t val);

:ref:`OPAL_SLW_SET_REG` is used to inform low-level firmware to restore a
given value of SPR when there is a state loss.  The actual set of SPRs
that are supported is platform dependent.

In Power 8, it uses p8_pore_gen_cpufreq_fixed(), api provided by pore engine,
to inform the spr with their corresponding values with which they
must be restored.

In Power 9, it uses p9_stop_save_cpureg(), api provided by self restore code,
to inform the spr with their corresponding values with which they
must be restored.


Parameters
----------

``uint64_t cpu_pir``
  This parameter specifies the pir of the cpu for which the call is being made.
``uint64_t sprn``
  This parameter specifies the spr number as mentioned in p9_stop_api.H for
  Power9 and p8_pore_table_gen_api.H for Power8.
``uint64_t val``
  This parameter specifices value with which the spr should be restored.

Returns
-------

:ref:`OPAL_INTERNAL_ERROR`
  On failure. The actual error code from the platform specific code is logged in the OPAL logs
:ref:`OPAL_UNSUPPORTED`
  If spr restore is not supported by pore engine.
:ref:`OPAL_SUCCESS`
  On success
