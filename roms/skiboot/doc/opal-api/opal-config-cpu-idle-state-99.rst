.. _OPAL_CONFIG_CPU_IDLE_STATE:

OPAL_CONFIG_CPU_IDLE_STATE
==========================

.. code-block:: c

   #define OPAL_CONFIG_CPU_IDLE_STATE		99

   /*
    * Setup and cleanup method for fast-sleep workarounds
    * state = 1 fast-sleep
    * enter = 1 Enter state
    * exit  = 0 Exit state
    */

   #define OPAL_PM_SLEEP_ENABLED_ER1	0x00080000 /* with workaround */

   int64_t opal_config_cpu_idle_state(uint64_t state, uint64_t enter);

If the `OPAL_PM_SLEEP_ENABLED_ER1` bit is set on a stop state, then this OPAL
call needs to be made upon entry and exit of stop state.
This is currently needed for the `fastsleep_` idle state, present on POWER8
systems.

Returns
-------

:ref:`OPAL_SUCCESS`
     Applied workaround
:ref:`OPAL_PARAMETER`
     Invalid state or enter/exit.
