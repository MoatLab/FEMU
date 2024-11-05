====================================
Starting and stopping secondary CPUs
====================================

In this context, each thread is a CPU. That is, you start and stop threads of
CPUs.

.. _OPAL_START_CPU:

OPAL_START_CPU
==============

.. code-block:: c

   #define OPAL_START_CPU				41

   int64_t opal_start_cpu_thread(uint64_t server_no, uint64_t start_address);

Returns
-------

:ref:`OPAL_SUCCESS`
     The CPU was instructed to start executing instructions from the specified
     `start_address`.
     This is an *asynchronous* operation, so it may take a short period of
     time before the CPU actually starts at that address.
:ref:`OPAL_PARAMETER`
     Invalid CPU.
:ref:`OPAL_WRONG_STATE`
     If the CPU thread is not in OPAL, or is being re-initialized through :ref:`OPAL_REINIT_CPUS`
:ref:`OPAL_INTERNAL_ERROR`
     Something else went horribly wrong.

.. _OPAL_RETURN_CPU:

OPAL_RETURN_CPU
===============

.. code-block:: c

   #define OPAL_RETURN_CPU				69

   int64_t opal_return_cpu(void);

When OPAL first starts the host, all secondary CPUs are spinning in OPAL.
To start them, one must call OPAL_START_CPU (you may want to OPAL_REINIT_CPUS
to set the HILE bit first).

In cases where you need OPAL to do something for you across all CPUs, such
as OPAL_REINIT_CPUS, (on some platforms) a firmware update or get the machine
back into a similar state as to when the host OS was started (e.g. for kexec)
you may also need to return control of the CPU to OPAL.


Returns
-------
This call does **not return**. You need to OPAL_START_CPU.
