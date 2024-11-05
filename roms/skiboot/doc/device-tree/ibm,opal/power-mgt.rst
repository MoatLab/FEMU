.. _power-mgt-devtree:

ibm,opal/power-mgt device tree entries
======================================

.. toctree::
   :maxdepth: 2

   power-mgt/occ
   power-mgt/powercap
   power-mgt/psr


All available CPU idle states are listed in ibm,cpu-idle-state-names

For example:

.. code-block:: dts

  power-mgt {
    ibm,cpu-idle-state-names = "nap", "fastsleep_", "winkle";
    ibm,cpu-idle-state-residency-ns = <0x1 0x2 0x3>;
    ibm,cpu-idle-state-latencies-ns = <0x1 0x2 0x3>;
  };

The idle states are characterized by latency and residency
numbers which determine the breakeven point for entry into them. The
latency is a measure of the exit overhead from the idle state and
residency is the minimum amount of time that a CPU must be predicted
to be idle so as to reap the powersavings from entering into that idle
state.

These numbers are made use of by the cpuidle governors in the kernel to
arrive at the appropriate idle state that a CPU must enter into when there is
no work to be done. The values in ibm,cpu-idle-state-latencies-ns are the
the measured latency numbers for the idle states. The residency numbers have
been arrived at experimentally after ensuring that the performance of latency
sensitive workloads do not regress while allowing deeper idle states to be
entered into during low load situations. The kernel is expected to use these
values for optimal power efficiency.

Example:

.. code-block:: dts

   / {
     ibm,opal {
       power-mgt {
		ibm,pstate-frequencies-mhz = <0xda3 0xd82 0xd60 0xd3f 0xd1e 0xcfd 0xcdb 0xcba 0xc99 0xc78 0xc56 0xc35 0xc14 0xbf3 0xbd1 0xbb0 0xb8f 0xb6e 0xb4c 0xb2b 0xb0a 0xae9 0xac7 0xaa6 0xa85 0xa64 0xa42 0xa21 0xa00 0x9df 0x9bd 0x99c 0x97b 0x95a 0x938 0x917 0x8f6 0x8d5 0x8b3 0x892 0x871 0x850 0x82e 0x80d>;
                ibm,cpu-idle-state-latencies-ns = <0xfa0 0x9c40 0x989680>;
                ibm,cpu-idle-state-flags = <0x11000 0x81003 0x47003>;
                ibm,cpu-idle-state-names = "nap", "fastsleep_", "winkle";
                ibm,cpu-idle-state-pmicr = <0x0 0x0 0x20 0x0 0x0 0x0>;
                ibm,pstate-nominal = <0xffffffef>;
                ibm,cpu-idle-state-residency-ns = <0x186a0 0x11e1a300 0x3b9aca00>;
                ibm,cpu-idle-state-pmicr-mask = <0x0 0x0 0x30 0x0 0x0 0x0>;
                phandle = <0x100002a0>;
                ibm,pstate-ids = <0x0 0xffffffff 0xfffffffe 0xfffffffd 0xfffffffc 0xfffffffb 0xfffffffa 0xfffffff9 0xfffffff8 0xfffffff7 0xfffffff6 0xfffffff5 0xfffffff4 0xfffffff3 0xfffffff2 0xfffffff1 0xfffffff0 0xffffffef 0xffffffee 0xffffffed 0xffffffec 0xffffffeb 0xffffffea 0xffffffe9 0xffffffe8 0xffffffe7 0xffffffe6 0xffffffe5 0xffffffe4 0xffffffe3 0xffffffe2 0xffffffe1 0xffffffe0 0xffffffdf 0xffffffde 0xffffffdd 0xffffffdc 0xffffffdb 0xffffffda 0xffffffd9 0xffffffd8 0xffffffd7 0xffffffd6 0xffffffd5>;
                ibm,pstate-max = <0x0>;
                ibm,pstate-min = <0xffffffd5>;
       };
     };
   };



ibm,cpu-idle-state-pmicr ibm,cpu-idle-state-pmicr-mask
------------------------------------------------------
In POWER8, idle states sleep and winkle have 2 modes- fast and deep. In fast
mode, idle state puts the core into threshold voltage whereas deep mode
completely turns off the core. Choosing fast vs deep mode for an idle state
can be done either via PM_GP1 scom or by writing to PMICR special register.
If using the PMICR path to choose fast/deep mode then ibm,cpu-idle-state-pmicr
and ibm,cpu-idle-state-pmicr-mask properties expose relevant PMICR bits and
values for corresponding idle states.


ibm,cpu-idle-state-psscr ibm,cpu-idle-state-psscr-mask
------------------------------------------------------
In POWER ISA v3, there is a common instruction 'stop' to enter any idle state
and SPR PSSCR is used to specify which idle state needs to be entered upon
executing stop instruction. Properties ibm,cpu-idle-state-psscr and
ibm,cpu-idle-state-psscr-mask expose the relevant PSSCR bits and values for
corresponding idle states.


ibm,cpu-idle-state-flags
------------------------
These flags are used to describe the characteristics of the idle states like
the kind of core state loss caused. These flags are used by the kernel to
save/restore appropriate context while using the idle states.


ibm,pstate-ids
--------------

This property lists the available pstate identifiers, as signed 32-bit
big-endian values. While the identifiers are somewhat arbitrary, these define
the order of the pstates in other ibm,pstate-* properties.


ibm,pstate-frequencies-mhz
--------------------------

This property lists the frequency, in MHz, of each of the pstates listed in the
ibm,pstate-ids file. Each frequency is a 32-bit big-endian word.


ibm,pstate-max ibm,pstate-min ibm,pstate-nominal
------------------------------------------------

These properties give the maximum, minimum and nominal pstate values, as an id
specified in the ibm,pstate-ids file.

ibm,pstate-ultra-turbo ibm,pstate-turbo
---------------------------------------

These properties are added when ultra-turbo(WOF) is enabled. These properties
give the max turbo and max ultra-turbo pstate-id as specified in the
ibm,pstate-ids file. The frequencies present in turbo to ultra-turbo range are
referred to as boost/WOF frequencies and these are attained by the CPU under
favourable environmental conditions, low workloads and low active core counts.

Example:

.. code-block:: dts

  power-mgt {
        ibm,pstate-core-max = <0x0 0x0 0x0 0x0 0x0 0x0 0x0>;
        ibm,pstate-turbo = <0xfffffffb>
        ibm,pstate-ultra-turbo = <0x0>;
  };

ibm,pstate-core-max
-------------------

This property is added when ultra_turbo(WOF) is enabled. This property gives
the list of max pstate for each 'n' number of active cores in the chip.

ibm,pstate-base
----------------

This pstate points to the base frequency of the chip. POWER9 base frequency is
the highest frequency that is guaranteed when ALL cores are active in ANY
operating condition (ie. workloads, environmental conditions such as max
ambient temperature, active core counts)
