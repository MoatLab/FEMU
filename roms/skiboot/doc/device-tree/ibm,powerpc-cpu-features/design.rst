ibm,powerpc-cpu-features Design
===============================

The OPAL / skiboot code is the canonical location for this specification.  All
definitions of features, constant, bit positions, etc. must be documented here
before being deployed in Linux. This is not presently part of LoPAPR.


Interfaces
----------
This specification describes the ibm,powerpc-cpu-features binding (the formal
definition of binding can be found in binding.txt in this directory).

This specification also involves the Linux ELF AUXV AT_HWCAP and AT_HWCAP2
interfaces for PPC_FEATURE* bits. Allocation of new AT_HWCAP bits should be
done in coordination with OPAL / skiboot, Linux, and glibc projects.

The binding is passed to the hypervisor by firmware. The hypervisor may
build a subset with unsupported/disabled features and hypervisor specifics
removed, and pass that to a guest OS. The OS may advertise features to
userspace.


Background
----------
The cpu-features binding (subsequently "cpu-features") aims to provide an
extensible metadata and protocol between different levels of system software
(firmware, hypervisor, OS/guest, userspace) to advertise the CPU features
available on the system. With each level able to shape the features available
to the next.

The binding specifies features common to all CPUs in the system. Heterogeneous
CPU features are not supported at present (such could be added by providing
additional cpu-features nodes and linking those to particular CPUs with
additional features).

There is no strict definition for what a CPU feature must be, but an
architectural behaviour or performance characteristic (or group of related
behaviours). They must be documented in skiboot/core/cpufeatures.c sufficiently
precisely. More guidelines for feature definitions below.

cpu-features is intended to provide fine grained control of CPU features at
all levels of the stack (firmware, hypervisor, OS, userspace), with the
ability for new CPU features to be used by some components without all
components being upgraded (e.g., a new floating point instruction could be
used by userspace math library without upgrading kernel and hypervisor).


Overview
--------

The cpu-features node is created by firmware and passed to the hypervisor.
The hypervisor may create cpu-features node to be passed to guest, based on
the features that have been enabled, and policy decisions. Hypervisor specific
features, and hypervisor bits and properties should not be advertised to
guests. Guest OS may advertise features to userspace using another method
(e.g., using AUXV vectors, userspace typically does not parse DT).

When the cpu-features node is present, ibm,pa-features and individual feature
properties (e.g., "ibm,vsx"), and cpu-version under the "cpu" compatible nodes
can be ignored by the consumer. For compatibility, the provider must continue
to provide those older properties and the consumer must not assume cpu-features
exists.

When this node exists, software may assume a base feature set which is ISA
v2.07B (BookS) minus the explicit features listed in core/cpufeatures.c
entries in this source tree.

Each feature is advertised as a node underneath the cpu-features node, named
with a human-readable string name that uniquely identifies specification of
that capability.

A feature node has a number of metadata properties describing privilege levels
a feature may be used (HV, OS, PR/user), and information about how it is to
be enabled and advertised to lesser privilege levels. Enabling means to make
it available at a lesser privilege level, (how to enable a given feature
for this privilege level is implicit: if the software know how to use a
feature, it also knows how to enable it).

Feature node properties:

- "isa", the Power ISA version where this feature first became available.
  In case of an implementation specific feature
- "usable-privilege", a bitmask (HV, OS, PR/user) specifying which privilege
  levels this feature may be used in.
- "hv-support", a bitmask. If this exists, the hypervisor must do some work
  to enable support for lesser privilege levels. Bits can be set in this mask
  to specify prescription/recipes to enable the feature without custom code.
  If no bits are set, no recipe exists and custom code must be used. HFSCR
  register enable bit is the only such recipe currently.
- "os-support", similar to hv-support. FSCR recipe.
- Features may have additional properties associated, must be documented with
  the feature.
- Recipes may have additional properties associated. HFSCR recipe has
  hfscr-bit-nr, and FSCR recipe has fscr-bit-nr.
- "dependencies" array of phandles. If this exists, it links to the
  features that must be enabled in order for this feature to be enabled.
- "hwcap-bit-nr" if it exists provides a Linux ELF AUXV HWCAP bit number that
  can be used to advertise this feature to userspace.

Together, these compatibility, support, and dependencies properties allow
unknown features to be enabled and advertised to lesser privilege levels
(when possible).

All bits not defined in usable, support masks must be 0, and should be ignored
by consumers. This allows extensibility to add new privilege levels and new
recipes. Unknown properties should also be ignored. This allows extensibility
for additional methods and metadata for enablement and advertisement.

The policy for selecting and configuring which features to advertise and use
is left for implementations.


Guidelines for defining features
--------------------------------

As a rough guide, features should be based on functional groups of changes
to the ISA, or related performance characteristics.

Grouping should be made by one or a combination of those that:

- Share common enablement requirements (e.g., share particular registers or
  firmware setup requirements).
- Share common usage patterns (e..g, likely to be used together).
- Are implemented with a particular new hardware unit.
- Are optional in the ISA.

Granularity can be debated, but fine grained and encompassing is generally
preferable. For example, memory management unit may be considered fundamental,
but the MMU in POWER9 is very different and in many ways incompatible from
that in POWER8 even in hash mode.

For example, "POWER9" would be too general, but a new feature for every
instruction would be too specific. The "summary of changes" preface in Power
ISA specification is a good starting point to give a guideline for granularity
of the architected features.

New features that offer additional or incompatible functionality beyond
an existing feature may contain an ISA version postfix.

Implementation specific behaviour should contain a CPU type postfix. E.g.,
"machine-check-power9" gives exact MCE properties. If a future CPU has the same
MCE architecture, it should define the same property. If it has a
backward-compatible superset, it could additionally define
"machine-check-newcpu".

Features should be "positive" as much as possible. That is, the presence of
a feature should indicate the presence of an additional CPU feature (e.g., a
new instruction or register). This requires some anticipation and foresight
for defining CPU features. "Negative" features may be unavoidable in some
cases.
