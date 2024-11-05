PCI Slots
=========

The PCI slots are instantiated to represent their associated properties and
operations. The slot properties are exported to OS through the device tree
node of the corresponding parent PCI device. The slot operations are used
to accomodate requests from OS regarding the indicated PCI slot:

   * PCI slot reset
   * PCI slot property retrival

The PCI slots are expected to be created by individual platforms based on
the given templates, which are classified to PHB slot or normal one currently.
The PHB slot is instantiated based on PHB types like P7IOC and PHB3. However,
the normal PCI slots are created based on general RC (Root Complex), PCIE switch
ports, PCIE-to-PCIx bridge. Individual platform may create PCI slot, which doesn't
have existing template.

The PCI slots are created at different stages according to their types. PHB slots
are expected to be created once the PHB is register (struct platform::pci_setup_phb())
because the PHB slot reset operations are required at early stage of PCI enumeration.
The normal slots are populated after their parent PCI devices are instantiated at
struct platform::pci_get_slot_info().

The operation set supplied by the template might be overrided and reimplemented, or
partially. It's usually done according to the VPD figured out by individual platforms.

PCI Slot Operations
-------------------

The following operations are supported to one particular PCI slot. More details
could be found from the definition of struct pci_slot_ops:

===================== ==========
Operation             Definition
===================== ==========
get_presence_state    Check if any adapter connected to slot
get_link_state        Retrieve PCIE link status: up, down, link width
get_power_state       Retrieve the power status: on, off
get_attention_state   Retrieve attention status: on, off, blinking
get_latch_state       Retrieve latch status
set_power_state       Configure the power status: on, off
set_attention_state   Configure attention status: on, off, blinking

prepare_link_change   Prepare PCIE link status change
poll_link             Poll PCIE link until it's up or down permanently
creset                Complete reset, only available to PHB slot
freset                Fundamental reset
hreset                Hot reset
poll                  Interface for OPAL API to drive internal state machine

add_properties        Additional PCI slot properties seen by platform
===================== ==========

PCI Slot Properties
===================

The following PCI slot properties have been exported through PCI device tree
node for a root port, a PCIE switch port, or a PCIE to PCIx bridge. If the
individual platforms (e.g. Firenze and Apollo) have VPD for the PCI slot, they
should extract the PCI slot properties from VPD and export them accordingly.

=========================== ==========
Property                    Definition
=========================== ==========
ibm,reset-by-firmware       Boolean indicating whether the slot reset should be done in firmware
ibm,slot-pluggable          Boolean indicating whether the slot is pluggable
ibm,slot-surprise-pluggable Boolean indicating whether the slot supports surprise hotplug
ibm,slot-broken-pdc         Boolean indicating whether PDC (Presence Detection Change) is broken
ibm,slot-power-ctl          Boolean indicating whether the slot has power control
ibm,slot-wired-lanes        The number of hardware lanes that are wired
ibm,slot-pwr-led-ctl        Presence of slot power led, and controlling entity
ibm,slot-attn-led-ctl       Presence of slot ATTN led, and controlling entity
=========================== ==========

PCI Hotplug
-----------

The implementation of PCI slot hotplug heavily relies on its power state.
Initially, the slot is powered off if there are no adapters behind it.
Otherwise, the slot should be powered on.

In hot add scenario, the adapter is physically inserted to PCI slot. Then
the PCI slot is powered on by OPAL API opal_pci_set_power_state(). The
power is supplied to the PCI slot, the adapter behind the PCI slot is
probed and the device sub-tree (for hot added devices) is populated. A
OPAL message is sent to OS on completion. The OS needs retrieve the device
sub-tree through OPAL API opal_get_device_tree(), unflatten it and populate
the device sub-tree. After that, the adapter behind the PCI slot should
be probed and added to the system.

On the other hand, the OS removes the adapter behind the PCI slot before
calling opal_pci_set_power_state(). Skiboot cuts off the power supply to
the PCI slot, removes the adapter behind the PCI slot and the corresponding
device sub-tree. A OPAL message (OPAL_MSG_ASYNC_COMP) is sent to OS. The
OS removes the device sub-tree for the adapter behind the PCI slot.

The OPAL message used in PCI hotplug is comprised of 4 dwords in sequence:
asychronous token from OS, PCI slot device node's phandle, OPAL_PCI_SLOT_POWER_{ON,
OFF}, OPAL_SUCCESS or errcode.

The states OPAL_PCI_SLOT_OFFLINE and OPAL_PCI_SLOT_ONLINE are used for removing
or adding devices behind the slot. The device nodes in the device tree are
removed or added accordingly, without actually changing the slot's power state.
The API call will return OPAL_SUCCESS immediately and no further asynchronous
message will be sent.

PCI Slot on Apollo and Firenze
------------------------------

On IBM's Apollo and Firenze platform, the PCI VPD is fetched from dedicated LID,
which is organized in so-called 1004, 1005, or 1006 format. 1006 mapping format
isn't supported currently. The PCI slot properties are figured out from the VPD.
On the other hand, there might have external power management entity hooked to
I2C buses for one PCI slot. The fundamental reset operation of the PCI slot should
be implemented based on the external power management entity for that case.

On Firenze platform, PERST pin is accessible through bit#10 of PCI config register
(offset: 0x80) for those PCI slots behind some PLX switch downstream ports. For
those PCI slots, PERST pin is utilized to implement fundamental reset if external
power management entity doesn't exist.

For Apollo and Firenze platform, following PCI slot properties are exported through
PCI device tree node except those generic properties (as above):

======================= ==========
Property                Definition
======================= ==========
ibm,slot-location-code  System location code string for the slot connector
ibm,slot-label          Slot label, part of "ibm,slot-location-code"
======================= ==========
