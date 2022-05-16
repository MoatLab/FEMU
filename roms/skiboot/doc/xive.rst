P9 XIVE Exploitation
====================

.. _xive-device-tree:

I - Device-tree updates
-----------------------

 1) The existing OPAL ``/interrupt-controller@0`` node remains

    This node represents both the emulated XICS source controller and
    an abstraction of the virtualization engine. This represents the
    fact thet OPAL set_xive/get_xive functions are still supported
    though they don't provide access to the full functionality.

    It is still the parent of all interrupts in the device-tree.

    New or modified properties:

    - ``compatible`` : This is extended with a new value ``ibm,opal-xive-vc``


 2) The new ``/interrupt-controller@<addr>`` node

    This node represents both the emulated XICS presentation controller
    and the new XIVE presentation layer.

    Unlike the traditional XICS, there is only one such node for the whole
    system.

    New or modified properties:

    - ``compatible`` : This contains at least the following strings:

      - ``ibm,opal-intc`` : This represents the emulated XICS presentation
        facility and might be the only property present if the version of
        OPAL doesn't support XIVE exploitation.
      - ``ibm,opal-xive-pe`` : This represents the XIVE presentation
        engine.

    - ``ibm,xive-eq-sizes`` : One cell per size supported, contains log2
      of size, in ascending order.

    - ``ibm,xive-#priorities`` : One cell, the number of supported priorities
      (the priorities will be 0...n)

    - ``ibm,xive-provision-page-size`` : Page size (in bytes) of the pages to
      pass to OPAL for provisioning internal structures
      (see opal_xive_donate_page). If this is absent, OPAL will never require
      additional provisioning. The page must be naturally aligned.

    - ``ibm,xive-provision-chips`` : The list of chip IDs for which provisioning
      is required. Typically, if a VP allocation return OPAL_XIVE_PROVISIONING,
      opal_xive_donate_page() will need to be called to donate a page to
      *each* of these chips before trying again.

    - ``reg`` property contains the addresses & sizes for the register
      ranges corresponding respectively to the 4 rings:

      - Ultravisor level
      - Hypervisor level
      - Guest OS level
      - User level

      For any of these, a size of 0 means this level is not supported.

    - ``single-escalation-support`` (option). When present, indicatges that
      the "single escalation" feature is supported, thus enabling the use
      of the OPAL_XIVE_VP_SINGLE_ESCALATION flag.

3) Interrupt descriptors

    The interrupt descriptors (aka "interrupts" properties and parts
    of "interrupt-map" properties) remain 2 cells. The first cell is
    a global interrupt number which represents a unique interrupt
    source in the system and is an abstraction provided by OPAL.

    The default configuration for all sources in the IVT/EAS is to
    issue that number (it's internally a combination of the source
    chip and per-chip interrupt number but the details of that
    combination are not exposed and subject to change).

    The second cell remains as usual "0" for an edge interrupt and
    "1" for a level interrupts.

 4) IPIs

    Each ``cpu`` node now contains an ``interrupts`` property which has
    one entry (2 cells per entry) for each thread on that core
    containing the interrupt number for the IPI targeted at that
    thread.

 5) Interrupt targets

    Targetting of interrupts uses processor targets and priority
    numbers. The processor target encoding depends on which API is
    used:

     - The legacy opal_set/get_xive() APIs only support the old
       "mangled" (ie. shifted by 2) HW processor numbers.

     - The new opal_xive_set/get_irq_config API (and other
       exploitation mode APIs) use a "token" VP number which is
       described in II-2. Unmodified HW processor numbers are valid
       VP numbers for those APIs.

II - General operations
-----------------------

Most configuration operations are abstracted via OPAL calls, there is
no direct access or exposure of such things as real HW interrupt or VP
numbers.

OPAL sets up all the physical interrupts and assigns them numbers, it
also allocates enough virtual interrupts to provide an IPI per physical
thread in the system.

All interrupts are pre-configured masked and must be set to an explicit
target before first use. The default interrupt number is programmed
in the EAS and will remain unchanged if the targetting/unmasking is
done using the legacy set_xive() interface.

An interrupt "target" is a combination of a target processor number
and a priority.

Processor numbers are in a single domain that represents both the
physical processors and any virtual processor or group allocated
using the interfaces defined in this specification. These numbers
are an OPAL maintained abstraction and are only partially related
to the real VP numbers:

In order to maintain the grouping ability, when VPs are allocated
in blocks of naturally aligned powers of 2, the underlying HW
numbers will respect this alignment.

  .. note:: The block group mode extension makes the numbering scheme
   	    a bit more tricky than simple powers of two however, see below.


1) Interrupt numbering and allocation

   As specified in the device-tree definition, interrupt numbers
   are abstracted by OPAL to be a 30-bit number. All HW interrupts
   are "allocated" and configured at boot time along with enough
   IPIs for all processor threads.

   Additionally, in order to be compatible with the XICS emulation,
   all interrupt numbers present in the device-tree (ie all physical
   sources or pre-allocated IPIs) will fit within a 24-bit number
   space.

   Interrupt sources that are only usable in exploitation mode, such
   as escalation interrupts, can have numbers covering the full 30-bit
   range. The same is true of interrupts allocated dynamically.

   The hypervisor can allocate additional blocks of interrupts,
   in which case OPAL will return the resulting abstracted global
   numbers. They will have to be individually configured to map
   to a given number at the target and be routed to a given target
   and priority using opal_xive_set_irq_config(). This call is
   semantically equivalent to the old opal_set_xive() which is
   still supported with the addition that opal_xive_set_irq_config()
   can also specify the logical interrupt number.

2) VP numbering and allocation

   A VP number is a 64-bit number. The internal make-up of that number
   is opaque to the OS. However, it is a discrete integer that will
   be a naturally aligned power of two when allocating a chunk of
   VPs representing the "base" number of that chunk, the OS will do
   basic arithmetic to get to all the VPs in the range.

   Groups, when supported, will also be numbers in that space.

   The physical processors numbering uses the same number space.

   The underlying HW VP numbering is hidden from the OS, the APIs
   uses the system processor numbers as presented in the
   ``ibm,ppc-interrupt-server#s`` which corresponds to the PIR register
   content to represent physical processors within the same number
   space as dynamically allocated VPs.

   .. note:: Note about block group mode:

	     The block group mode shall as much as possible be handled
	     transparently by OPAL.

	     For example, on a 2-chips machine, a request to allocate
	     2^n VPs might result in an allocation of 2^(n-1) VPs per
	     chip allocated accross 2 chips. The resulting VP numbers
	     will encode the order of the allocation allowing OPAL to
	     reconstitute which bits are the block ID bits and which bits
	     are the index bits in a way transparent to the OS. The overall
	     range of numbers passed to Linux will still be contiguous.

	     That implies however a limitation: We can only allocate within
	     power-of-two number of blocks. Thus the VP allocator will limit
	     itself to the largest power of two that can fit in the number
	     of available chips in the machine: A machine with 3 good chips
	     will only be able to allocate VPs from 2 of them.

3) Group numbering and allocation

   The group numbers are in the *same* number space as the VP
   numbers. OPAL will internally use some bits of the VP number
   to encode the group geometry.

   [TBD] OPAL may or may not allocate a default group of all physical
   processors, per-chip groups or per-core groups. This will be
   represented in the device-tree somewhat...

   [TBD] OPAL will provide interfaces for allocating groups


   .. note:: Note about P/Q bit operation on sources:

	     opal_xive_get_irq_info() returns a certain number of flags
	     which define the type of operation supported. The following
	     rules apply based on what those flags say:

             - The Q bit isn't functional on an LSI interrupt. There is no
               garantee that the special combination "01" will work for an
               LSI (and in fact it will not work on the PHB LSIs). However
               just setting P to 1 is sufficient to mask an LSI (just don't
               EOI it while masked).

             - The recommended setting for a masked interrupt that is
	       temporarily masked by a driver is "10". This means a new
	       occurrence while masked will be recorded and a "StoreEOI"
	       will replay it appropriately.


III - Event queues
------------------

Each virtual processor or group has a certain number of event queues
associated with it. Each correspond to a given priority. The number
of supported priorities is provided in the device-tree
(``ibm,xive-#priorities`` property of the xive node).

By default, OPAL populates at least one queue for every physical thread
in the system. The number of queues and the size used is implementation
specific. If the OS wants to re-use these to save memory, it can query
the VP configuration.

The opal_xive_get_queue_info() and opal_xive_set_queue_info() can be used
to query a queue configuration (ie, to obtain the current page and size
for the queue itself, but also to collect some configuration flags for
that queue such as whether it coalesces notifications etc...) and to
obtain the MMIO address of the queue EOI page (in the case where
coalescing is enabled).

IV - OPAL APIs
--------------

.. warning:: *All* the calls listed below may return OPAL_BUSY unless
             explicitely documented not to. In that case, the call
             should be performed again. The OS is allowed to insert a
             delay though no minimum nor maxmimum delay is specified.
             This will typically happen when performing cache update
             operations in the XIVE, if they result in a collision.

.. warning:: Calls that are expected to be called at runtime
             simultaneously without conflicts such as getting/setting
             IRQ info or queue info are fine to do so concurrently.

             However, there is no internal locking to prevent races
             between things such as freeing a VP block and getting/setting
             queue infos on that block.

             These aren't fully specified (yet) but common sense shall
             apply.

.. _OPAL_XIVE_RESET:

OPAL_XIVE_RESET
^^^^^^^^^^^^^^^
.. code-block:: c

   int64_t opal_xive_reset(uint64_t version)

The OS should call this once when starting up to re-initialize the
XIVE hardware and the OPAL XIVE related state back to all defaults.

It can call it a second time before handing over to another (ie.
kexec) to re-enable XICS emulation.

The "version" argument should be set to 1 to enable the XIVE
exploitation mode APIs or 0 to switch back to the default XICS
emulation mode.

Future versions of OPAL might allow higher versions than 1 to
represent newer versions of this API. OPAL will return an error
if it doesn't recognize the requested version.

Any page of memory that the OS has "donated" to OPAL, either backing
store for EQDs or VPDs or actual queue buffers will be removed from
the various HW maps and can be re-used by the OS or freed after this
call regardless of the version information. The HW will be reset to
a (mostly) clean state.

It is the responsibility of the caller to ensure that no other
XIVE or XICS emulation call happens simultaneously to this. This
basically should happen on an otherwise quiescent system. In the
case of kexec, it is recommended that all processors CPPR is lowered
first.

.. note:: This call always executes fully synchronously, never returns
	  OPAL_BUSY and will work regardless of whether VPs and EQs are left
	  enabled or disabled. It *will* spend a significant amount of time
	  inside OPAL and as such is not suitable to be performed during normal
	  runtime.

.. _OPAL_XIVE_GET_IRQ_INFO:

OPAL_XIVE_GET_IRQ_INFO
^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

   int64_t opal_xive_get_irq_info(uint32_t girq,
                                  uint64_t *out_flags,
                                  uint64_t *out_eoi_page,
                                  uint64_t *out_trig_page,
				  uint32_t *out_esb_shift,
                                  uint32_t *out_src_chip);

Returns info about an interrupt source. This call never returns
OPAL_BUSY.

* out_flags returns a set of flags. The following flags
  are defined in the API (some bits are reserved, so any bit
  not defined here should be ignored):

  - OPAL_XIVE_IRQ_TRIGGER_PAGE

    Indicate that the trigger page is a separate page. If that
    bit is clear, there is either no trigger page or the trigger
    can be done in the same page as the EOI, see below.

  - OPAL_XIVE_IRQ_STORE_EOI

    Indicates that the interrupt supports the "Store EOI" option,
    ie a store to the EOI page will move Q into P and retrigger
    if the resulting P bit is 1. If this flag is 0, then a store
    to the EOI page will do a trigger if OPAL_XIVE_IRQ_TRIGGER_PAGE
    is also 0.

  - OPAL_XIVE_IRQ_LSI

    Indicates that the source is a level sensitive source and thus
    doesn't have a functional Q bit. The Q bit may or may not be
    implemented in HW but SW shouldn't rely on it doing anything.

  - OPAL_XIVE_IRQ_SHIFT_BUG

    Indicates that the source has a HW bug that shifts the bits
    of the "offset" inside the EOI page left by 4 bits. So when
    this is set, us 0xc000, 0xd000... instead of 0xc00, 0xd00...
    as offets in the EOI page.

  - OPAL_XIVE_IRQ_MASK_VIA_FW

    Indicates that a FW call is needed (either opal_set_xive()
    or opal_xive_set_irq_config()) to succesfully mask and unmask
    the interrupt. The operations via the ESB page aren't fully
    functional.

  - OPAL_XIVE_IRQ_EOI_VIA_FW

    Indicates that a FW call to opal_xive_eoi() is needed to
    successfully EOI the interrupt. The operation via the ESB page
    isn't fully functional.

    * out_eoi_page and out_trig_page outputs will be set to the
      EOI page physical address (always) and the trigger page address
      (if it exists).
      The trigger page may exist even if OPAL_XIVE_IRQ_TRIGGER_PAGE
      is not set. In that case out_trig_page is equal to out_eoi_page.
      If the trigger page doesn't exist, out_trig_page is set to 0.

    * out_esb_shift contains the size (as an order, ie 2^n) of the
      EOI and trigger pages. Current supported values are 12 (4k)
      and 16 (64k). Those cannot be configured by the OS and are set
      by firmware but can be different for different interrupt sources.

    * out_src_chip will be set to the chip ID of the HW entity this
      interrupt is sourced from. It's meant to be informative only
      and thus isn't guaranteed to be 100% accurate. The idea is for
      the OS to use that to pick up a default target processor on
      the same chip.

.. _OPAL_XIVE_EOI:

OPAL_XIVE_EOI
^^^^^^^^^^^^^

.. code-block:: c

   int64_t opal_xive_eoi(uint32_t girq);

Performs an EOI on the interrupt. This should only be called if
OPAL_XIVE_IRQ_EOI_VIA_FW is set as otherwise direct ESB access
is preferred.

.. note:: This is the *same* opal_xive_eoi() call used by OPAL XICS
	  emulation. However the XIRR parameter is re-purposed as "GIRQ".

	  The call will perform the appropriate function depending on
	  whether OPAL is in XICS emulation mode  or native XIVE exploitation
	  mode.

.. _OPAL_XIVE_GET_IRQ_CONFIG:

OPAL_XIVE_GET_IRQ_CONFIG
^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_get_irq_config(uint32_t girq, uint64_t *out_vp,
                                  uint8_t *out_prio, uint32_t *out_lirq);

Returns current the configuration of an interrupt source. This is
the equivalent of opal_get_xive() with the addition of the logical
interrupt number (the number that will be presented in the queue).

* girq: The interrupt number to get the configuration of as
  provided by the device-tree.

* out_vp: Will contain the target virtual processor where the
  interrupt is currently routed to. This can return 0xffffffff
  if the interrupt isn't routed to a valid virtual processor.

* out_prio: Will contain the priority of the interrupt or 0xff
  if masked

* out_lirq: Will contain the logical interrupt assigned to the
  interrupt. By default this will be the same as girq.

.. _OPAL_XIVE_SET_IRQ_CONFIG:

OPAL_XIVE_SET_IRQ_CONFIG
^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_set_irq_config(uint32_t girq, uint64_t vp, uint8_t prio,
                                  uint32_t lirq);

This allows configuration and routing of a hardware interrupt. This is
equivalent to opal_set_xive() with the addition of the ability to
configure the logical IRQ number (the number that will be presented
in the target queue).

* girq: The interrupt number to configure of as provided by the
  device-tree.

* vp: The target virtual processor. The target VP/Prio combination
  must already exist, be enabled and populated (ie, a queue page must
  be provisioned for that queue).

* prio: The priority of the interrupt.

* lirq: The logical interrupt number assigned to that interrupt

  .. note:: Note about masking:

	    If the prio is set to 0xff, this call will cause the interrupt to
	    be masked (*). This function will not clobber the source P/Q bits (**).
	    It will however set the IVT/EAS "mask" bit if the prio passed
	    is 0xff which means that interrupt events from the ESB will be
	    discarded, potentially leaving the ESB in a stale state. Thus
	    care must be taken by the caller to "cleanup" the ESB state
	    appropriately before enabling an interrupt with this.

	    (*) Escalation interrupts cannot be masked via this function

	    (**) The exception to this rule is interrupt sources that have
	    the OPAL_XIVE_IRQ_MASK_VIA_FW flag set. For such sources, the OS
	    should make no assumption as to the state of the ESB and this
	    function *will* perform all the necessary masking and unmasking.

  .. note:: This call contains an implicit opal_xive_sync() of the interrupt
	    source (see OPAL_XIVE_SYNC below)

  It is recommended for an OS exploiting the XIVE directly to not use
  this function for temporary driver-initiated masking of interrupts
  but to directly mask using the P/Q bits of the source instead.

  Masking using this function is intended for the case where the OS has
  no handler registered for a given interrupt anymore or when registering
  a new handler for an interrupt that had none. In these case, losing
  interrupts happening while no handler was attached is considered fine.

.. _OPAL_XIVE_GET_QUEUE_INFO:

OPAL_XIVE_GET_QUEUE_INFO
^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_get_queue_info(uint64_t vp, uint32_t prio,
                                  uint64_t *out_qpage,
                                  uint64_t *out_qsize,
                                  uint64_t *out_qeoi_page,
                                  uint32_t *out_escalate_irq,
                                  uint64_t *out_qflags);

This returns informations about a given interrupt queue associated
with a virtual processor and a priority.

* out_qpage: will contain the physical address of the page where the
  interrupt events will be posted or 0 if none has been configured
  yet.

* out_qsize: will contain the log2 of the size of the queue buffer
  or 0 if the queue hasn't been populated. Example: 12 for a 4k page.

* out_qeoi_page: will contain the physical address of the MMIO page
  used to perform EOIs for the queue notifications.

* out_escalate_irq: will contain a girq number for the escalation
  interrupt associated with that queue.

  .. warning:: The "escalate_irq" is a special interrupt number, depending
	       on the implementation it may or may not correspond to a normal
	       XIVE source. Those interrupts have no triggers, and will not
	       be masked by opal_set_irq_config() with a prio of 0xff.

  ..note::     The state of the OPAL_XIVE_VP_SINGLE_ESCALATION flag passed to
	       opal_xive_set_vp_info() can change the escalation irq number,
	       so make sure you only retrieve this after having set the flag
	       to the desired value. When set, all priorities will have the
	       same escalation interrupt.

* out_qflags: will contain flags defined as follow:

  - OPAL_XIVE_EQ_ENABLED

    This must be set for the queue to be enabled and thus a valid
    target for interrupts. Newly allocated queues are disabled by
    default and must be disabled again before being freed (allocating
    and freeing of queues currently only happens along with their
    owner VP).

    .. note:: A newly enabled queue will have the generation set to 1
              and the queue pointer to 0. If the OS wants to "reset" a queue
              generation and pointer, it thus must disable and re-enable
              the queue.

  - OPAL_XIVE_EQ_ALWAYS_NOTIFY

    When this is set, the HW will always notify the VP on any new
    entry in the queue, thus the queue own P/Q bits won't be relevant
    and using the EOI page will be unnecessary.

  - OPAL_XIVE_EQ_ESCALATE

    When this is set, the EQ will escalate to the escalation interrupt
    when failing to notify.

.. _OPAL_XIVE_SET_QUEUE_INFO:

OPAL_XIVE_SET_QUEUE_INFO
^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_set_queue_info(uint64_t vp, uint32_t prio,
                                  uint64_t qpage,
                                  uint64_t qsize,
                                  uint64_t qflags);

This allows the OS to configure the queue page for a given processor
and priority and adjust the behaviour of the queue via flags.

* qpage: physical address of the page where the interrupt events will
  be posted. This has to be naturally aligned.

* qsize: log2 of the size of the above page. A 0 here will disable
  the queue.

* qflags: Flags (see definitions in opal_xive_get_queue_info)

  .. note:: This call will reset the generation bit to 1 and the queue
	    production pointer to 0.

  .. note:: The PQ bits of the escalation interrupts and of the queue
            notification will be set to 00 when OPAL_XIVE_EQ_ENABLED is
	    set, and to 01 (masked) when disabling it.

  .. note:: This must be called at least once on a queue with the flag
	    OPAL_XIVE_EQ_ENABLED in order to enable it after it has been
	    allocated (along with its owner VP).

  .. note:: When the queue is disabled (flag OPAL_XIVE_EQ_ENABLED cleared)
	    all other flags and arguments are ignored and the queue
	    configuration is wiped.

.. _OPAL_XIVE_DONATE_PAGE:

OPAL_XIVE_DONATE_PAGE
^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_donate_page(uint32_t chip_id, uint64_t addr);

This call is used to donate pages to OPAL for use by VP/EQ provisioning.

The pages must be of the size specified by the "ibm,xive-provision-page-size"
property and naturally aligned.

All donated pages are forgotten by OPAL (and thus returned to the OS)
on any call to opal_xive_reset().

The chip_id should be the chip on which the pages were allocated or -1
if unspecified. Ideally, when a VP allocation request fails with the
OPAL_XIVE_PROVISIONING error, the OS should allocate one such page
for each chip in the system and hand it to OPAL before trying again.

.. note:: It is possible that the provisioning ends up requiring more than
	  one page per chip. OPAL will keep returning the above error until
	  enough pages have been provided.

.. _OPAL_XIVE_ALLOCATE_VP_BLOCK:

OPAL_XIVE_ALLOCATE_VP_BLOCK
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_alloc_vp_block(uint32_t alloc_order);

This call is used to allocate a block of VPs. It will return a number
representing the base of the block which will be aligned on the alloc
order, allowing the OS to do basic arithmetic to index VPs in the block.

The VPs will have queue structures reserved (but not initialized nor
provisioned) for all the priorities defined in the "ibm,xive-#priorities"
property

This call might return OPAL_XIVE_PROVISIONING. In this case, the OS
must allocate pages and provision OPAL using opal_xive_donate_page(),
see the documentation for opal_xive_donate_page() for details.

The resulting VPs must be individudally enabled with opal_xive_set_vp_info
below with the OPAL_XIVE_VP_ENABLED flag set before use.

For all priorities, the corresponding queues must also be individually
provisioned and enabled with opal_xive_set_queue_info.

.. _OPAL_XIVE_FREE_VP_BLOCK:

OPAL_XIVE_FREE_VP_BLOCK
^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_free_vp_block(uint64_t vp);

This call is used to free a block of VPs. It must be called with the same
*base* number as was returned by opal_xive_alloc_vp() (any index into the
block will result in an OPAL_PARAMETER error).

The VPs must have been previously all disabled with opal_xive_set_vp_info
below with the OPAL_XIVE_VP_ENABLED flag cleared before use.

All the queues must also have been disabled.

Failure to do any of the above will result in an OPAL_XIVE_FREE_ACTIVE error.

.. _OPAL_XIVE_GET_VP_INFO:

OPAL_XIVE_GET_VP_INFO
^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_get_vp_info(uint64_t vp,
                               uint64_t *flags,
                               uint64_t *cam_value,
                               uint64_t *report_cl_pair,
			       uint32_t *chip_id);

This call returns information about a VP:

* flags:

  - OPAL_XIVE_VP_ENABLED

    Returns the enabled state of the VP

  - OPAL_XIVE_VP_SINGLE_ESCALATION (if available)

    Returns whether single escalation mode is enabled for this VP
    (see opal_xive_set_vp_info()).

* cam_value: This is the value to program into the thread management
  area to dispatch that VP (ie, an encoding of the block + index).

* report_cl_pair:  This is the real address of the reporting cache line
  pair for that VP (defaults to 0, ie disabled)

* chip_id: The chip that VCPU was allocated on

.. _OPAL_XIVE_SET_VP_INFO:

OPAL_XIVE_SET_VP_INFO
^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_set_vp_info(uint64_t vp,
                               uint64_t flags,
                               uint64_t report_cl_pair);

This call configures a VP:

* flags:

  - OPAL_XIVE_VP_ENABLED

    This must be set for the VP to be usable and cleared before freeing it.

    .. note:: This can be used to disable the boot time VPs though this
	      isn't recommended. This must be used to enable allocated VPs.

  - OPAL_XIVE_VP_SINGLE_ESCALATION (if available)

    If this is set, the queues are configured such that all priorities
    turn into a single escalation interrupt. This results in the loss of
    priority 7 which can no longer be used. This this needs to be set
    before any interrupt is routed to that priority and queue 7 must not
    have been already enabled.

    This feature is available if the "single-escalation-property" is
    present in the xive device-tree node.

    .. warning:: When enabling single escalation, and pre-existing routing
		 and configuration of the individual queues escalation
		 is lost (except queue 7 which is the new merged escalation).
		 When further disabling it, the previous value is not
		 retrieved and the field cleared, escalation is disabled on
		 all the queues.

* report_cl_pair: This is the real address of the reporting cache line
  pair for that VP or 0 to disable.

    .. note:: When disabling a VP, all other VP settings are lost.

.. _OPAL_XIVE_ALLOCATE_IRQ:

OPAL_XIVE_ALLOCATE_IRQ
^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_allocate_irq(uint32_t chip_id);

This call allocates a software IRQ on a given chip. It returns the
interrupt number or a negative error code.

.. _OPAL_XIVE_FREE_IRQ:

OPAL_XIVE_FREE_IRQ
^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_free_irq(uint32_t girq);

This call frees a software IRQ that was allocated by
opal_xive_allocate_irq. Passing any other interrupt number
will result in an OPAL_PARAMETER error.

.. _OPAL_XIVE_SYNC:

OPAL_XIVE_SYNC
^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_sync(uint32_t type, uint32_t id);

This call is uses to synchronize some HW queues to ensure various changes
have taken effect to the point where their effects are visible to the
processor.

* type: Type of synchronization:

  - XIVE_SYNC_EAS: Synchronize a source. "id" is the girq number of the
    interrupt. This will ensure that any change to the PQ bits or the
    interrupt targetting has taken effect.

  - XIVE_SYNC_QUEUE: Synchronize a target queue. "id" is the girq number
    of the interrupt. This will ensure that any previous occurrence of the
    interrupt has reached the in-memory queue and is visible to the processor.

    .. note:: XIVE_SYNC_EAS and XIVE_SYNC_QUEUE can be used together
	      (ie. XIVE_SYNC_EAS | XIVE_SYNC_QUEUE) to completely synchronize
	      the path of an interrupt to its queue.

* id: Depends on the synchronization type, see above

.. _OPAL_XIVE_DUMP:

OPAL_XIVE_DUMP
^^^^^^^^^^^^^^
.. code-block:: c

  int64_t opal_xive_dump(uint32_t type, uint32_t id);

This is a debugging call that will dump in the OPAL console various
state information about the XIVE.

* type: Type of info to dump:

  - XIVE_DUMP_TM_HYP:  Dump the TIMA area for hypervisor physical thread
                       "id" is the PIR value of the thread

  - XIVE_DUMP_TM_POOL: Dump the TIMA area for the hypervisor pool
		       "id" is the PIR value of the thread

  - XIVE_DUMP_TM_OS:   Dump the TIMA area for the OS
		       "id" is the PIR value of the thread

  - XIVE_DUMP_TM_USER: Dump the TIMA area for the "user" area (unsupported)
		       "id" is the PIR value of the thread

  - XIVE_DUMP_VP:      Dump the state of a VP structure
                       "id" is the VP id

  - XIVE_DUMP_EMU:     Dump the state of the XICS emulation for a thread
		       "id" is the PIR value of the thread

.. _OPAL_XIVE_GET_QUEUE_STATE:

OPAL_XIVE_GET_QUEUE_STATE
^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_get_queue_state(uint64_t vp, uint32_t prio,
				   uint32_t *out_qtoggle,
				   uint32_t *out_qindex);

This call saves the queue toggle bit and index. This must be called on
an enabled queue.

* vp, prio: The target queue

* out_qtoggle: toggle bit of the queue

* out_qindex: index of the queue

.. _OPAL_XIVE_SET_QUEUE_STATE:

OPAL_XIVE_SET_QUEUE_STATE
^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_set_queue_state(uint64_t vp, uint32_t prio,
				   uint32_t qtoggle,
				   uint32_t qindex);

This call restores the queue toggle bit and index that was previously
saved by a call to opal_xive_get_queue_state(). This must be called on
an enabled queue.

* vp, prio: The target queue

* qtoggle: toggle bit of the queue

* qindex: index of the queue


.. _OPAL_XIVE_GET_VP_STATE:

OPAL_XIVE_GET_VP_STATE
^^^^^^^^^^^^^^^^^^^^^^
.. code-block:: c

 int64_t opal_xive_get_vp_state(uint64_t vp_id,
				uint64_t *out_state);

This call saves the VP HW state in "out_state". The format matches the
XIVE NVT word 4 and word 5. This must be called on an enabled VP.

* vp_id: The target VP

* out_state: Location where the state is to be stored
