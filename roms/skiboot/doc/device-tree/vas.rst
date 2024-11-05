.. _device-tree/vas:


Virtual Accelerator Switchboard (VAS)
=====================================

VAS is present in P9 or later processors. In P9, each chip has one
instance of VAS. Each instance of VAS is represented as a "platform
device" i.e as a node in root of the device tree: ::

  /vas@<vas_addr>

with unique VAS address which also represents the Hypervisor window
context address for the instance of VAS.

Each VAS node contains: ::

  compatible: "ibm,power9-vas", "ibm,vas"

  ibm,chip-id: Chip-id of the chip containing this instance of VAS.

  ibm,vas-id: unique identifier for each instance of VAS in the system.

  ibm,vas-port: Port address for the interrupt.

  interrupts: <IRQ# level> for this VAS instance.

  interrupt-parent: Interrupt controller phandle.

  reg: contains 8 64-bit fields.

        Fields [0] and [1] represent the Hypervisor window context BAR
        (start and length). Fields [2] and [3] represent the OS/User
        window context BAR (start and length). Fields [4] and [5]
        contain the start and length of paste power bus address region
        for this chip. Fields [6] and [7] represent the bit field (start
        bit and number of bits) where the window id of the window should
        be encoded when computing the paste address for the window.
