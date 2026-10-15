# Computational Programs and Subsystem Local Memory

A CSD controller (`femu_mode=4`) can also offer the two ratified NVMe command
sets for computational storage:

- Subsystem Local Memory (SLM) 1.2, command set identifier (CSI) 03h: a
  memory namespace of volatile, byte addressable device memory.
- Computational Programs (CP) 1.2, CSI 04h: a compute namespace that loads,
  activates and runs programs on ranges of that memory.

Both are opt-in. Without `csd_slm_size` and `csd_cp` the controller is the
CSD controller of [CSD mode](../modes/csd.md), with its CEMU commands only.
The CEMU commands stay on and keep their opcodes when the new sets are on.

## Requirements

- `femu_mode=4` and one CSD namespace (from `femu_mode` or
  `namespace_modes`).
- The host enables every I/O command set: CC.CSS 110b. Linux does that
  when the controller reports more than one command set.
- Linux and nvme-cli have no CP or SLM support. Send the commands through
  NVMe passthrough (`nvme io-passthru`, `nvme admin-passthru`).
- Downloaded programs need `csd_program_dir`, as in
  [CSD mode](../modes/csd.md#security-programs-run-inside-qemu-on-the-host).

## Launch

The shortest device line with both namespaces:

<!-- femu-example: csd-cp-slm -->
```
-device femu,devsz_mb=64,femu_mode=4,fdm_size=16,csd_slm_size=4,csd_cp=on
```

The controller then has three namespaces:

```
 NSID 1   CSD block namespace, CSI 00h   NVM commands, CEMU commands (b0h..f8h)
 NSID 2   memory namespace,    CSI 03h   4 MiB of device memory
 NSID 3   compute namespace,   CSI 04h   programs
```

With `namespaces=N`, the memory namespace is N+1 and the compute namespace
N+2. A memory namespace alone (`csd_slm_size` without `csd_cp`) is allowed.

## Configuration

| Property | Unit | Default | Meaning |
| --- | --- | --- | --- |
| `csd_slm_size` | MiB | 0 | Size of the memory namespace, 1 to 1024. 0 adds none. |
| `csd_cp` | bool | off | Add the compute namespace. Needs `csd_slm_size`. |

`nr_cu` is also the most programs the compute namespace activates at once
(MAXACT). `csf_runtime_scale` sets the run time of every CP program, as in
[CSD mode](../modes/csd.md#configuration).

## How a host uses it

```
 host                    compute ns (3)              memory ns (2)        block ns (1)
  |  Memory Copy, format 2h --------------------------> SLM <---- read ---- LBAs
  |  Execute Program ----> program on a compute unit
  |                         reads and writes ranges --> SLM
  |  <--- completion: 64-bit return value
  |  Memory Read 02h ----------------------------------> SLM --> host buffer
  |  Copy, format 4h, to namespace 1 -------------------------- SLM ---> LBAs
```

1. Write the input to the memory namespace with Memory Write, or copy it
   from blocks with Memory Copy, format 2h.
2. Create a Memory Range Set on the compute namespace.
3. Activate a program.
4. Run it with Execute Program, naming the set.
5. Read the result with Memory Read, or copy it to blocks with Copy, format
   4h.

Memory Read replaces the CEMU READ_AFDM (f2h) second step.

## Commands

### Memory namespace (SLM 1.2)

| Opcode | Command | Notes |
| --- | --- | --- |
| 00h | Flush | No effect. |
| 01h | Memory Copy | Formats 2h (blocks) and 4h (memory). |
| 02h | Memory Read | SB in CDW10-11, length in CDW12. |
| 04h | Memory Fill | Fills zeros. |
| 05h | Memory Write | SB in CDW10-11, length in CDW12. |

- Addresses and lengths are dword aligned.
- Memory Copy formats 2h and 4h each need their bit in the Copy Descriptor
  Formats Enable field of Host Behavior Support (feature 16h).
- Each command is atomic as a whole: a lock serializes all memory access,
  and data moves through a buffer, so a failed transfer changes nothing.

### Compute namespace (CP 1.2)

| Opcode | Command |
| --- | --- |
| 00h (I/O) | Flush, no effect |
| 01h (I/O) | Execute Program |
| 85h (admin) | Load Program |
| 88h (admin) | Program Activation Management |
| 89h (admin) | Memory Range Set Management |

The admin commands name the compute namespace in NSID.

### Programs

| PIND | Kind | What it does |
| --- | --- | --- |
| 0 | device-defined | Copies Memory Range 1 into Memory Range 2. Returns the bytes copied. |
| 1 | device-defined | FNV-1a, 64 bits, over every range in order, then the program data. Returns the hash. |
| 2 to 15 | downloadable | Load Program, type C3h (FEMU shared library) or C1h (FEMU eBPF, with uBPF). |

- A downloaded program has the CEMU program format and ABI: the file name,
  a NUL, the symbol, a NUL. CEMU programs therefore run unchanged.
- A program sees copies of its ranges. The device writes the changed bytes
  back when the program returns. A queue deletion or a controller reset
  while the program runs drops the command, and then nothing reaches the
  memory. A command dropped after its program returned keeps what the
  program wrote.
- Native programs still run inside QEMU with all of its rights. A program
  that writes outside its ranges damages QEMU memory, not the memory
  namespace.

### In use

```
 Execute fetched ---> program runs ---> completion waits ---> completion posted
 |<-------------------- program and range set are in use --------------->|
```

While an Execute is in use, Load Program unload and Program Activation
Management deactivate of its program give Program In Use (99h). Memory Range
Set Management delete of its set gives Memory Range Set In Use (95h). The
forms that name all (FFFFh) change nothing when any entry is in use.

## Identify and log pages

| Structure | Value |
| --- | --- |
| Identify Controller NN | namespaces plus 1 or 2 |
| CRCAP (byte 134) | 3h: Reachability Reporting, group identifiers fixed |
| OAES bit 17 | Reachability change notices; the topology never changes, so none is sent |
| OCFS | bits 2 and 4 with a memory namespace |
| CNS 1Ch | bit 3 (SLM), bit 4 (CP) |
| CNS 05h, CSI 03h | NSZE in bytes, NF 0, NOWG 0, MCMCL and MCMSSRL 1 MiB, MCMSRC 127 |
| CNS 05h, CSI 04h | MAXACT `nr_cu`, MAXMEMRS 64, MRSG 2, MAXMEMR 128, MAXPB 64 MiB, LPG 2 |
| CNS 06h, CSI 03h and 04h | version 1.2 |
| CNS 08h | RGRPID 1 for every namespace |

Log pages: [log pages and counters](../reference/log-pages-and-counters.md#computational-programs-and-reachability).

## Limits and refusals

| Message | Cause |
| --- | --- |
| `csd_slm_size and csd_cp need femu_mode=4` | The controller is not a CSD controller. |
| `csd_slm_size and csd_cp need a CSD namespace` | No namespace runs CSD. |
| `csd_cp needs a memory namespace: set csd_slm_size` | `csd_cp=on` alone. |
| `csd_slm_size must be at most 1024 MiB` | Too large. |
| `csd_slm_size and csd_cp cannot be used with ns_mgmt, subsys, power_loss or a CXL link` | Reachability is reported for one controller only. FDP needs a subsystem, so FDP is refused too. |
| `CSD: cannot allocate csd_slm_size` | The host has no memory for it. |

Where FEMU differs from the specifications:

| Specification | FEMU |
| --- | --- |
| Several compute and memory namespaces | One of each per controller. |
| Memory Copy format 3h | Invalid Field: no 16-byte protection information. |
| A format 2h source with protection information and PRACT=1 is copied without it | Incompatible Namespace or Format for any source with protection information. |
| A ZNS namespace is a valid format 2h source | Invalid Namespace or Format: no ZNS read timing here. |
| Fast copy | Not offered: FCO gives Fast Copy Not Possible (186h). |
| Program Unique Identifiers of NVMe programs | None registered yet; device-defined programs report PIT 000b. |
| A failed program run | No status is defined; FEMU returns the program's own error, Invalid Field. |
| A Memory Range outside the memory namespace | No status is defined; FEMU returns Invalid Memory Range Set (8Ch) for a set and Invalid Field for Execute. |
| CP Figure 53 gives 8Ch for an invalid PIND | FEMU returns 8Fh, as CP Figure 14 does. |
| Program run time | CP has no field for it; every run takes host time times `csf_runtime_scale`. |

## Timing

- Memory Read, Write and Fill have no media time. With the host link model
  on, the link charges the bytes each command moves to or from the host.
- Memory Copy, format 2h, charges the NAND reads of its block ranges on the
  FTL thread, as a Copy does.
- Copy, format 4h, charges only the write of its destination blocks.
- Execute Program takes the CSD program time: host run time times
  `csf_runtime_scale` on the first free compute unit.

## Verify

The qtests in `hw/femu/tests/qtest/femu-test.c` named `csd-cpslm-*`,
`csd-slm-*` and `csd-cp-*` send every command. `caps-csd-cpslm` checks every
opcode and log page against the logs. Run them from `build-femu/`:

<!-- femu-untested: runs the qtest binary, not a FEMU device line -->
```bash
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/qos-test -m quick \
  -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests/csd-cp-exec
```

## Related pages

- [CSD mode](../modes/csd.md): the controller, CEMU commands and programs
- [CSD design](../design/csd.md#cp-and-slm-command-sets)
- [Several namespaces](multi-namespace.md)
