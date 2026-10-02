# Several namespaces and devices

One FEMU controller can expose several namespaces, and each namespace can
run its own mode. A controller can, for example, offer a BlackBox namespace
for random writes next to a ZNS namespace for zoned data. You can also start
several FEMU controllers in one guest.

Namespaces created this way exist from boot. To create and delete
namespaces from the guest while it runs, see
[namespace management](ns-management-and-pi.md).

## Requirements

- Host and guest: see [the mode table](../concepts/choosing-a-mode.md#every-mode-at-a-glance)
  and [requirements.md](../getting-started/requirements.md#kernel-per-mode).
  Each namespace needs what its own mode needs: a ZNS namespace needs a
  guest kernel with ZNS support, and a KV namespace gets no block device.
- Host memory: `devsz_mb` is split between the namespaces, so the total does
  not grow with the namespace count. Each extra controller adds its own
  `devsz_mb`.

## Launch

There is no launcher for this. Take any `run-*.sh` script and change its
`-device femu` line.

Two BlackBox namespaces that split 4 GiB evenly:

<!-- femu-example: multi-ns-even -->
```
-device femu,devsz_mb=4096,femu_mode=1,namespaces=2
```

The same with explicit sizes of 3 GiB and 1 GiB. A comma inside a property
value is written twice on the QEMU command line:

<!-- femu-example: multi-ns-sizes -->
```
-device femu,devsz_mb=4096,femu_mode=1,namespaces=2,namespace_sizes=3G,,1G
```

Four namespaces, each in a different mode:

<!-- femu-example: multi-ns-modes -->
```
-device femu,devsz_mb=4096,femu_mode=1,namespaces=4,namespace_modes=nossd,,bbssd,,znssd,,kvssd
```

Two controllers, one BlackBox and one ZNS, each with its own memory:

<!-- femu-example: multi-ns-two-controllers -->
```
-device femu,id=nvme0,devsz_mb=1024,femu_mode=1 -device femu,id=nvme1,devsz_mb=1024,femu_mode=3
```

## Configuration

Properties: [mode, capacity and namespaces](../reference/properties.md#mode-capacity-and-namespaces).

- `namespaces`: 1 to 256 namespaces.
- `namespace_sizes`: the size of each namespace, in bytes or with a QEMU
  size suffix (`4G`, `512M`). One entry per namespace, each at least one
  512-byte sector; the sum may be all of `devsz_mb`. Unset, `devsz_mb` is
  split evenly, each share rounded down to 512 bytes. Each size, given or
  split, is then rounded down to whole logical blocks (`512 << lba_index`
  bytes; 512 bytes for a KV namespace), and a size under one block makes an
  empty namespace. Capacity that no namespace takes, because the sizes sum
  to less than `devsz_mb` or because of this rounding, stays unused and is
  not reported in `tnvmcap`.
- `namespace_modes`: the mode of each namespace, one of `nossd`, `bbssd`,
  `znssd`, `ocssd`, `csd` and `kvssd`, one entry per namespace. Unset, every
  namespace runs `femu_mode`.
  The controller's model number and serial still come from `femu_mode`.

The namespaces are packed one after another in the controller's memory, so
none can overwrite another.

The mode properties apply to each namespace of that mode:

- Each BlackBox or CSD namespace has its own FTL with the full NAND geometry
  (`nchs`, `blks_per_pl` and so on). Each namespace must fit in that
  geometry on its own, with room for GC.
- Each ZNS namespace builds its zones from the `zns_` properties and its own
  size, so a smaller ZNS namespace gets smaller zones
  ([zone size](../modes/zns.md#zone-size-and-zone-count)). Keep each ZNS
  namespace's size a power of two, or Linux may refuse its zone size.
- Each KV namespace has its own key space.

## Use it from the guest

List the namespaces and look at one:

```sh
sudo nvme list
sudo nvme list-ns /dev/nvme0
sudo nvme id-ns /dev/nvme0n2
```

Block namespaces appear as `/dev/nvme0n1`, `/dev/nvme0n2` and so on, in
namespace order; `nvme list` shows which ID each one has. A ZNS namespace is
a zoned block device. In the four-mode example it is the third namespace:

```sh
cat /sys/block/nvme0n3/queue/zoned
```

A KV namespace has no block device. Address it by namespace ID through the
controller, as in the [KV guide](../modes/kvssd.md#use-it-from-the-guest),
with `-n` set to its ID.

The SMART log and the vendor log page C0h report the controller as a whole:
C0h sums its counters over every BlackBox, CSD and KV namespace, and reports
the largest block read count among them. The second command below prints the
controller's WAF times 1000
([log pages and counters](../reference/log-pages-and-counters.md#vendor-log-page-c0h)).

```sh
sudo nvme smart-log /dev/nvme0
sudo nvme get-log /dev/nvme0 --log-id=0xc0 --log-len=512 -b | od -An -t u4 -N 4
```

A second controller is `/dev/nvme1` with its own namespaces.

## Limits and refusals

| Message | Cause and fix |
| --- | --- |
| `namespaces must be in [1, 256]` | `namespaces` out of range. |
| `namespace_sizes count must equal namespaces=2` | Give one size per namespace. Check that every comma inside the value is doubled. |
| `namespace_sizes: invalid size '3X'` | A size QEMU cannot parse. |
| `namespace_sizes sum (2147483648 B) exceeds the backend capacity (1073741824 B)` | Raise `devsz_mb` or lower the sizes. |
| `backend capacity N B is too small for M namespaces` | `devsz_mb=0`. |
| `namespace_sizes: '100' is smaller than a sector` | Each size must be at least 512 bytes. |
| `namespace_modes count must equal namespaces=2` | Give one mode per namespace. |
| `namespace_modes: unknown mode 'foo'` | Use `nossd`, `bbssd`, `znssd`, `ocssd`, `csd` or `kvssd`. |
| `ocssd supports a single namespace` | OCSSD cannot share a controller. |
| `csd supports at most one namespace per controller` | Only one CSD namespace. Its neighbours may use other modes. |
| `meta: namespace 2 runs a mode without metadata support (block or no-SSD only)` | `meta` needs every namespace to be NoSSD or BlackBox. |
| `streams requires NVM namespaces` | Streams needs every namespace to be NoSSD or BlackBox. |
| `FDP supports a single namespace; set namespaces=1 or disable FDP on the subsystem` | FDP takes one namespace. |
| `FEMU bbssd: namespace 1 exposes 4096 MiB of the 2048 MiB this geometry has, ...` | A BlackBox namespace is larger than the NAND geometry allows. Each namespace is checked against the full geometry. |

## Verify

1. `sudo nvme list-ns /dev/nvme0` lists IDs 1 to `namespaces`.
2. `sudo nvme list` shows one block device per non-KV namespace, with the
   sizes you set.
3. Data written to one namespace does not appear in another.

## Troubleshooting

- **Only one namespace appears.** `namespaces` defaults to 1. Set it, and
  check that the commas in `namespace_sizes` and `namespace_modes` are
  doubled. A single comma ends the property and QEMU reads the next item as
  a new property.
- **I want random-write and zoned capacity on one ZNS device.** Linux
  rejects ZNS conventional zones, so use a BlackBox namespace next to a ZNS
  namespace instead.
- **I want several separate SSDs.** Add one `-device femu` per SSD, each
  with its own `id` and `devsz_mb`.
- **Data is gone after QEMU exits.** Every namespace lives in host memory
  only. A guest reboot keeps the data.

Related issues: #26, #52, #121.

## Related pages

- [Namespace management, metadata and protection information](ns-management-and-pi.md)
- [Choosing a mode: which features combine](../concepts/choosing-a-mode.md#which-features-combine)
- [Architecture: mode backends](../concepts/architecture.md#3-mode-backends)
