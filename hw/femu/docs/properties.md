# Configuration reference

This page moved. The property reference is now generated from the binary, so
it lists every property with the description `-device <type>,help` prints:

- [reference/properties.md](reference/properties.md): every property of
  `femu`, `femu-subsys` and `femu-cxl-ssd`, with type, default and meaning,
  and the environment variables FEMU reads.
- [reference/runtime-properties.md](reference/runtime-properties.md): QOM
  properties and counters read or set with `qom-get` and `qom-set`.
- [reference/log-pages-and-counters.md](reference/log-pages-and-counters.md):
  the vendor log page C0h and the telemetry snapshot.

The sections of the old page map to these:

## Device and capacity

See [Mode, capacity and namespaces](reference/properties.md#mode-capacity-and-namespaces).

## SSD geometry

See [NAND geometry](reference/properties.md#nand-geometry-bbssd-csd-kv).

## NAND timing

See [NAND timing](reference/properties.md#nand-timing-bbssd-csd-kv).

## NAND media and reliability

See [Reliability and wear](reference/properties.md#reliability-and-wear).

## Garbage collection and mapping

See [Garbage collection, mapping and caches](reference/properties.md#garbage-collection-mapping-and-caches).

## Caching and buffering

See [Garbage collection, mapping and caches](reference/properties.md#garbage-collection-mapping-and-caches).

## Host link and controller

See [Host link and controller firmware](reference/properties.md#host-link-and-controller-firmware)
and [Queues, pollers and interrupts](reference/properties.md#queues-pollers-and-interrupts).

## Everything else

See the [full reference](reference/properties.md).

## Vendor log page C0h

See [Vendor log page C0h](reference/log-pages-and-counters.md#vendor-log-page-c0h).

## CXL SSD

See [`femu-cxl-ssd`](reference/properties.md#femu-cxl-ssd-cxl-type-3-ssd), its
[runtime properties](reference/runtime-properties.md#femu-cxl-ssd-cxl-type-3-ssd)
and the design note [cxlssd.md](cxlssd.md).
