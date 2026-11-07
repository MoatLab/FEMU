# NAND profiles

A NAND profile is a small versioned file that states the base timing of one
NAND chip. bbssd, CSD, KV and ZNS read the same file, so one study can name
the chip it used in one word.

```
 nand_profile=FILE --> realize reads it --> writes the timing properties:
   bbssd, CSD, KV: pg_rd_lat, pg_wr_lat, blk_er_lat, cmd_addr_lat, pg_xfer_lat, status_lat
   ZNS:            zns_pg_rd_lat, zns_pg_wr_lat (x pages of a wordline), zns_blk_er_lat, ...
 query-femu media member --> read-ns, program-ns, erase-ns, nand-profile
```

## File format, version 1

```ini
femu_nand_profile = 1    ; the first key that is not a comment
name = bbssd-flat-default
nand_type = none         ; none slc mlc tlc qlc: sets only the P/E rating
read_ns = 40000          ; one page read
program_ns = 200000      ; one page program
erase_ns = 2000000
cmd_addr_ns = 0          ; channel bus phases; 0 leaves the bus out
xfer_ns = 0              ; one NAND page of the mode on the bus
status_ns = 0
```

- Every key is required, once. `;` and `#` start a comment.
- Times are whole ns. Read, program and erase take 1 to 2147483647; the
  bus phases take 0 to 2147483647.
- The file path is relative to the working directory of QEMU.

## Rules

- A profile always gives flat timing: one time for every page. The NAND
  type tables and the page-type models stay off.
- A ZNS program covers a wordline: the device takes `program_ns` times
  the pages of a wordline of its `zns_flash_type`.
- `nand_type` sets `pe_cycles_rated` (none keeps 0, which still derives
  300 for default ZNS QLC).
- The timing properties a profile sets, and those that change the same
  times another way, must keep their defaults. Realize names the first
  one that does not.
- NoSSD and OCSSD namespaces refuse a profile, and so do a shared or CXL
  linked FTL.

## Files in the tree

| File | Gives |
| --- | --- |
| `hw/femu/profiles/bbssd-flat-default.nprof` | the bbssd, CSD and KV defaults |
| `hw/femu/profiles/qlc-zns-default.nprof` | the ZNS QLC defaults: 4 x 3049000 = 12196000 ns per program |

With either file the media times equal those without a profile.
`query-femu` shows them in `read-ns`, `program-ns` and `erase-ns`.
