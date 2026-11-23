# NAND profiles

A NAND profile is a small versioned file that states the base timing of one
NAND chip. bbssd, CSD, KV and ZNS read the same file, so one study can name
the chip it used in one word.

```
 nand_profile=FILE --> realize reads it --> writes the timing properties:
   bbssd, CSD, KV: pg_rd_lat, pg_wr_lat, blk_er_lat, cmd_addr_lat, pg_xfer_lat, status_lat
   ZNS:            zns_pg_rd_lat, zns_pg_wr_lat (x pages of a wordline), zns_blk_er_lat, ...
 query-femu media member --> read-ns, program-ns, erase-ns, nand-profile,
                             nand-profile-values (value, line, source)
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
- A UTF-8 byte order mark is not allowed: the first key then reads as
  unknown.
- Times are whole ns. Read, program and erase take 1 to 2147483647; the
  bus phases take 0 to 2147483647.
- The file path is relative to the working directory of QEMU.

## Sources

Each value key can have one source line. It states where the number
comes from: a datasheet, a paper or a measurement.

```ini
read_ns = 60000
source.read_ns = Example datasheet rev 2, Table 12; tR max at 25 C
```

- The key is `source.` and one value key: `nand_type`, `read_ns`,
  `program_ns`, `erase_ns`, `cmd_addr_ns`, `xfer_ns` or `status_ns`.
- The text is all of the line after the first `=`, without the white
  space at its ends. `;`, `#` and `=` are part of the text.
- The text has 1 to 255 bytes of UTF-8, with no control byte other
  than tab.
- A source line can come before or after its value, but after
  `femu_nand_profile`. A second source for one key is refused.
- Sources are optional. The version stays 1, so FEMU reads older files.
  An older FEMU refuses a file with sources, because it does not know
  the key.

`query-femu` lists the seven values in `nand-profile-values`, in the
order of their lines. Each entry holds the value realize used, its line,
and its source when the file has one. A time reads in canonical form:
`0040000` reads `40000`. Realize keeps a copy, so a later change to the
file does not change the reply.

```
 file line 6: read_ns = 60000            --> {"key": "read_ns", "value": "60000",
 file line 7: source.read_ns = Table 12       "line": 6, "source-line": 7,
                                              "source": "Table 12"}
```

## Rules

- On bbssd, CSD and KV a profile gives flat timing: one time for every
  page. The NAND type tables and the page-type models stay off.
- ZNS keeps its table timing (`array-timing` reads `table`), with the
  profile times as the base.
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

With either file the media times equal those without a profile. Each
value in both files has a source line that names the FEMU constant or
property it comes from.
`query-femu` shows them in `read-ns`, `program-ns` and `erase-ns`.
