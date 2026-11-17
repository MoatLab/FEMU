/*
 * RISC-V translation routines for xlrbr matching the unratified Zbr CRC32
 * bitmanip extension v0.93.
 *
 * Copyright (c) 2026 Rivos Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define REQUIRE_XLRBR(ctx) do {                    \
    if (!ctx->cfg_ptr->ext_xlrbr) {                \
        return false;                            \
    }                                            \
} while (0)

static bool gen_crc(DisasContext *ctx, arg_r2 *a,
                    void (*func)(TCGv, TCGv, TCGv), TCGv tsz)
{
    REQUIRE_XLRBR(ctx);
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1 = get_gpr(ctx, a->rs1, EXT_NONE);

    func(dest, src1, tsz);
    gen_set_gpr(ctx, a->rd, dest);

    return true;
}

#define TRANS_CRC32(NAME, SIZE) \
    static bool trans_crc32_##NAME(DisasContext *ctx, arg_r2 *a) \
    { if (SIZE == 8) { REQUIRE_64BIT(ctx); }; \
      return gen_crc(ctx, a, gen_helper_crc32, tcg_constant_tl(SIZE)); }
#define TRANS_CRC32C(NAME, SIZE) \
    static bool trans_crc32c_##NAME(DisasContext *ctx, arg_r2 *a) \
    { if (SIZE == 8) { REQUIRE_64BIT(ctx); }; \
      return gen_crc(ctx, a, gen_helper_crc32c, tcg_constant_tl(SIZE)); }

TRANS_CRC32(b, 1);
TRANS_CRC32(h, 2);
TRANS_CRC32(w, 4);
TRANS_CRC32(d, 8);
TRANS_CRC32C(b, 1);
TRANS_CRC32C(h, 2);
TRANS_CRC32C(w, 4);
TRANS_CRC32C(d, 8);
