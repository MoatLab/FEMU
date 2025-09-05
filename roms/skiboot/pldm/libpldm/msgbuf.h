#ifndef PLDM_MSGBUF_H
#define PLDM_MSGBUF_H

#ifdef __cplusplus
/*
 * Fix up C11's _Static_assert() vs C++'s static_assert().
 *
 * Can we please have nice things for once.
 */
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _Static_assert(...) static_assert(__VA_ARGS__)
extern "C" {
#endif

#include "base.h"
#include "pldm_types.h"

#include <assert.h>
#include <endian.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

/*
 * Fix up C11's _Static_assert() vs C++'s static_assert().
 *
 * Can we please have nice things for once.
 */
#ifdef __cplusplus
// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#define _Static_assert(...) static_assert(__VA_ARGS__)
#endif

struct pldm_msgbuf {
	uint8_t *cursor;
	size_t remaining;
};

/**
 * @brief Initialize pldm buf struct for buf extractor
 *
 * @param[out] ctx - pldm_msgbuf context for extractor
 * @param[in] minsize - The minimum required length of buffer `buf`
 * @param[in] buf - buffer to be extracted
 * @param[in] len - size of buffer
 *
 * @return PLDM_SUCCESS if all buffer accesses were in-bounds,
 * PLDM_ERROR_INVALID_DATA if pointer parameters are invalid, or
 * PLDM_ERROR_INVALID_LENGTH if length constraints are violated.
 */
__attribute__((no_sanitize("pointer-overflow"))) static inline int
pldm_msgbuf_init(struct pldm_msgbuf *ctx, size_t minsize, const void *buf,
		 size_t len)
{
	uint8_t *end;

	if (!ctx || !buf) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if ((minsize > len) || (len > SIZE_MAX)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	end = (uint8_t *)buf + len;
	if (end && end < (uint8_t *)buf) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	ctx->cursor = (uint8_t *)buf;
	ctx->remaining = (size_t)len;

	return PLDM_SUCCESS;
}

/**
 * @brief Validate buffer overflow state
 *
 * @param[in] ctx - pldm_msgbuf context for extractor
 *
 * @return PLDM_SUCCESS if there are zero or more bytes of data that remain
 * unread from the buffer. Otherwise, PLDM_ERROR_INVALID_LENGTH indicates that a
 * prior accesses would have occurred beyond the bounds of the buffer, and
 * PLDM_ERROR_INVALID_DATA indicates that the provided context was not a valid
 * pointer.
 */
static inline int pldm_msgbuf_validate(struct pldm_msgbuf *ctx)
{
	if (!ctx) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return ctx->remaining >= 0 ? PLDM_SUCCESS : PLDM_ERROR_INVALID_LENGTH;
}

/**
 * @brief Test whether a message buffer has been exactly consumed
 *
 * @param[in] ctx - pldm_msgbuf context for extractor
 *
 * @return PLDM_SUCCESS iff there are zero bytes of data that remain unread from
 * the buffer and no overflow has occurred. Otherwise, PLDM_ERROR_INVALID_LENGTH
 * indicates that an incorrect sequence of accesses have occurred, and
 * PLDM_ERROR_INVALID_DATA indicates that the provided context was not a valid
 * pointer.
 */
static inline int pldm_msgbuf_consumed(struct pldm_msgbuf *ctx)
{
	if (!ctx) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return ctx->remaining == 0 ? PLDM_SUCCESS : PLDM_ERROR_INVALID_LENGTH;
}

/**
 * @brief Destroy the pldm buf
 *
 * @param[in] ctx - pldm_msgbuf context for extractor
 *
 * @return PLDM_SUCCESS if all buffer accesses were in-bounds,
 * PLDM_ERROR_INVALID_DATA if the ctx parameter is invalid, or
 * PLDM_ERROR_INVALID_LENGTH if prior accesses would have occurred beyond the
 * bounds of the buffer.
 */
static inline int pldm_msgbuf_destroy(struct pldm_msgbuf *ctx)
{
	int valid;

	if (!ctx) {
		return PLDM_ERROR_INVALID_DATA;
	}

	valid = pldm_msgbuf_validate(ctx);

	ctx->cursor = NULL;
	ctx->remaining = 0;

	return valid;
}

/**
 * @brief Destroy the pldm_msgbuf instance, and check that the underlying buffer
 * has been completely consumed without overflow
 *
 * @param[in] ctx - pldm_msgbuf context
 *
 * @return PLDM_SUCCESS if all buffer access were in-bounds and completely
 * consume the underlying buffer. Otherwise, PLDM_ERROR_INVALID_DATA if the ctx
 * parameter is invalid, or PLDM_ERROR_INVALID_LENGTH if prior accesses would
 * have occurred byond the bounds of the buffer
 */
static inline int pldm_msgbuf_destroy_consumed(struct pldm_msgbuf *ctx)
{
	int consumed;

	if (!ctx) {
		return PLDM_ERROR_INVALID_DATA;
	}

	consumed = pldm_msgbuf_consumed(ctx);

	ctx->cursor = NULL;
	ctx->remaining = 0;

	return consumed;
}

/**
 * @brief pldm_msgbuf extractor for a uint8_t
 *
 * @param[inout] ctx - pldm_msgbuf context for extractor
 * @param[out] dst - destination of extracted value
 *
 * @return PLDM_SUCCESS if buffer accesses were in-bounds,
 * PLDM_ERROR_INVALID_LENGTH otherwise.
 * PLDM_ERROR_INVALID_DATA if input a invalid ctx
 */
static inline int pldm_msgbuf_extract_uint8(struct pldm_msgbuf *ctx,
					    uint8_t *dst)
{
	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(*dst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*dst = *((uint8_t *)(ctx->cursor));
	ctx->cursor++;
	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_int8(struct pldm_msgbuf *ctx, int8_t *dst)
{
	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(*dst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*dst = *((int8_t *)(ctx->cursor));
	ctx->cursor++;
	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_uint16(struct pldm_msgbuf *ctx,
					     uint16_t *dst)
{
	uint16_t ldst;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	// Check for buffer overflow. If we overflow, account for the request as
	// negative values in ctx->remaining. This way we can debug how far
	// we've overflowed.
	ctx->remaining -= sizeof(ldst);

	// Prevent the access if it would overflow. First, assert so we blow up
	// the test suite right at the point of failure. However, cater to
	// -DNDEBUG by explicitly testing that the access is valid.
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	// Use memcpy() to have the compiler deal with any alignment
	// issues on the target architecture
	memcpy(&ldst, ctx->cursor, sizeof(ldst));

	// Only assign the target value once it's correctly decoded
	*dst = le16toh(ldst);
	ctx->cursor += sizeof(ldst);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_int16(struct pldm_msgbuf *ctx,
					    int16_t *dst)
{
	int16_t ldst;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(ldst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(&ldst, ctx->cursor, sizeof(ldst));

	*dst = le16toh(ldst);
	ctx->cursor += sizeof(ldst);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_uint32(struct pldm_msgbuf *ctx,
					     uint32_t *dst)
{
	uint32_t ldst;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(ldst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(&ldst, ctx->cursor, sizeof(ldst));

	*dst = le32toh(ldst);
	ctx->cursor += sizeof(ldst);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_int32(struct pldm_msgbuf *ctx,
					    int32_t *dst)
{
	int32_t ldst;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(ldst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(&ldst, ctx->cursor, sizeof(ldst));

	*dst = le32toh(ldst);
	ctx->cursor += sizeof(ldst);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_extract_real32(struct pldm_msgbuf *ctx,
					     real32_t *dst)
{
	uint32_t ldst;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(ldst);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	_Static_assert(sizeof(*dst) == sizeof(ldst),
		       "Mismatched type sizes for dst and ldst");
	memcpy(&ldst, ctx->cursor, sizeof(ldst));
	ldst = le32toh(ldst);
	memcpy(dst, &ldst, sizeof(*dst));
	ctx->cursor += sizeof(*dst);

	return PLDM_SUCCESS;
}

#define pldm_msgbuf_extract(ctx, dst)                                          \
	_Generic((*(dst)),                                                     \
		uint8_t: pldm_msgbuf_extract_uint8,                            \
		int8_t: pldm_msgbuf_extract_int8,                              \
		uint16_t: pldm_msgbuf_extract_uint16,                          \
		int16_t: pldm_msgbuf_extract_int16,                            \
		uint32_t: pldm_msgbuf_extract_uint32,                          \
		int32_t: pldm_msgbuf_extract_int32,                            \
		real32_t: pldm_msgbuf_extract_real32)(ctx, dst)

static inline int pldm_msgbuf_extract_array_uint8(struct pldm_msgbuf *ctx,
						  uint8_t *dst, size_t count)
{
	size_t len;

	if (!ctx || !ctx->cursor || !dst) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (!count) {
		return PLDM_SUCCESS;
	}

	len = sizeof(*dst) * count;
	if (len > SIZE_MAX) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	ctx->remaining -= (size_t)len;
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(dst, ctx->cursor, len);
	ctx->cursor += len;

	return PLDM_SUCCESS;
}

#define pldm_msgbuf_extract_array(ctx, dst, count)                             \
	_Generic((*(dst)), uint8_t: pldm_msgbuf_extract_array_uint8)(ctx, dst, \
								     count)

static inline int pldm_msgbuf_insert_uint32(struct pldm_msgbuf *ctx,
					    const uint32_t src)
{
	uint32_t val = htole32(src);

	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &val, sizeof(val));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_insert_uint16(struct pldm_msgbuf *ctx,
					    const uint16_t src)
{
	uint16_t val = htole16(src);

	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &val, sizeof(val));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_insert_uint8(struct pldm_msgbuf *ctx,
					   const uint8_t src)
{
	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &src, sizeof(src));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_insert_int32(struct pldm_msgbuf *ctx,
					   const int32_t src)
{
	int32_t val = htole32(src);

	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &val, sizeof(val));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_insert_int16(struct pldm_msgbuf *ctx,
					   const int16_t src)
{
	int16_t val = htole16(src);

	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &val, sizeof(val));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_insert_int8(struct pldm_msgbuf *ctx,
					  const int8_t src)
{
	if (!ctx || !ctx->cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	ctx->remaining -= sizeof(src);
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, &src, sizeof(src));
	ctx->cursor += sizeof(src);

	return PLDM_SUCCESS;
}

#define pldm_msgbuf_insert(dst, src)                                           \
	_Generic((src),                                                        \
		uint8_t: pldm_msgbuf_insert_uint8,                             \
		int8_t: pldm_msgbuf_insert_int8,                               \
		uint16_t: pldm_msgbuf_insert_uint16,                           \
		int16_t: pldm_msgbuf_insert_int16,                             \
		uint32_t: pldm_msgbuf_insert_uint32,                           \
		int32_t: pldm_msgbuf_insert_int32)(dst, src)

static inline int pldm_msgbuf_insert_array_uint8(struct pldm_msgbuf *ctx,
						 const uint8_t *src,
						 size_t count)
{
	size_t len;
	if (!ctx || !ctx->cursor || !src) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (!count) {
		return PLDM_SUCCESS;
	}

	len = sizeof(*src) * count;
	if (len > SIZE_MAX) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	ctx->remaining -= (size_t)len;
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(ctx->cursor, src, len);
	ctx->cursor += len;

	return PLDM_SUCCESS;
}

#define pldm_msgbuf_insert_array(dst, src, count)                              \
	_Generic((*(src)), uint8_t: pldm_msgbuf_insert_array_uint8)(dst, src,  \
								    count)

static inline int pldm_msgbuf_span_required(struct pldm_msgbuf *ctx,
					    size_t required, void **cursor)
{
	if (!ctx || !ctx->cursor || !cursor || *cursor) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (required > SIZE_MAX) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	ctx->remaining -= (size_t)required;
	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*cursor = ctx->cursor;
	ctx->cursor += required;

	return PLDM_SUCCESS;
}

static inline int pldm_msgbuf_span_remaining(struct pldm_msgbuf *ctx,
					     void **cursor, size_t *len)
{
	if (!ctx || !ctx->cursor || !cursor || *cursor || !len) {
		return PLDM_ERROR_INVALID_DATA;
	}

	assert(ctx->remaining >= 0);
	if (ctx->remaining < 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*cursor = ctx->cursor;
	ctx->cursor += ctx->remaining;
	*len = ctx->remaining;
	ctx->remaining = 0;

	return PLDM_SUCCESS;
}
#ifdef __cplusplus
}
#endif

#endif /* BUF_H */
