#include "bios_table.h"
#include "base.h"
#include "bios.h"
#include "utils.h"
#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define POINTER_CHECK(pointer)                                                 \
	do {                                                                   \
		if ((pointer) == NULL)                                         \
			return PLDM_ERROR_INVALID_DATA;                        \
	} while (0)

#define ATTR_TYPE_EXPECT(type, expected)                                       \
	do {                                                                   \
		if ((type) != (expected) && (type) != ((expected) | 0x80))     \
			return PLDM_ERROR_INVALID_DATA;                        \
	} while (0)

#define BUFFER_SIZE_EXPECT(current_size, expected_size)                        \
	do {                                                                   \
		if ((current_size) < (expected_size))                          \
			return PLDM_ERROR_INVALID_LENGTH;                      \
	} while (0)

#define MEMBER_SIZE(type, member) sizeof(((struct type *)0)->member)

static void set_errmsg(const char **errmsg, const char *msg)
{
	if (errmsg != NULL) {
		*errmsg = msg;
	}
}

static uint16_t get_bios_string_handle(void)
{
	static uint16_t handle = 0;
	assert(handle != UINT16_MAX);

	return handle++;
}

size_t pldm_bios_table_string_entry_encode_length(uint16_t string_length)
{
	return sizeof(struct pldm_bios_string_table_entry) -
	       MEMBER_SIZE(pldm_bios_string_table_entry, name) + string_length;
}

void pldm_bios_table_string_entry_encode(void *entry, size_t entry_length,
					 const char *str, uint16_t str_length)
{
	size_t length = pldm_bios_table_string_entry_encode_length(str_length);
	assert(length <= entry_length);
	struct pldm_bios_string_table_entry *string_entry = entry;
	string_entry->string_handle = htole16(get_bios_string_handle());
	string_entry->string_length = htole16(str_length);
	memcpy(string_entry->name, str, str_length);
}

int pldm_bios_table_string_entry_encode_check(void *entry, size_t entry_length,
					      const char *str,
					      uint16_t str_length)
{
	if (str_length == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}
	POINTER_CHECK(entry);
	POINTER_CHECK(str);
	size_t length = pldm_bios_table_string_entry_encode_length(str_length);
	BUFFER_SIZE_EXPECT(entry_length, length);
	pldm_bios_table_string_entry_encode(entry, entry_length, str,
					    str_length);
	return PLDM_SUCCESS;
}

uint16_t pldm_bios_table_string_entry_decode_handle(
	const struct pldm_bios_string_table_entry *entry)
{
	return le16toh(entry->string_handle);
}

uint16_t pldm_bios_table_string_entry_decode_string_length(
	const struct pldm_bios_string_table_entry *entry)
{
	return le16toh(entry->string_length);
}

uint16_t pldm_bios_table_string_entry_decode_string(
	const struct pldm_bios_string_table_entry *entry, char *buffer,
	size_t size)
{
	uint16_t length =
		pldm_bios_table_string_entry_decode_string_length(entry);
	length = length < (size - 1) ? length : (size - 1);
	memcpy(buffer, entry->name, length);
	buffer[length] = 0;
	return length;
}

int pldm_bios_table_string_entry_decode_string_check(
	const struct pldm_bios_string_table_entry *entry, char *buffer,
	size_t size)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(buffer);
	size_t length =
		pldm_bios_table_string_entry_decode_string_length(entry);
	BUFFER_SIZE_EXPECT(size, length + 1);
	pldm_bios_table_string_entry_decode_string(entry, buffer, size);
	return PLDM_SUCCESS;
}

static size_t string_table_entry_length(const void *table_entry)
{
	const struct pldm_bios_string_table_entry *entry = table_entry;
	return sizeof(*entry) - sizeof(entry->name) +
	       pldm_bios_table_string_entry_decode_string_length(entry);
}

static uint16_t get_bios_attr_handle(void)
{
	static uint16_t handle = 0;
	assert(handle != UINT16_MAX);

	return handle++;
}

static void attr_table_entry_encode_header(void *entry, size_t length,
					   uint8_t attr_type,
					   uint16_t string_handle)
{
	struct pldm_bios_attr_table_entry *attr_entry = entry;
	assert(sizeof(*attr_entry) <= length);
	attr_entry->attr_handle = htole16(get_bios_attr_handle());
	attr_entry->attr_type = attr_type;
	attr_entry->string_handle = htole16(string_handle);
}

uint16_t pldm_bios_table_attr_entry_decode_attribute_handle(
	const struct pldm_bios_attr_table_entry *entry)
{
	return le16toh(entry->attr_handle);
}

uint8_t pldm_bios_table_attr_entry_decode_attribute_type(
	const struct pldm_bios_attr_table_entry *entry)
{
	return entry->attr_type;
}

uint16_t pldm_bios_table_attr_entry_decode_string_handle(
	const struct pldm_bios_attr_table_entry *entry)
{
	return le16toh(entry->string_handle);
}

size_t pldm_bios_table_attr_entry_enum_encode_length(uint8_t pv_num,
						     uint8_t def_num)
{
	return sizeof(struct pldm_bios_attr_table_entry) -
	       MEMBER_SIZE(pldm_bios_attr_table_entry, metadata) +
	       sizeof(pv_num) + pv_num * sizeof(uint16_t) + sizeof(def_num) +
	       def_num;
}

void pldm_bios_table_attr_entry_enum_encode(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_enum_info *info)
{
	size_t length = pldm_bios_table_attr_entry_enum_encode_length(
		info->pv_num, info->def_num);
	assert(length <= entry_length);
	uint8_t attr_type = info->read_only ? PLDM_BIOS_ENUMERATION_READ_ONLY :
					      PLDM_BIOS_ENUMERATION;
	attr_table_entry_encode_header(entry, entry_length, attr_type,
				       info->name_handle);
	struct pldm_bios_attr_table_entry *attr_entry = entry;
	attr_entry->metadata[0] = info->pv_num;
	uint16_t *pv_hdls =
		(uint16_t *)(attr_entry->metadata + 1 /* sizeof(pv num) */);
	size_t i;
	for (i = 0; i < info->pv_num; i++) {
		pv_hdls[i] = htole16(info->pv_handle[i]);
	}
	attr_entry->metadata[1 + info->pv_num * sizeof(uint16_t)] =
		info->def_num;
	memcpy(attr_entry->metadata + 1 /* sizeof(pv num) */ +
		       info->pv_num * sizeof(uint16_t) + 1 /* sizeof(def num)*/,
	       info->def_index, info->def_num);
}

int pldm_bios_table_attr_entry_enum_encode_check(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_enum_info *info)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(info);
	size_t length = pldm_bios_table_attr_entry_enum_encode_length(
		info->pv_num, info->def_num);
	BUFFER_SIZE_EXPECT(entry_length, length);
	pldm_bios_table_attr_entry_enum_encode(entry, entry_length, info);
	return PLDM_SUCCESS;
}

#define ATTR_TYPE_EXPECT(type, expected)                                       \
	do {                                                                   \
		if ((type) != (expected) && (type) != ((expected) | 0x80))     \
			return PLDM_ERROR_INVALID_DATA;                        \
	} while (0)

uint8_t pldm_bios_table_attr_entry_enum_decode_pv_num(
	const struct pldm_bios_attr_table_entry *entry)
{
	return entry->metadata[0];
}

int pldm_bios_table_attr_entry_enum_decode_pv_num_check(
	const struct pldm_bios_attr_table_entry *entry, uint8_t *pv_num)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(pv_num);
	ATTR_TYPE_EXPECT(entry->attr_type, PLDM_BIOS_ENUMERATION);
	*pv_num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	return PLDM_SUCCESS;
}

uint8_t pldm_bios_table_attr_entry_enum_decode_def_num(
	const struct pldm_bios_attr_table_entry *entry)
{
	uint8_t pv_num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	return entry->metadata[sizeof(uint8_t) /* pv_num */ +
			       sizeof(uint16_t) * pv_num];
}

int pldm_bios_table_attr_entry_enum_decode_def_num_check(
	const struct pldm_bios_attr_table_entry *entry, uint8_t *def_num)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(def_num);
	ATTR_TYPE_EXPECT(entry->attr_type, PLDM_BIOS_ENUMERATION);
	*def_num = pldm_bios_table_attr_entry_enum_decode_def_num(entry);
	return PLDM_SUCCESS;
}

uint8_t pldm_bios_table_attr_entry_enum_decode_pv_hdls(
	const struct pldm_bios_attr_table_entry *entry, uint16_t *pv_hdls,
	uint8_t pv_num)
{
	uint8_t num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	num = num < pv_num ? num : pv_num;
	size_t i;
	for (i = 0; i < num; i++) {
		uint16_t *hdl = (uint16_t *)(entry->metadata + sizeof(uint8_t) +
					     i * sizeof(uint16_t));
		pv_hdls[i] = le16toh(*hdl);
	}
	return num;
}

int pldm_bios_table_attr_entry_enum_decode_pv_hdls_check(
	const struct pldm_bios_attr_table_entry *entry, uint16_t *pv_hdls,
	uint8_t pv_num)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(pv_hdls);
	ATTR_TYPE_EXPECT(entry->attr_type, PLDM_BIOS_ENUMERATION);
	uint8_t num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	if (num != pv_num) {
		return PLDM_ERROR_INVALID_DATA;
	}
	pldm_bios_table_attr_entry_enum_decode_pv_hdls(entry, pv_hdls, pv_num);
	return PLDM_SUCCESS;
}

uint8_t pldm_bios_table_attr_entry_enum_decode_def_indices(
	const struct pldm_bios_attr_table_entry *entry, uint8_t *def_indices,
	uint8_t def_num)
{
	uint8_t num = pldm_bios_table_attr_entry_enum_decode_def_num(entry);
	num = num < def_num ? num : def_num;
	uint8_t pv_num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	const uint8_t *p = entry->metadata +
			   sizeof(uint8_t) /* number of possible values*/
			   + pv_num * sizeof(uint16_t) /* possible values */
			   + sizeof(uint8_t); /* number of default values */
	memcpy(def_indices, p, num);
	return num;
}

/** @brief Get length of an enum attribute entry
 */
static size_t attr_table_entry_length_enum(const void *entry)
{
	uint8_t pv_num = pldm_bios_table_attr_entry_enum_decode_pv_num(entry);
	uint8_t def_num = pldm_bios_table_attr_entry_enum_decode_def_num(entry);
	return pldm_bios_table_attr_entry_enum_encode_length(pv_num, def_num);
}

struct attr_table_string_entry_fields {
	uint8_t string_type;
	uint16_t min_length;
	uint16_t max_length;
	uint16_t def_length;
	uint8_t def_string[1];
} __attribute__((packed));

size_t pldm_bios_table_attr_entry_string_encode_length(uint16_t def_str_len)
{
	return sizeof(struct pldm_bios_attr_table_entry) -
	       MEMBER_SIZE(pldm_bios_attr_table_entry, metadata) +
	       sizeof(struct attr_table_string_entry_fields) -
	       MEMBER_SIZE(attr_table_string_entry_fields, def_string) +
	       def_str_len;
}

void pldm_bios_table_attr_entry_string_encode(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_string_info *info)
{
	size_t length = pldm_bios_table_attr_entry_string_encode_length(
		info->def_length);
	assert(length <= entry_length);
	uint8_t attr_type = info->read_only ? PLDM_BIOS_STRING_READ_ONLY :
					      PLDM_BIOS_STRING;
	attr_table_entry_encode_header(entry, entry_length, attr_type,
				       info->name_handle);
	struct pldm_bios_attr_table_entry *attr_entry = entry;
	struct attr_table_string_entry_fields *attr_fields =
		(struct attr_table_string_entry_fields *)attr_entry->metadata;
	attr_fields->string_type = info->string_type;
	attr_fields->min_length = htole16(info->min_length);
	attr_fields->max_length = htole16(info->max_length);
	attr_fields->def_length = htole16(info->def_length);
	if (info->def_length != 0 && info->def_string != NULL) {
		memcpy(attr_fields->def_string, info->def_string,
		       info->def_length);
	}
}

#define PLDM_STRING_TYPE_MAX	5
#define PLDM_STRING_TYPE_VENDOR 0xff

int pldm_bios_table_attr_entry_string_info_check(
	const struct pldm_bios_table_attr_entry_string_info *info,
	const char **errmsg)
{
	if (info->min_length > info->max_length) {
		set_errmsg(errmsg, "MinimumStingLength should not be greater "
				   "than MaximumStringLength");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->min_length == info->max_length &&
	    info->def_length != info->min_length) {
		set_errmsg(errmsg, "Wrong DefaultStringLength");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->def_length > info->max_length ||
	    info->def_length < info->min_length) {
		set_errmsg(errmsg, "Wrong DefaultStringLength");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->string_type > PLDM_STRING_TYPE_MAX &&
	    info->string_type != PLDM_STRING_TYPE_VENDOR) {
		set_errmsg(errmsg, "Wrong StringType");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->def_length != strlen(info->def_string)) {
		set_errmsg(errmsg, "Length of DefaultString should be equal to "
				   "DefaultStringLength");
		return PLDM_ERROR_INVALID_DATA;
	}

	return PLDM_SUCCESS;
}

int pldm_bios_table_attr_entry_string_encode_check(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_string_info *info)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(info);
	size_t length = pldm_bios_table_attr_entry_string_encode_length(
		info->def_length);
	BUFFER_SIZE_EXPECT(entry_length, length);
	if (pldm_bios_table_attr_entry_string_info_check(info, NULL) !=
	    PLDM_SUCCESS) {
		return PLDM_ERROR_INVALID_DATA;
	}
	pldm_bios_table_attr_entry_string_encode(entry, entry_length, info);
	return PLDM_SUCCESS;
}

uint16_t pldm_bios_table_attr_entry_string_decode_def_string_length(
	const struct pldm_bios_attr_table_entry *entry)
{
	struct attr_table_string_entry_fields *fields =
		(struct attr_table_string_entry_fields *)entry->metadata;
	return le16toh(fields->def_length);
}

int pldm_bios_table_attr_entry_string_decode_def_string_length_check(
	const struct pldm_bios_attr_table_entry *entry,
	uint16_t *def_string_length)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(def_string_length);
	ATTR_TYPE_EXPECT(entry->attr_type, PLDM_BIOS_STRING);
	*def_string_length =
		pldm_bios_table_attr_entry_string_decode_def_string_length(
			entry);
	return PLDM_SUCCESS;
}

uint8_t pldm_bios_table_attr_entry_string_decode_string_type(
	const struct pldm_bios_attr_table_entry *entry)
{
	struct attr_table_string_entry_fields *fields =
		(struct attr_table_string_entry_fields *)entry->metadata;
	return fields->string_type;
}

uint16_t pldm_bios_table_attr_entry_string_decode_max_length(
	const struct pldm_bios_attr_table_entry *entry)
{
	struct attr_table_string_entry_fields *fields =
		(struct attr_table_string_entry_fields *)entry->metadata;
	return le16toh(fields->max_length);
}

uint16_t pldm_bios_table_attr_entry_string_decode_min_length(
	const struct pldm_bios_attr_table_entry *entry)
{
	struct attr_table_string_entry_fields *fields =
		(struct attr_table_string_entry_fields *)entry->metadata;
	return le16toh(fields->min_length);
}

uint16_t pldm_bios_table_attr_entry_string_decode_def_string(
	const struct pldm_bios_attr_table_entry *entry, char *buffer,
	size_t size)
{
	uint16_t length =
		pldm_bios_table_attr_entry_string_decode_def_string_length(
			entry);
	length = length < (size - 1) ? length : (size - 1);
	struct attr_table_string_entry_fields *fields =
		(struct attr_table_string_entry_fields *)entry->metadata;
	memcpy(buffer, fields->def_string, length);
	buffer[length] = 0;
	return length;
}

/** @brief Get length of a string attribute entry
 */
static size_t attr_table_entry_length_string(const void *entry)
{
	uint16_t def_str_len =
		pldm_bios_table_attr_entry_string_decode_def_string_length(
			entry);
	return pldm_bios_table_attr_entry_string_encode_length(def_str_len);
}

struct attr_table_integer_entry_fields {
	uint64_t lower_bound;
	uint64_t upper_bound;
	uint32_t scalar_increment;
	uint64_t default_value;
} __attribute__((packed));

size_t pldm_bios_table_attr_entry_integer_encode_length(void)
{
	return sizeof(struct pldm_bios_attr_table_entry) - 1 +
	       sizeof(struct attr_table_integer_entry_fields);
}

void pldm_bios_table_attr_entry_integer_encode(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_integer_info *info)
{
	size_t length = pldm_bios_table_attr_entry_integer_encode_length();
	assert(length <= entry_length);
	uint8_t attr_type = info->read_only ? PLDM_BIOS_INTEGER_READ_ONLY :
					      PLDM_BIOS_INTEGER;
	attr_table_entry_encode_header(entry, entry_length, attr_type,
				       info->name_handle);
	struct pldm_bios_attr_table_entry *attr_entry = entry;
	struct attr_table_integer_entry_fields *attr_fields =
		(struct attr_table_integer_entry_fields *)attr_entry->metadata;
	attr_fields->lower_bound = htole64(info->lower_bound);
	attr_fields->upper_bound = htole64(info->upper_bound);
	attr_fields->scalar_increment = htole32(info->scalar_increment);
	attr_fields->default_value = htole64(info->default_value);
}

int pldm_bios_table_attr_entry_integer_info_check(
	const struct pldm_bios_table_attr_entry_integer_info *info,
	const char **errmsg)
{
	if (info->lower_bound == info->upper_bound) {
		if (info->default_value != info->lower_bound) {
			set_errmsg(errmsg, "Wrong DefaultValue");
			return PLDM_ERROR_INVALID_DATA;
		}
		if (info->scalar_increment != 0) {
			set_errmsg(errmsg, "Wrong ScalarIncrement");
			return PLDM_ERROR_INVALID_DATA;
		}
		return PLDM_SUCCESS;
	}
	if (info->lower_bound > info->upper_bound) {
		set_errmsg(errmsg,
			   "LowerBound should not be greater than UpperBound");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->default_value > info->upper_bound ||
	    info->default_value < info->lower_bound) {
		set_errmsg(errmsg, "Wrong DefaultValue");
		return PLDM_ERROR_INVALID_DATA;
	}
	if (info->scalar_increment == 0) {
		set_errmsg(errmsg, "ScalarIncrement should not be zero when "
				   "lower_bound != upper_bound");
		return PLDM_ERROR_INVALID_DATA;
	}
	if ((info->default_value - info->lower_bound) %
		    info->scalar_increment !=
	    0) {
		set_errmsg(errmsg, "Wrong DefaultValue or ScalarIncrement");
		return PLDM_ERROR_INVALID_DATA;
	}
	return PLDM_SUCCESS;
}

int pldm_bios_table_attr_entry_integer_encode_check(
	void *entry, size_t entry_length,
	const struct pldm_bios_table_attr_entry_integer_info *info)
{
	POINTER_CHECK(entry);
	POINTER_CHECK(info);
	size_t length = pldm_bios_table_attr_entry_integer_encode_length();
	BUFFER_SIZE_EXPECT(entry_length, length);
	if (pldm_bios_table_attr_entry_integer_info_check(info, NULL) !=
	    PLDM_SUCCESS) {
		return PLDM_ERROR_INVALID_DATA;
	}
	pldm_bios_table_attr_entry_integer_encode(entry, entry_length, info);
	return PLDM_SUCCESS;
}

void pldm_bios_table_attr_entry_integer_decode(
	const struct pldm_bios_attr_table_entry *entry, uint64_t *lower,
	uint64_t *upper, uint32_t *scalar, uint64_t *def)
{
	struct attr_table_integer_entry_fields *fields =
		(struct attr_table_integer_entry_fields *)entry->metadata;
	*lower = le64toh(fields->lower_bound);
	*upper = le64toh(fields->upper_bound);
	*scalar = le32toh(fields->scalar_increment);
	*def = le64toh(fields->default_value);
}

static size_t attr_table_entry_length_integer(const void *entry)
{
	(void)entry;
	return pldm_bios_table_attr_entry_integer_encode_length();
}

struct table_entry_length {
	uint8_t attr_type;
	size_t (*entry_length_handler)(const void *);
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const struct table_entry_length *
find_table_entry_length_by_type(uint8_t attr_type,
				const struct table_entry_length *handlers,
				size_t count)
{
	size_t i;
	for (i = 0; i < count; i++) {
		if (attr_type == handlers[i].attr_type) {
			return &handlers[i];
		}
	}
	return NULL;
}

static const struct table_entry_length attr_table_entries[] = {
	{ .attr_type = PLDM_BIOS_ENUMERATION,
	  .entry_length_handler = attr_table_entry_length_enum },
	{ .attr_type = PLDM_BIOS_ENUMERATION_READ_ONLY,
	  .entry_length_handler = attr_table_entry_length_enum },
	{ .attr_type = PLDM_BIOS_STRING,
	  .entry_length_handler = attr_table_entry_length_string },
	{ .attr_type = PLDM_BIOS_STRING_READ_ONLY,
	  .entry_length_handler = attr_table_entry_length_string },
	{ .attr_type = PLDM_BIOS_INTEGER,
	  .entry_length_handler = attr_table_entry_length_integer },
	{ .attr_type = PLDM_BIOS_INTEGER_READ_ONLY,
	  .entry_length_handler = attr_table_entry_length_integer },
};

static size_t attr_table_entry_length(const void *table_entry)
{
	const struct pldm_bios_attr_table_entry *entry = table_entry;
	const struct table_entry_length *attr_table_entry =
		find_table_entry_length_by_type(entry->attr_type,
						attr_table_entries,
						ARRAY_SIZE(attr_table_entries));
	assert(attr_table_entry != NULL);
	assert(attr_table_entry->entry_length_handler != NULL);

	return attr_table_entry->entry_length_handler(entry);
}

uint16_t pldm_bios_table_attr_value_entry_decode_attribute_handle(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	return le16toh(entry->attr_handle);
}

uint8_t pldm_bios_table_attr_value_entry_decode_attribute_type(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	return entry->attr_type;
}

size_t pldm_bios_table_attr_value_entry_encode_enum_length(uint8_t count)
{
	return sizeof(struct pldm_bios_attr_val_table_entry) - 1 +
	       sizeof(count) + count;
}

void pldm_bios_table_attr_value_entry_encode_enum(
	void *entry, size_t entry_length, uint16_t attr_handle,
	uint8_t attr_type, uint8_t count, const uint8_t *handles)
{
	size_t length =
		pldm_bios_table_attr_value_entry_encode_enum_length(count);
	assert(length <= entry_length);

	struct pldm_bios_attr_val_table_entry *table_entry = entry;
	table_entry->attr_handle = htole16(attr_handle);
	table_entry->attr_type = attr_type;
	table_entry->value[0] = count;
	if (count != 0) {
		memcpy(&table_entry->value[1], handles, count);
	}
}

uint8_t pldm_bios_table_attr_value_entry_enum_decode_number(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	return entry->value[0];
}

uint8_t pldm_bios_table_attr_value_entry_enum_decode_handles(
	const struct pldm_bios_attr_val_table_entry *entry, uint8_t *handles,
	uint8_t number)
{
	uint8_t curr_num =
		pldm_bios_table_attr_value_entry_enum_decode_number(entry);
	number = number < curr_num ? number : curr_num;
	memcpy(handles, &entry->value[1], number);

	return number;
}

int pldm_bios_table_attr_value_entry_encode_enum_check(
	void *entry, size_t entry_length, uint16_t attr_handle,
	uint8_t attr_type, uint8_t count, uint8_t *handles)
{
	POINTER_CHECK(entry);
	if (count != 0 && handles == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	ATTR_TYPE_EXPECT(attr_type, PLDM_BIOS_ENUMERATION);
	size_t length =
		pldm_bios_table_attr_value_entry_encode_enum_length(count);
	BUFFER_SIZE_EXPECT(entry_length, length);
	pldm_bios_table_attr_value_entry_encode_enum(
		entry, entry_length, attr_handle, attr_type, count, handles);
	return PLDM_SUCCESS;
}

static size_t attr_value_table_entry_length_enum(const void *entry)
{
	uint8_t number =
		pldm_bios_table_attr_value_entry_enum_decode_number(entry);
	return pldm_bios_table_attr_value_entry_encode_enum_length(number);
}

size_t
pldm_bios_table_attr_value_entry_encode_string_length(uint16_t string_length)
{
	return sizeof(struct pldm_bios_attr_val_table_entry) - 1 +
	       sizeof(string_length) + string_length;
}

void pldm_bios_table_attr_value_entry_encode_string(
	void *entry, size_t entry_length, uint16_t attr_handle,
	uint8_t attr_type, uint16_t str_length, const char *str)
{
	size_t length = pldm_bios_table_attr_value_entry_encode_string_length(
		str_length);
	assert(length <= entry_length);

	struct pldm_bios_attr_val_table_entry *table_entry = entry;
	table_entry->attr_handle = htole16(attr_handle);
	table_entry->attr_type = attr_type;
	if (str_length != 0) {
		memcpy(table_entry->value + sizeof(str_length), str,
		       str_length);
	}
	str_length = htole16(str_length);
	memcpy(table_entry->value, &str_length, sizeof(str_length));
}

uint16_t pldm_bios_table_attr_value_entry_string_decode_length(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	uint16_t str_length = 0;
	memcpy(&str_length, entry->value, sizeof(str_length));
	return le16toh(str_length);
}

void pldm_bios_table_attr_value_entry_string_decode_string(
	const struct pldm_bios_attr_val_table_entry *entry,
	struct variable_field *current_string)
{
	current_string->length =
		pldm_bios_table_attr_value_entry_string_decode_length(entry);
	current_string->ptr =
		entry->value + sizeof(uint16_t); // sizeof(CurrentStringLength)
}

int pldm_bios_table_attr_value_entry_encode_string_check(
	void *entry, size_t entry_length, uint16_t attr_handle,
	uint8_t attr_type, uint16_t str_length, const char *str)
{
	POINTER_CHECK(entry);
	if (str_length != 0 && str == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	ATTR_TYPE_EXPECT(attr_type, PLDM_BIOS_STRING);
	size_t length = pldm_bios_table_attr_value_entry_encode_string_length(
		str_length);
	BUFFER_SIZE_EXPECT(entry_length, length);
	pldm_bios_table_attr_value_entry_encode_string(
		entry, entry_length, attr_handle, attr_type, str_length, str);
	return PLDM_SUCCESS;
}

static size_t attr_value_table_entry_length_string(const void *entry)
{
	uint16_t str_length =
		pldm_bios_table_attr_value_entry_string_decode_length(entry);
	return pldm_bios_table_attr_value_entry_encode_string_length(
		str_length);
}

size_t pldm_bios_table_attr_value_entry_encode_integer_length(void)
{
	return sizeof(struct pldm_bios_attr_val_table_entry) - 1 +
	       sizeof(uint64_t);
}
void pldm_bios_table_attr_value_entry_encode_integer(void *entry,
						     size_t entry_length,
						     uint16_t attr_handle,
						     uint8_t attr_type,
						     uint64_t cv)
{
	size_t length =
		pldm_bios_table_attr_value_entry_encode_integer_length();
	assert(length <= entry_length);

	struct pldm_bios_attr_val_table_entry *table_entry = entry;
	table_entry->attr_handle = htole16(attr_handle);
	table_entry->attr_type = attr_type;
	cv = htole64(cv);
	memcpy(table_entry->value, &cv, sizeof(uint64_t));
}

int pldm_bios_table_attr_value_entry_encode_integer_check(void *entry,
							  size_t entry_length,
							  uint16_t attr_handle,
							  uint8_t attr_type,
							  uint64_t cv)
{
	POINTER_CHECK(entry);
	size_t length =
		pldm_bios_table_attr_value_entry_encode_integer_length();
	ATTR_TYPE_EXPECT(attr_type, PLDM_BIOS_INTEGER);
	BUFFER_SIZE_EXPECT(entry_length, length);
	pldm_bios_table_attr_value_entry_encode_integer(
		entry, entry_length, attr_handle, attr_type, cv);
	return PLDM_SUCCESS;
}

uint64_t pldm_bios_table_attr_value_entry_integer_decode_cv(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	uint64_t cv = 0;
	memcpy(&cv, entry->value, sizeof(cv));
	cv = le64toh(cv);
	return cv;
}

static size_t attr_value_table_entry_length_integer(const void *entry)
{
	(void)entry;
	return pldm_bios_table_attr_value_entry_encode_integer_length();
}

static const struct table_entry_length attr_value_table_entries[] = {
	{ .attr_type = PLDM_BIOS_ENUMERATION,
	  .entry_length_handler = attr_value_table_entry_length_enum },
	{ .attr_type = PLDM_BIOS_ENUMERATION_READ_ONLY,
	  .entry_length_handler = attr_value_table_entry_length_enum },
	{ .attr_type = PLDM_BIOS_STRING,
	  .entry_length_handler = attr_value_table_entry_length_string },
	{ .attr_type = PLDM_BIOS_STRING_READ_ONLY,
	  .entry_length_handler = attr_value_table_entry_length_string },
	{ .attr_type = PLDM_BIOS_INTEGER,
	  .entry_length_handler = attr_value_table_entry_length_integer },
	{ .attr_type = PLDM_BIOS_INTEGER_READ_ONLY,
	  .entry_length_handler = attr_value_table_entry_length_integer },
};

static size_t attr_value_table_entry_length(const void *table_entry)
{
	const struct pldm_bios_attr_val_table_entry *entry = table_entry;
	const struct table_entry_length *entry_length =
		find_table_entry_length_by_type(
			entry->attr_type, attr_value_table_entries,
			ARRAY_SIZE(attr_value_table_entries));
	assert(entry_length != NULL);
	assert(entry_length->entry_length_handler != NULL);

	return entry_length->entry_length_handler(entry);
}

size_t pldm_bios_table_attr_value_entry_length(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	return attr_value_table_entry_length(entry);
}

uint16_t pldm_bios_table_attr_value_entry_decode_handle(
	const struct pldm_bios_attr_val_table_entry *entry)
{
	return le16toh(entry->attr_handle);
}

static size_t pad_size_get(size_t size_without_pad)
{
	return ((size_without_pad % 4) ? (4 - size_without_pad % 4) : 0);
}

static uint8_t *pad_append(uint8_t *table_end, size_t pad_size)
{
	while (pad_size--) {
		*table_end++ = 0;
	}

	return table_end;
}

static uint8_t *checksum_append(uint8_t *table_end, uint32_t checksum)
{
	checksum = htole32(checksum);
	memcpy(table_end, &checksum, sizeof(checksum));

	return table_end + sizeof(checksum);
}

size_t pldm_bios_table_pad_checksum_size(size_t size_without_pad)
{
	size_t size = pad_size_get(size_without_pad) +
		      sizeof(uint32_t) /*sizeof(checksum)*/;
	return size;
}

size_t pldm_bios_table_append_pad_checksum(void *table, size_t size,
					   size_t size_without_pad)
{
	size_t pad_checksum_size =
		pldm_bios_table_pad_checksum_size(size_without_pad);
	size_t total_length = size_without_pad + pad_checksum_size;
	assert(size >= total_length);

	uint8_t *table_end = (uint8_t *)table + size_without_pad;
	size_t pad_size = pad_size_get(size_without_pad);
	table_end = pad_append(table_end, pad_size);

	uint32_t checksum = crc32(table, size_without_pad + pad_size);
	checksum_append(table_end, checksum);

	return total_length;
}

struct pldm_bios_table_iter {
	const uint8_t *table_data;
	size_t table_len;
	size_t current_pos;
	size_t (*entry_length_handler)(const void *table_entry);
};

struct pldm_bios_table_iter *
pldm_bios_table_iter_create(const void *table, size_t length,
			    enum pldm_bios_table_types type)
{
	struct pldm_bios_table_iter *iter = malloc(sizeof(*iter));
	assert(iter != NULL);
	iter->table_data = table;
	iter->table_len = length;
	iter->current_pos = 0;
	iter->entry_length_handler = NULL;
	switch (type) {
	case PLDM_BIOS_STRING_TABLE:
		iter->entry_length_handler = string_table_entry_length;
		break;
	case PLDM_BIOS_ATTR_TABLE:
		iter->entry_length_handler = attr_table_entry_length;
		break;
	case PLDM_BIOS_ATTR_VAL_TABLE:
		iter->entry_length_handler = attr_value_table_entry_length;
		break;
	}

	return iter;
}

void pldm_bios_table_iter_free(struct pldm_bios_table_iter *iter)
{
	free(iter);
}

#define pad_and_check_max 7
bool pldm_bios_table_iter_is_end(const struct pldm_bios_table_iter *iter)
{
	if (iter->table_len - iter->current_pos <= pad_and_check_max) {
		return true;
	}
	return false;
}

void pldm_bios_table_iter_next(struct pldm_bios_table_iter *iter)
{
	if (pldm_bios_table_iter_is_end(iter)) {
		return;
	}
	const void *entry = iter->table_data + iter->current_pos;
	iter->current_pos += iter->entry_length_handler(entry);
}

const void *pldm_bios_table_iter_value(struct pldm_bios_table_iter *iter)
{
	return iter->table_data + iter->current_pos;
}

typedef bool (*equal_handler)(const void *entry, const void *key);

static const void *
pldm_bios_table_entry_find_by_iter(struct pldm_bios_table_iter *iter,
				   const void *key, equal_handler equal)
{
	const void *entry;
	while (!pldm_bios_table_iter_is_end(iter)) {
		entry = pldm_bios_table_iter_value(iter);
		if (equal(entry, key)) {
			return entry;
		}
		pldm_bios_table_iter_next(iter);
	}
	return NULL;
}

static const void *
pldm_bios_table_entry_find_from_table(const void *table, size_t length,
				      enum pldm_bios_table_types type,
				      equal_handler equal, const void *key)
{
	struct pldm_bios_table_iter *iter =
		pldm_bios_table_iter_create(table, length, type);
	const void *entry =
		pldm_bios_table_entry_find_by_iter(iter, key, equal);
	pldm_bios_table_iter_free(iter);
	return entry;
}

static bool string_table_handle_equal(const void *entry, const void *key)
{
	const struct pldm_bios_string_table_entry *string_entry = entry;
	uint16_t handle = *(uint16_t *)key;
	if (pldm_bios_table_string_entry_decode_handle(string_entry) ==
	    handle) {
		return true;
	}
	return false;
}

const struct pldm_bios_string_table_entry *
pldm_bios_table_string_find_by_handle(const void *table, size_t length,
				      uint16_t handle)
{
	return pldm_bios_table_entry_find_from_table(table, length,
						     PLDM_BIOS_STRING_TABLE,
						     string_table_handle_equal,
						     &handle);
}

struct string_equal_arg {
	uint16_t str_length;
	const char *str;
};

static bool string_table_string_equal(const void *entry, const void *key)
{
	const struct pldm_bios_string_table_entry *string_entry = entry;
	const struct string_equal_arg *arg = key;
	if (arg->str_length !=
	    pldm_bios_table_string_entry_decode_string_length(string_entry)) {
		return false;
	}
	if (memcmp(string_entry->name, arg->str, arg->str_length) != 0) {
		return false;
	}
	return true;
}

const struct pldm_bios_string_table_entry *
pldm_bios_table_string_find_by_string(const void *table, size_t length,
				      const char *str)
{
	uint16_t str_length = strlen(str);
	struct string_equal_arg arg = { str_length, str };
	return pldm_bios_table_entry_find_from_table(table, length,
						     PLDM_BIOS_STRING_TABLE,
						     string_table_string_equal,
						     &arg);
}

static bool attr_table_handle_equal(const void *entry, const void *key)
{
	uint16_t handle = *(uint16_t *)key;
	return pldm_bios_table_attr_entry_decode_attribute_handle(entry) ==
	       handle;
}

const struct pldm_bios_attr_table_entry *
pldm_bios_table_attr_find_by_handle(const void *table, size_t length,
				    uint16_t handle)
{
	return pldm_bios_table_entry_find_from_table(table, length,
						     PLDM_BIOS_ATTR_TABLE,
						     attr_table_handle_equal,
						     &handle);
}

static bool attr_table_string_handle_equal(const void *entry, const void *key)
{
	uint16_t handle = *(uint16_t *)key;
	return pldm_bios_table_attr_entry_decode_string_handle(entry) == handle;
}

const struct pldm_bios_attr_table_entry *
pldm_bios_table_attr_find_by_string_handle(const void *table, size_t length,
					   uint16_t handle)
{
	return pldm_bios_table_entry_find_from_table(
		table, length, PLDM_BIOS_ATTR_TABLE,
		attr_table_string_handle_equal, &handle);
}

static bool attr_value_table_handle_equal(const void *entry, const void *key)
{
	uint16_t handle = *(uint16_t *)key;
	return pldm_bios_table_attr_value_entry_decode_handle(entry) == handle;
}

const struct pldm_bios_attr_val_table_entry *
pldm_bios_table_attr_value_find_by_handle(const void *table, size_t length,
					  uint16_t handle)
{
	return pldm_bios_table_entry_find_from_table(
		table, length, PLDM_BIOS_ATTR_VAL_TABLE,
		attr_value_table_handle_equal, &handle);
}

int pldm_bios_table_attr_value_copy_and_update(
	const void *src_table, size_t src_length, void *dest_table,
	size_t *dest_length, const void *entry, size_t entry_length)
{
	struct pldm_bios_table_iter *iter = pldm_bios_table_iter_create(
		src_table, src_length, PLDM_BIOS_ATTR_VAL_TABLE);

	int rc = PLDM_SUCCESS;
	const struct pldm_bios_attr_val_table_entry *tmp;
	const struct pldm_bios_attr_val_table_entry *to_update = entry;
	size_t buffer_length = *dest_length;
	size_t copied_length = 0;
	size_t length = 0;
	while (!pldm_bios_table_iter_is_end(iter)) {
		tmp = pldm_bios_table_iter_attr_value_entry_value(iter);
		length = attr_value_table_entry_length(tmp);

		/* we need the tmp's entry_length here, iter_next will calculate
		 * it too, use current_pos directly to avoid calculating it
		 * twice */
		iter->current_pos += length;
		if (tmp->attr_handle == to_update->attr_handle) {
			if (tmp->attr_type != to_update->attr_type) {
				rc = PLDM_ERROR_INVALID_DATA;
				goto out;
			}
			length = entry_length;
			tmp = entry;
		}
		if (copied_length + length > buffer_length) {
			rc = PLDM_ERROR_INVALID_LENGTH;
			goto out;
		}
		memcpy((uint8_t *)dest_table + copied_length, tmp, length);
		copied_length += length;
	}

	size_t pad_checksum_size =
		pldm_bios_table_pad_checksum_size(copied_length);
	if ((pad_checksum_size + copied_length) > buffer_length) {
		rc = PLDM_ERROR_INVALID_LENGTH;
		goto out;
	}

	*dest_length = pldm_bios_table_append_pad_checksum(
		dest_table, buffer_length, copied_length);
out:
	pldm_bios_table_iter_free(iter);
	return rc;
}

bool pldm_bios_table_checksum(const uint8_t *table, size_t size)
{
	if (table == NULL) {
		return false;
	}

	// 12: BIOSStringHandle(uint16) + BIOSStringLength(uint16) +
	//     Variable(4) + checksum(uint32)
	if (size < 12) {
		return false;
	}

	uint32_t src_crc = le32toh(*(uint32_t *)(table + size - 4));
	uint32_t dst_crc = crc32(table, size - 4);

	return src_crc == dst_crc;
}
