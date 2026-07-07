/*
 * upscat.c: USB HID UPS status streaming utility
 *
 * This program stays independent of the liberty library
 * in order to build on Windows.
 *
 * Copyright (c) 2026, Přemysl Eric Janouch <p@janouch.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>

#include <getopt.h>
#include <hidapi.h>

#ifdef _WIN32
#include <sysinfoapi.h>  // GetTickCount
#include <synchapi.h>  // Sleep
#else
#include <errno.h>
#include <time.h>  // clock_gettime
#endif

#include "upscat-usb.h"

#include "config.h"
#undef PROGRAM_NAME
#define PROGRAM_NAME "upscat"

#ifdef __OpenBSD__
#define hid_init hidapi_hid_init
#endif

#if defined __MINGW_GNU_PRINTF
#define ATTRIBUTE_PRINTF(x, y) __MINGW_GNU_PRINTF((x), (y))
#elif defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__((format(printf, x, y)))
#else
#define ATTRIBUTE_PRINTF(x, y)
#endif

#define countof(array) (sizeof array / sizeof array[0])

static int64_t
get_timestamp_ms(void)
{
#ifdef _WIN32
	return GetTickCount64();
#else
	struct timespec tp;
	if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0) {
		fprintf(stderr, "error: clock_gettime: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	return (int64_t) tp.tv_sec * 1000 + (int64_t) tp.tv_nsec / 1000000;
#endif
}

// --- USB HID report descriptor parser ----------------------------------------
// This parser is simplified for simple readouts.
// hidpar.pdf provides guidelines for better conforming implementations.

enum {
	// This is one byte.
	// USB HID 6.2.2.7: Report ID zero is reserved and should not be used.
	PARSER_REPORT_LIMIT = 256,
	// There is no explicit limit on the number of usages.
	PARSER_USAGES_LIMIT = 64,
};

enum {
	PARSER_ITEM_TYPE_MAIN = 0,
	PARSER_ITEM_TYPE_GLOBAL,
	PARSER_ITEM_TYPE_LOCAL,
	PARSER_ITEM_TYPE_RESERVED,

	PARSER_ITEM_TAG_LONG                     = 0xf,

	PARSER_ITEM_TAG_MAIN_INPUT               = 0x8,
	PARSER_ITEM_TAG_MAIN_OUTPUT              = 0x9,
	PARSER_ITEM_TAG_MAIN_FEATURE             = 0xb,
	PARSER_ITEM_TAG_MAIN_COLLECTION          = 0xa,
	PARSER_ITEM_TAG_MAIN_END_COLLECTION      = 0xc,

	PARSER_ITEM_TAG_GLOBAL_USAGE_PAGE        = 0x0,
	PARSER_ITEM_TAG_GLOBAL_LOGICAL_MINIMUM   = 0x1,
	PARSER_ITEM_TAG_GLOBAL_LOGICAL_MAXIMUM   = 0x2,
	PARSER_ITEM_TAG_GLOBAL_PHYSICAL_MINIMUM  = 0x3,
	PARSER_ITEM_TAG_GLOBAL_PHYSICAL_MAXIMUM  = 0x4,
	PARSER_ITEM_TAG_GLOBAL_UNIT_EXPONENT     = 0x5,
	PARSER_ITEM_TAG_GLOBAL_UNIT              = 0x6,
	PARSER_ITEM_TAG_GLOBAL_REPORT_SIZE       = 0x7,
	PARSER_ITEM_TAG_GLOBAL_REPORT_ID         = 0x8,
	PARSER_ITEM_TAG_GLOBAL_REPORT_COUNT      = 0x9,
	PARSER_ITEM_TAG_GLOBAL_PUSH              = 0xa,
	PARSER_ITEM_TAG_GLOBAL_POP               = 0xb,

	PARSER_ITEM_TAG_LOCAL_USAGE              = 0x0,
	PARSER_ITEM_TAG_LOCAL_USAGE_MINIMUM      = 0x1,
	PARSER_ITEM_TAG_LOCAL_USAGE_MAXIMUM      = 0x2,
	PARSER_ITEM_TAG_LOCAL_DESIGNATOR_INDEX   = 0x3,
	PARSER_ITEM_TAG_LOCAL_DESIGNATOR_MINIMUM = 0x4,
	PARSER_ITEM_TAG_LOCAL_DESIGNATOR_MAXIMUM = 0x5,
	PARSER_ITEM_TAG_LOCAL_STRING_INDEX       = 0x7,
	PARSER_ITEM_TAG_LOCAL_STRING_MINIMUM     = 0x8,
	PARSER_ITEM_TAG_LOCAL_STRING_MAXIMUM     = 0x9,
	PARSER_ITEM_TAG_LOCAL_DELIMITER          = 0xa,
};

// Technically, this is for data-type main items, describing fields.
struct parser_field {
	// USB HID 6.2.2.9: "Reports can be padded to byte-align fields by [...]
	// not declaring a usage for the main item."
	// USB HID 6.2.2.8: If there are fewer Usages than controls, the last Usage
	// also applies to the remaining controls.
	uint32_t usages[PARSER_USAGES_LIMIT];
	size_t usages_len;
	int32_t logical_minimum;
	int32_t logical_maximum;
	uint32_t report_size;
	uint32_t report_count;
	unsigned array__variable : 1;
	unsigned absolute__relative : 1;
};

struct parser_report {
	uint32_t report_id;
	// USB HID 8.4: "reports may not span more than one top-level collection."
	uint32_t application_usage;

	// There is no explicit limit on the number of fields per report.
	struct parser_field fields[16];
	size_t fields_len;
};

struct parser {
	// There is no explicit limit on the depth of collections.
	// USB HID 6.2.2.6: "a Usage item tag must be associated
	// with any collection" however many devices simply do not care.
	uint32_t collections[16];
	size_t collections_len;
	struct parser_state_global {
		uint32_t usage_page;
		int32_t logical_minimum;   // \_ If neither is negative,
		int32_t logical_maximum;   // /  the report field is unsigned.
		int32_t physical_minimum;  // \  These actually
		int32_t physical_maximum;  //  > start as UNDEFINED,
		int32_t unit_exponent;     // /  which we can't express.
		int32_t unit;
		uint32_t report_size;
		uint32_t report_id;
		uint32_t report_count;
	} global;
	struct parser_state_local {
		uint32_t usages[PARSER_USAGES_LIMIT];
		size_t usages_len;
		uint32_t usage_minimum;
		uint32_t designator_index;
		uint32_t designator_minimum;
		uint32_t designator_maximum;
		uint32_t string_index;
		uint32_t string_minimum;
		uint32_t string_maximum;
		uint32_t delimiter;
	} local;
	struct parser_report input[PARSER_REPORT_LIMIT];
	struct parser_report feature[PARSER_REPORT_LIMIT];
};

static const char *
parse_item_set(struct parser *parser, uint32_t flags, bool feature)
{
	struct parser_state_global *global = &parser->global;
	if (!global->report_id)
		return "missing Report ID";
	if (global->report_id >= PARSER_REPORT_LIMIT)
		return "Report ID is too high";

	struct parser_report *report = feature
		? &parser->feature[global->report_id]
		: &parser->input[global->report_id];
	if (report->fields_len == countof(report->fields))
		return "too many fields per Report";

	struct parser_state_local *local = &parser->local;
	struct parser_field *field = &report->fields[report->fields_len++];

	if (local->usages_len) {
		uint32_t last = local->usages[local->usages_len - 1];
		// Not bothering to error out on hitting the compile-time limit.
		while (local->usages_len < global->report_count
			&& local->usages_len < PARSER_USAGES_LIMIT)
			local->usages[local->usages_len++] = last;
	}

	report->report_id         = global->report_id;
	report->application_usage = parser->collections[0];
	memcpy(field->usages, local->usages, sizeof local->usages);
	field->usages_len         = local->usages_len;
	field->logical_minimum    = global->logical_minimum;
	field->logical_maximum    = global->logical_maximum;
	field->report_size        = global->report_size;
	field->report_count       = global->report_count;
	field->array__variable    = (flags >> 1) & 1;
	field->absolute__relative = (flags >> 2) & 1;

	return NULL;
}

static const char *
parse_item(
	struct parser *parser, uint8_t type, uint8_t tag, int32_t s, uint32_t u)
{
	switch (type) {
	case PARSER_ITEM_TYPE_MAIN: {
		const char *err = NULL;
		switch (tag) {
		break; case PARSER_ITEM_TAG_MAIN_INPUT:
			err = parse_item_set(parser, u, false);
		break; case PARSER_ITEM_TAG_MAIN_OUTPUT:
			// We don't care about these.
		break; case PARSER_ITEM_TAG_MAIN_FEATURE:
			err = parse_item_set(parser, u, true);
		break; case PARSER_ITEM_TAG_MAIN_COLLECTION:
			if (parser->local.usages_len > 1)
				return "expecting Collections to have at most one usage";
			if (!parser->collections_len && u != USB_HID_COLLECTION_APPLICATION)
				return "top-level Collections must be Application";

			if (parser->collections_len == countof(parser->collections))
				return "Collections nested too deep";
			parser->collections[parser->collections_len++] =
				parser->local.usages_len ? parser->local.usages[0] : 0;
		break; case PARSER_ITEM_TAG_MAIN_END_COLLECTION:
			if (!parser->collections_len)
				return "no Collection to end";
			parser->collections_len--;
		break; default:
			return "unsupported Main item tag";
		}

		parser->local = (struct parser_state_local) {};
		return err;
	}
	case PARSER_ITEM_TYPE_GLOBAL:
		switch (tag) {
		break; case PARSER_ITEM_TAG_GLOBAL_USAGE_PAGE:
			parser->global.usage_page = u;
		break; case PARSER_ITEM_TAG_GLOBAL_LOGICAL_MINIMUM:
			parser->global.logical_minimum = s;
		break; case PARSER_ITEM_TAG_GLOBAL_LOGICAL_MAXIMUM:
			parser->global.logical_maximum = s;
		break; case PARSER_ITEM_TAG_GLOBAL_PHYSICAL_MINIMUM:
			parser->global.physical_minimum = s;
		break; case PARSER_ITEM_TAG_GLOBAL_PHYSICAL_MAXIMUM:
			parser->global.physical_maximum = s;
		break; case PARSER_ITEM_TAG_GLOBAL_UNIT_EXPONENT:
			parser->global.unit_exponent = s;
		break; case PARSER_ITEM_TAG_GLOBAL_UNIT:
			parser->global.unit = s;
		break; case PARSER_ITEM_TAG_GLOBAL_REPORT_SIZE:
			if (u > 32)
				return "Report Size too large";
			parser->global.report_size = u;
		break; case PARSER_ITEM_TAG_GLOBAL_REPORT_ID:
			parser->global.report_id = u;
		break; case PARSER_ITEM_TAG_GLOBAL_REPORT_COUNT:
			parser->global.report_count = u;
		break; case PARSER_ITEM_TAG_GLOBAL_PUSH:
			return "state pushing is not supported";
		break; case PARSER_ITEM_TAG_GLOBAL_POP:
			return "state pushing is not supported";
		break; default:
			return "unsupported Global item tag";
		}
		break;
	case PARSER_ITEM_TYPE_LOCAL:
		switch (tag) {
		break; case PARSER_ITEM_TAG_LOCAL_USAGE:
			if (parser->local.usages_len == countof(parser->local.usages))
				return "too many Usages per field";

			// USB HUT 3.1: Usage ID 0 should always be reserved.
			if (!u)
				return "zero Usage";

			// We should really decide by the data length instead.
			if (u < 0x10000)
				u = parser->global.usage_page << 16 | u;

			parser->local.usages[parser->local.usages_len++] = u;
		break; case PARSER_ITEM_TAG_LOCAL_USAGE_MINIMUM:
			parser->local.usage_minimum = u;
		break; case PARSER_ITEM_TAG_LOCAL_USAGE_MAXIMUM:
			// This adds to usages from parser->local.usage_minimum through u.
			return "usage ranges are not supported";
		break; case PARSER_ITEM_TAG_LOCAL_DESIGNATOR_INDEX:
			parser->local.designator_index = u;
		break; case PARSER_ITEM_TAG_LOCAL_DESIGNATOR_MINIMUM:
			parser->local.designator_minimum = u;
		break; case PARSER_ITEM_TAG_LOCAL_DESIGNATOR_MAXIMUM:
			parser->local.designator_maximum = u;
		break; case PARSER_ITEM_TAG_LOCAL_STRING_INDEX:
			parser->local.string_index = u;
		break; case PARSER_ITEM_TAG_LOCAL_STRING_MINIMUM:
			parser->local.string_minimum = u;
		break; case PARSER_ITEM_TAG_LOCAL_STRING_MAXIMUM:
			parser->local.string_maximum = u;
		break; case PARSER_ITEM_TAG_LOCAL_DELIMITER:
			parser->local.delimiter = u;
			return "delimiters are not supported";
		break; default:
			return "unsupported Local item tag";
		}
		break;
	case PARSER_ITEM_TYPE_RESERVED:
		// Completely unnecessary.
		return "long/reserved items are not supported";
	}
	return NULL;
}

static const char *
parse_descriptor(struct parser *parser, const uint8_t *descriptor, size_t len)
{
	// USB HID 5.2 Report Descriptors
	const uint8_t *p = descriptor, *end = p + len;
	while (p != end) {
		// USB HID 5.3 Generic Item Format
		// USB HID 6.2.2.1 Items Types and Tags
		uint8_t prefix = *p++,
			size =  prefix       & 0x3,
			type = (prefix >> 2) & 0x3,
			tag  =  prefix >> 4;

		size += size == 3;
		if (p + size > end)
			return "item overflow";

		uint32_t uvalue = 0;
		int32_t svalue = 0;
		switch (size) {
		break; case 0:
		break; case 1:
			uvalue = p[0];
			svalue = (int8_t) p[0];
		break; case 2:
			uvalue = p[0] | p[1] << 8;
			svalue = (int16_t) (p[0] | p[1] << 8);
		break; case 4:
			uvalue = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
			svalue = (int32_t) uvalue;
		}

		p += size;
		const char *err = parse_item(parser, type, tag, svalue, uvalue);
		if (err)
			return err;
	}
	return NULL;
}

// --- Report reader -----------------------------------------------------------

struct report_parser {
	const uint8_t *data;                ///< Start of data from the report
	size_t len;                         ///< Length of report data
	const struct parser_report *report; ///< Report definition

	unsigned field;                     ///< Current field iterator
	unsigned subfield;                  ///< report_count iterator
	unsigned bit_position;              ///< Current bit position within data
};

static struct report_parser
report_parser_make(
	const struct parser_report *report, const uint8_t *data, size_t len)
{
	return (struct report_parser) {.data = data, .len = len, .report = report};
}

static int64_t
report_parser_extract(struct report_parser *rp, unsigned nbits, bool is_signed)
{
	// XXX: This algorithm seems unnecessarily random-access.
	// USB HID 5.8: the little-endian aspect actually needs no special handling.
	unsigned byte_offset = rp->bit_position / 8,
		shift = rp->bit_position % 8,
		nbytes = (shift + nbits + 7) / 8;

	uint64_t raw = 0;
	for (unsigned i = 0; i < nbytes; i++) {
		uint8_t byte = 0;
		if (byte_offset + i < rp->len)
			byte = rp->data[byte_offset + i];
		raw |= (uint64_t) byte << (8 * i);
	}
	rp->bit_position += nbits;

	raw >>= shift;
	if (nbits < 64)
		raw &= (1ULL << nbits) - 1;

	// USB HID 5.8: fields are signed (2's complement)
	// unless both Logical Minimum and Logical Maximum are non-negative.
	// Do sign extension.
	if (is_signed && nbits > 0 && nbits < 64 && (raw & 1ULL << (nbits - 1)))
		raw |= ~((1ULL << nbits) - 1);
	return (int64_t) raw;
}

static bool
report_parser_parse(struct report_parser *rp, uint32_t *usage, int64_t *value)
{
	while (rp->field < rp->report->fields_len) {
		const struct parser_field *f = &rp->report->fields[rp->field];
		if (!f->report_count) {
			rp->field++;
			continue;
		}

		uint32_t u = 0;
		if (rp->subfield < f->usages_len)
			u = f->usages[rp->subfield];
		int64_t v = report_parser_extract(
			rp, f->report_size, f->logical_minimum < 0);

		if (++rp->subfield == f->report_count) {
			rp->field++;
			rp->subfield = 0;
		}

		// Cannot make use of these.
		if (f->array__variable == 0 || f->absolute__relative == 1)
			continue;

		*usage = u;
		*value = v;
		return true;
	}
	return false;
}

// --- UPS abstraction ---------------------------------------------------------

struct ups_usage_output {
	uint32_t usage;                     ///< Extended usage, including page
	int64_t value;                      ///< Value
};

static int
ups_usage_output_cmp(const void *a, const void *b)
{
	const struct ups_usage_output *aa = (const struct ups_usage_output *) a;
	const struct ups_usage_output *bb = (const struct ups_usage_output *) b;
	return (aa->usage > bb->usage) - (aa->usage < bb->usage);
}

struct ups {
	hid_device *dev;                    ///< HID device handle
	const struct hid_device_info *info; ///< HID device information
	struct parser parser;               ///< Parsed USB HID report descriptor

	bool useful_reports[PARSER_REPORT_LIMIT];
	struct ups_usage_output fields[256];
	size_t fields_len;

	// As a theme, we spend memory in order to limit code and dependencies.
	char error[1024];
};

static int
ups_printid(const struct ups *u, char *buffer, size_t len)
{
	if (!*u->info->manufacturer_string)
		return snprintf(buffer, len, "%s(%04x:%04x): ",
			u->info->path, u->info->vendor_id, u->info->product_id);
	else if (!wcsncmp(u->info->manufacturer_string, u->info->product_string,
			wcslen(u->info->manufacturer_string)))
		return snprintf(buffer, len, "%s(%ls): ",
			u->info->path, u->info->product_string);
	else
		return snprintf(buffer, len, "%s(%ls %ls): ", u->info->path,
			u->info->manufacturer_string, u->info->product_string);
}

static bool
ups_failf(struct ups *u, const char *format, ...)
ATTRIBUTE_PRINTF(2, 3);

static bool
ups_failf(struct ups *u, const char *format, ...)
{
	int len = ups_printid(u, u->error, sizeof u->error);
	if (len >= 0) {
		va_list ap;
		va_start(ap, format);
		(void) vsnprintf(u->error + len, sizeof u->error - len, format, ap);
		va_end(ap);
	}
	return false;
}

static unsigned
ups_find_feature_report_with_usage(struct ups *u, uint32_t usage)
{
	for (size_t i = 0; i < PARSER_REPORT_LIMIT; i++) {
		struct parser_report *r = &u->parser.feature[i];
		if (!r->report_id || r->application_usage != USB_HID_USAGE__POWER__UPS)
			continue;

		for (size_t k = 0; k < r->fields_len; k++) {
			struct parser_field *f = &r->fields[k];

			// Cannot make use of these.
			if (f->array__variable == 0 || f->absolute__relative == 1)
				continue;

			for (size_t u = 0; u < f->usages_len; u++)
				if (f->usages[u] == usage)
					return r->report_id;
		}
	}
	return 0;
}

static const uint32_t ups_required_usages[] = {
	USB_HID_USAGE__BATTERY_SYSTEM__AC_PRESENT,
	USB_HID_USAGE__BATTERY_SYSTEM__REMAINING_CAPACITY,
	USB_HID_USAGE__BATTERY_SYSTEM__RUN_TIME_TO_EMPTY,
	USB_HID_USAGE__POWER__PERCENT_LOAD,
	0
};

static bool
ups_is_required_usage(uint32_t usage)
{
	for (size_t i = 0; ups_required_usages[i]; i++)
		if (ups_required_usages[i] == usage)
			return true;
	return false;
}

static bool
ups_is_compatible(struct ups *u)
{
	for (size_t i = 0; ups_required_usages[i]; i++) {
		unsigned report_id =
			ups_find_feature_report_with_usage(u, ups_required_usages[i]);
		if (!report_id)
			return ups_failf(u, "usage not found: %s",
				usb_hid_usage_to_string_full(ups_required_usages[i]));
		u->useful_reports[report_id] = true;
	}
	return true;
}

static bool
ups_open(struct ups *u, const struct hid_device_info *info)
{
#if 0
	// On some systems, we get one Application collection per logical device.
	// However, on systems where this is not the case, if there are
	// more such collections, these fields only cover the first one of them.
	// We'll use the parsed descriptor to figure out compatibility.
	uint32_t usage = info->usage_page << 16 | info->usage;
	if (usage && usage !=  USB_HID_USAGE__POWER__UPS)
		return ups_failf(u, "unexpected HID usage");
#endif

	u->info = info;
	hid_device *dev = hid_open_path(info->path);
	if (!dev) {
		ups_failf(u, "%ls", hid_error(NULL));
		goto out1;
	}

	u->dev = dev;
	u->info = hid_get_device_info(dev);
	if (!u->info) {
		ups_failf(u, "%ls", hid_error(NULL));
		goto out2;
	}

	// XXX: On Windows, this is wildly reconstructed, and may not work.
	uint8_t descriptor[HID_API_MAX_REPORT_DESCRIPTOR_SIZE] = {};
	int len = hid_get_report_descriptor(dev, descriptor, sizeof descriptor);
	if (len < 0) {
		ups_failf(u, "failed to read report descriptor");
		goto out2;
	}

	const char *err = parse_descriptor(&u->parser, descriptor, len);
	if (err) {
		ups_failf(u, "failed to parse report descriptor: %s", err);
		goto out2;
	}

	if (ups_is_compatible(u))
		return true;

out2:
	hid_close(dev);
out1:
	u->dev = NULL;
	u->info = NULL;
	return false;
}

static void
ups_close(struct ups *u)
{
	if (u->dev)
		hid_close(u->dev);

	*u = (struct ups) {};
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static size_t
ups_report_len(const struct parser_report *r)
{
	size_t total_bits = 0;
	for (size_t i = 0; i < r->fields_len; i++)
		total_bits += r->fields[i].report_size * r->fields[i].report_count;
	return (total_bits + 7) / 8;
}

static bool
ups_parse_report_field(
	struct ups *u, const struct ups_usage_output field, bool filter)
{
	// Update values of the same usage.
	//
	// This is not ideal, because, e.g., Voltage can figure in multiple
	// Power page physical collections: Power Summary, Input, Output.
	//
	// It also causes spurious change reports.
	for (size_t i = 0; i < u->fields_len; i++) {
		if (u->fields[i].usage == field.usage) {
			bool changed = u->fields[i].value != field.value;
			u->fields[i].value = field.value;
			return changed;
		}
	}
	if (filter && !ups_is_required_usage(field.usage))
		return false;
	if (u->fields_len == countof(u->fields)) {
		fprintf(stderr, "warning: too many fields\n");
		return false;
	}
	u->fields[u->fields_len++] = field;
	return true;

}

static bool
ups_parse_report(struct ups *u, const struct parser_report *r,
	const uint8_t *data, size_t len, bool filter)
{
	struct report_parser rp = report_parser_make(r, data, len);
	struct ups_usage_output field = {};
	bool changed = false;
	while (report_parser_parse(&rp, &field.usage, &field.value))
		if (ups_parse_report_field(u, field, filter))
			changed = true;

	qsort(u->fields, u->fields_len, sizeof u->fields[0], ups_usage_output_cmp);
	return changed;
}

static void
ups_dump(const struct ups *u)
{
	printf("%s,%ls,%ls,%ls", u->info->path, u->info->manufacturer_string,
		u->info->product_string, u->info->serial_number);
	for (size_t i = 0; i < u->fields_len; i++)
		if (u->fields[i].usage)
			printf(",%" PRId64, u->fields[i].value);
	putchar('\n');
	fflush(stdout);
}

/// Retrieve all reports which contain the data we're interested in.
static bool
ups_rescan(struct ups *u, int verbose, bool *changed)
{
	for (unsigned i = 0; i < countof(u->useful_reports); i++) {
		if (verbose < 2 && !u->useful_reports[i])
			continue;

		const struct parser_report *r = &u->parser.feature[i];
		if (!r->report_id)
			continue;

		size_t len = 1 + ups_report_len(r);
		uint8_t buf[1024] = {i};
		if (hid_get_feature_report(u->dev, buf, len) < 0) {
			ups_failf(u, "Get_Feature failed: %ls", hid_error(u->dev));
			return false;
		}

		if (ups_parse_report(u, r, buf + 1, len - 1, !verbose))
			*changed = true;
	}
	return true;
}

static bool
ups_watch(struct ups *u, int interval, int verbose)
{
	int until_rescan = interval;

	uint8_t buf[1024] = {};
	int res = 0;
	while (true) {
#ifdef _WIN32
		// FIXME: Windows seems to fail reads with "Incorrect function".
		// For now, at least try to make do with simple rescans.
		Sleep(until_rescan);
#else
		int64_t stamp = get_timestamp_ms();
		if ((res = hid_read_timeout(
				u->dev, buf, sizeof buf, until_rescan)) < 0)
			return ups_failf(u, "watch: %ls", hid_read_error(u->dev));
		if (interval >= 0) {
			if ((until_rescan -= get_timestamp_ms() - stamp) < 0)
				until_rescan = 0;
		}
#endif

		if (!res) {
			// Non-negative intervals allow a timeout:
			// do a full rescan, and prime the next interval.
			until_rescan = interval;

			bool changed = false;
			if (!ups_rescan(u, verbose, &changed))
				return false;
			if (changed)
				ups_dump(u);
		} else {
			const struct parser_report *r = &u->parser.input[buf[0]];
			if (r->report_id && ups_parse_report(u, r, buf + 1, res - 1, true))
				ups_dump(u);
		}
	}
	return true;
}

// --- Tests -------------------------------------------------------------------

#ifdef TESTING

static struct ups test_ups = {.info = &(const struct hid_device_info) {
	.path = "",
	.manufacturer_string = L"Test",
	.product_string = L"Test",
}};

static bool
test_parse_descriptor_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		perror(path);
		return false;
	}

	uint8_t data[65535] = {};
	size_t len = fread(data, 1, sizeof data, fp);
	if (ferror(fp)) {
		perror(path);
		fclose(fp);
		return false;
	}
	fclose(fp);

	struct ups *u = &test_ups;
	memset(&u->parser, 0, sizeof u->parser);
	const char *err = parse_descriptor(&u->parser, data, len);
	if (err) {
		fprintf(stderr, "%s: failed to parse report descriptor: %s\n",
			path, err);
		return false;
	}
	if (!ups_is_compatible(u)) {
		fprintf(stderr, "%s: incompatible: %s\n", path, u->error);
		return false;
	}
	return true;
}

int
main(int argc, char *argv[])
{
	// The most complex part of this program is the report descriptor parser,
	// so that's what we'll test.  All passed files are expected to be valid
	// and useful descriptors of a UPS-class device.
	int status = 0;
	for (int i = 1; i < argc; i++)
		if (!test_parse_descriptor_file(argv[i]))
			status = 1;
	return status;
}

#define main main_shadowed
#endif // TESTING

// --- Main --------------------------------------------------------------------

static const char *
run(struct ups *devices, size_t len, bool watch, int interval, int verbose)
{
	if (!len)
		return "no devices found";

	// The CSV format is inconvenient, as verbose output would be heterogenous.
	// We could realistically switch to JSON, as we only need to produce it,
	// not parse it, and that isn't too hard.
	if (len > 1 && verbose) {
		fprintf(stderr,
			"warning: multiple devices, disabling verbose output\n");
		verbose = 0;
	}

	for (size_t i = 0; i < len; i++) {
		struct ups *u = &devices[i];
		bool changed = false;
		if (!ups_rescan(u, verbose, &changed))
			return u->error;

		// In non-verbose mode, the order must be made the same for all fields.
		if (u == devices) {
			printf("path,manufacturer,product,serial");
			for (size_t i = 0; i < u->fields_len; i++)
				if (u->fields[i].usage)
					printf(",%s", usb_hid_usage_to_string(u->fields[i].usage));
			putchar('\n');
		}

		ups_dump(u);
	}
	if (watch) {
		// TODO(p): We could support multiple devices, but it's tricky reading
		// from all of them at once.  Options:
		//  - Run hid_read_timeout() for all of them in a sequence.
		//    But any lags are in principle undesired.
		//  - Run this from multiple threads.  This is a bit more code.
		if (len > 1)
			fprintf(stderr, "warning: multiple devices, watching the first\n");

		struct ups *u = devices;
		if (!ups_watch(u, interval, verbose))
			return u->error;
	}
	return NULL;
}

static const char *usage = "Usage: %s OPTION...\n\n"
	"  -l, --list      List all recognised UPS devices.\n"
	"  -n, --nowatch   Do not watch for changes.\n"
	"  -i, --interval  Polling interval in milliseconds, negative to disable.\n"
	"  -v, --verbose   Output a bit more information.\n"
	"  -h, --help      Display this help and exit.\n"
	"  -V, --version   Output version information and exit.\n";

int
main(int argc, char *argv[])
{
	const char *name = argv[0];
	static struct option opts[] = {
		{"list",     no_argument,       NULL, 'l'},
		{"nowatch",  no_argument,       NULL, 'n'},
		{"interval", required_argument, NULL, 'i'},
		{"help",     no_argument,       NULL, 'h'},
		{"verbose",  no_argument,       NULL, 'v'},
		{"version",  no_argument,       NULL, 'V'},
		{}
	};

	// Some devices' Input reports simply never happen.
	// Eaton UPS Companion scans everything in 3-second intervals.
	//
	// On the other hand, CyberPower's continuous reporting makes our rescans
	// let the interrupt queue fill up, after which we may pick up slightly
	// older data from there.  It creates an opportunity for flip-flopping.
	long interval = 5000;

	bool list = false, watch = true;
	int verbose = 0;
	int c = 0;
	while ((c = getopt_long(argc, argv, "lni:vhV", opts, NULL)) != -1)
		switch (c) {
		case 'l':
			list = true;
			break;
		case 'n':
			watch = false;
			break;
		case 'i':
			if ((interval = strtol(optarg, NULL, 10)) < 0)
				interval = -1;
			else if (interval > INT_MAX)
				interval = INT_MAX;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			printf(usage, name);
			return 0;
		case 'V':
			printf(PROGRAM_NAME " " PROGRAM_VERSION "\n");
			return 0;
		default:
			fprintf(stderr, "Unknown option\n");
			fprintf(stderr, usage, name);
			return 1;
		}

	argc -= optind;
	argv += optind;
	if (argc != 0) {
		fprintf(stderr, usage, name);
		return 1;
	}

	// This is safe to call repeatedly, it just might reset the locale.
	// It's actually not needed, so we might even leave it out.
	if (hid_init()) {
		fprintf(stderr, "error: %ls\n", hid_error(NULL));
		return 1;
	}

	// Not many of these structures would fit on the stack.
	static struct ups devices[16] = {};
	size_t devices_len = 0;

	struct hid_device_info *devs = hid_enumerate(0, 0), *p = devs;
	for (; p; p = p->next) {
		if (devices_len == countof(devices)) {
			fprintf(stderr, "warning: too many devices, skipping the rest");
			break;
		}

		struct ups *u = &devices[devices_len];
		if (ups_open(u, p))
			devices_len++;
		else if (verbose)
			fprintf(stderr, "error: %s\n", u->error);
	}
	hid_free_enumeration(devs);

	const char *err = NULL;
	if (list) {
		for (size_t i = 0; i < devices_len; i++) {
			struct ups *u = &devices[i];
			printf("path,manufacturer,product,serial\n%s,%ls,%ls,%ls\n",
				u->info->path, u->info->manufacturer_string,
				u->info->product_string, u->info->serial_number);
		}
	} else if ((err = run(devices, devices_len, watch, interval, verbose))) {
		fprintf(stderr, "error: %s\n", err);
	}

	for (size_t i = 0; i < devices_len; i++)
		ups_close(&devices[i]);
	return err != NULL;
}
