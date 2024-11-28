/*
 * eizoctl.c: EIZO Monitor Control
 *
 * This program stays independent of the liberty library
 * in order to build on Windows.
 *
 * Copyright (c) 2024, Přemysl Eric Janouch <p@janouch.name>
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <math.h>

#include <assert.h>

#include <getopt.h>
#include <hidapi.h>

#include "config.h"
#undef PROGRAM_NAME
#define PROGRAM_NAME "eizoctl"

#ifdef __OpenBSD__
#define hid_init hidapi_hid_init
#endif

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__((format(printf, x, y)))
#else
#define ATTRIBUTE_PRINTF(x, y)
#endif

static uint16_t
peek_u16le(const uint8_t *p)
{
	return (uint16_t) p[1] << 8 | p[0];
}

static void
put_u16le(uint8_t *p, uint16_t value)
{
	p[0] = value;
	p[1] = value >> 8;
}

// --- Partial USB HID report descriptor parser --------------------------------
// This parser only needs to support EIZO monitors,
// which keep to a simple scheme, so it is appropriately simplified.

enum {
	PARSER_REPORT_LIMIT = 256,
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

struct parser_report {
	uint32_t usage;
	int32_t logical_minimum;
	int32_t logical_maximum;
	uint32_t report_size;
	uint32_t report_id;
	uint32_t report_count;
};

struct parser {
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
		uint32_t usage;
		uint32_t usage_minimum;
		uint32_t usage_maximum;
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
	bool array__variable               = (flags >> 1) & 1;
	bool absolute__relative            = (flags >> 2) & 1;
	bool non_volatile__volatile        = (flags >> 7) & 1;
	if (!array__variable) {
		// Skip: This occurs at the end of the secondary descriptor.
		return NULL;
	}
	if (absolute__relative)
		return "Report item kind not supported: relative";
	if (feature && non_volatile__volatile)
		return "Report item kind not supported: volatile";

	// We should really decide by the data length instead.
	uint32_t usage = parser->local.usage;
	if (usage < 0x10000)
		usage = parser->global.usage_page << 16 | usage;
	if (!usage)
		return "zero Usage";

	struct parser_state_global *global = &parser->global;
	if (!global->report_id)
		return "missing Report ID";
	if (global->report_id >= PARSER_REPORT_LIMIT)
		return "Report ID is too high";
	if (global->report_size % 8) {
		// Skip: This occurs at the end of the secondary descriptor.
		return NULL;
	}

	struct parser_report *report = feature
		? &parser->feature[global->report_id]
		: &parser->input[global->report_id];
	if (report->usage)
		return "only one item per Report is supported";

	report->usage           = usage;
	report->logical_minimum = global->logical_minimum;
	report->logical_maximum = global->logical_maximum;
	report->report_size     = global->report_size;
	report->report_id       = global->report_id;
	report->report_count    = global->report_count;
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
			return "output items are not supported";
		break; case PARSER_ITEM_TAG_MAIN_FEATURE:
			err = parse_item_set(parser, u, true);
		break; case PARSER_ITEM_TAG_MAIN_COLLECTION:
			// Ignore for now.
			// Top level Collections must be Application.
		break; case PARSER_ITEM_TAG_MAIN_END_COLLECTION:
			// Ignore for now.
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
			// Note that reports can have multiple usages.
			parser->local.usage = u;
		break; case PARSER_ITEM_TAG_LOCAL_USAGE_MINIMUM:
			parser->local.usage_minimum = u;
		break; case PARSER_ITEM_TAG_LOCAL_USAGE_MAXIMUM:
			parser->local.usage_maximum = u;
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

// --- EIZO monitor control ----------------------------------------------------

enum {
	USB_VID_EIZO = 0x056d,

	USB_USAGE_PAGE__MONITOR = 0x80,
	USB_USAGE_PAGE__VESA_VIRTUAL_CONTROLS = 0x82,
	USB_USAGE_PAGE_MONITOR_ID__MONITOR_CONTROL = 0x01,

	EIZO_REPORT_ID_SECONDARY_DESCRIPTOR = 1,
	EIZO_REPORT_ID_SET                  = 2,
	EIZO_REPORT_ID_GET                  = 3,
	EIZO_REPORT_ID_SET_LONG             = 4,
	EIZO_REPORT_ID_GET_LONG             = 5,
	EIZO_REPORT_ID_PIN_CODE             = 6,
	EIZO_REPORT_ID_RESULT               = 7,
	EIZO_REPORT_ID_SERIAL_PRODUCT       = 8,
	EIZO_REPORT_ID_PROFILE              = 9,
	EIZO_REPORT_ID_CRITICAL_SECTION     = 10,
	// I'm not sure of the interaction.
	EIZO_REPORT_ID_CRITICAL_SET         = 11,
	EIZO_REPORT_ID_CRITICAL_GET         = 12,
	EIZO_REPORT_ID_CRITICAL_SET_LONG    = 13,
	EIZO_REPORT_ID_CRITICAL_GET_LONG    = 14,

	EIZO_REPORT_ID_COUNT                = 10,
	EIZO_SUBREPORT_COUNT                = PARSER_REPORT_LIMIT,

	EIZO_PROFILE_KEY_INPUT_PORTS        = 0x53,
	EIZO_PROFILE_KEY_USB_C_INPUT_PORTS  = 0x61,
};

struct eizo_monitor {
	uint16_t vid, pid;                  ///< USB device identification
	hid_device *dev;                    ///< HID device handle
	uint16_t pin_code;                  ///< Anti-race counter
	char serial[9], product[17];        ///< Serial number, product name

	struct eizo_profile_item {
		uint8_t len;
		uint8_t data[255];
	} profile[256];

	struct parser_report
		report_input[EIZO_REPORT_ID_COUNT],
		report_feature[EIZO_REPORT_ID_COUNT],
		subreports_input[EIZO_SUBREPORT_COUNT],
		subreports_feature[EIZO_SUBREPORT_COUNT];

	// As a theme, we spend memory in order to limit code and dependencies.
	char error[1024];
};

static bool
eizo_monitor_failf(struct eizo_monitor *m, const char *format, ...)
ATTRIBUTE_PRINTF(2, 3);

static bool
eizo_monitor_failf(struct eizo_monitor *m, const char *format, ...)
{
	int len = *m->product
		? snprintf(m->error, sizeof m->error, "%s %s: ", m->product, m->serial)
		: snprintf(m->error, sizeof m->error, "%04x:%04x: ", m->vid, m->pid);
	if (len >= 0) {
		va_list ap;
		va_start(ap, format);
		(void) vsnprintf(m->error + len, sizeof m->error - len, format, ap);
		va_end(ap);
	}
	return false;
}

static size_t
eizo_monitor_report_len(const struct parser_report *r)
{
	assert(r->report_size % 8 == 0);
	return r->report_size / 8 * r->report_count;
}

static bool
eizo_monitor_read_secondary_descriptor(struct eizo_monitor *m)
{
	const struct parser_report *r =
		&m->report_feature[EIZO_REPORT_ID_SECONDARY_DESCRIPTOR];
	size_t lenr = 1 + r->report_size / 8 * r->report_count;

	uint8_t buf[1024] = {r->report_id};
	enum { HEADER_LEN = 1 + 2 + 2 };
	if (sizeof buf < lenr)
		return eizo_monitor_failf(m, "buffer too short");

	if (hid_send_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"secondary descriptor Set_Feature failed: %ls", hid_error(m->dev));

	uint8_t descriptor[8 << 10];
	if (hid_get_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"secondary descriptor Get_Feature failed: %ls", hid_error(m->dev));
	size_t offset = peek_u16le(&buf[1]);
	if (offset)
		return eizo_monitor_failf(m,
			"secondary descriptor starts at an unexpected offset");
	size_t descriptor_len = peek_u16le(&buf[3]);
	if (descriptor_len > sizeof descriptor)
		return eizo_monitor_failf(m, "secondary descriptor is too long A");

	memcpy(descriptor + offset, &buf[HEADER_LEN], lenr - HEADER_LEN);
	offset += lenr - HEADER_LEN;
	while (offset < descriptor_len) {
		if (hid_get_feature_report(m->dev, buf, lenr) < 0)
			return eizo_monitor_failf(m,
				"secondary descriptor Get_Feature failed: %ls",
				hid_error(m->dev));
		if (peek_u16le(&buf[1]) != offset)
			return eizo_monitor_failf(m,
				"secondary descriptor starts at an unexpected offset");

		// We could also limit the amount we copy, but whatever.
		if (offset + lenr - HEADER_LEN > sizeof descriptor)
			return eizo_monitor_failf(m, "secondary descriptor is too long");

		memcpy(descriptor + offset, &buf[HEADER_LEN], lenr - HEADER_LEN);
		offset += lenr - HEADER_LEN;
	}

#if DUMP_DESCRIPTORS
	for (size_t i = 0; i < descriptor_len; i++)
		printf("%02x ", descriptor[i]);
	printf("\n");
#endif

	struct parser parser = {};
	const char *err = parse_descriptor(&parser, descriptor, descriptor_len);
	if (err)
		return eizo_monitor_failf(m, "secondary descriptor: %s", err);

	memcpy(m->subreports_feature, parser.feature, sizeof m->subreports_feature);
	memcpy(m->subreports_input, parser.input, sizeof m->subreports_input);
	return true;
}

static bool
eizo_monitor_read_profile(struct eizo_monitor *m)
{
	const struct parser_report *r = &m->report_feature[EIZO_REPORT_ID_PROFILE];
	size_t lenr = 1 + eizo_monitor_report_len(r);

	uint8_t buf[1024] = {r->report_id};
	enum { HEADER_LEN = 1 + 2 + 2 };
	if (sizeof buf < lenr)
		return eizo_monitor_failf(m, "buffer too short");

	if (hid_get_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"profile Get_Feature failed: %ls", hid_error(m->dev));

	const uint8_t *p = buf + 1, *end = buf + lenr;
	while (p + 2 <= end && p[0] != 0xff && p + 2 + p[1] <= end) {
		struct eizo_profile_item *item = &m->profile[p[0]];
		item->len = p[1];
		memcpy(item->data, p + 2, item->len);
		p += 2 + item->len;
	}
	return true;
}

static bool
eizo_monitor_open(struct eizo_monitor *m, const struct hid_device_info *info)
{
	m->vid = info->vendor_id;
	m->pid = info->product_id;
	if (info->usage_page != USB_USAGE_PAGE__MONITOR ||
		info->usage != USB_USAGE_PAGE_MONITOR_ID__MONITOR_CONTROL)
		return eizo_monitor_failf(m, "unexpected HID usage");

	// There can be more displays with the same VID/PID,
	// and info does not contain the serial number to tell them apart.
	hid_device *dev = hid_open_path(info->path);
	if (!dev)
		return eizo_monitor_failf(m, "%ls", hid_error(NULL));

	uint8_t descriptor[HID_API_MAX_REPORT_DESCRIPTOR_SIZE] = {};
	int len = hid_get_report_descriptor(dev, descriptor, sizeof descriptor);
	if (len < 0) {
		eizo_monitor_failf(m, "failed to read report descriptor");
		goto out;
	}

	struct parser parser = {};
	const char *err = parse_descriptor(&parser, descriptor, len);
	if (err) {
		eizo_monitor_failf(m, "failed to parse report descriptor: %s", err);
		goto out;
	}
	for (unsigned id = 1; id < EIZO_REPORT_ID_COUNT; id++) {
		if (parser.feature[id].usage == (0xff300000 | id))
			continue;

		eizo_monitor_failf(m, "EIZO HID report %u not supported", id);
		goto out;
	}

#if DUMP_DESCRIPTORS
	for (size_t i = 0; i < (size_t) len; i++)
		printf("%02x ", descriptor[i]);
	printf("\n");
#endif

	uint8_t pinbuf[3] = {EIZO_REPORT_ID_PIN_CODE, 0, 0};
	if (hid_get_feature_report(dev, pinbuf, sizeof pinbuf) != sizeof pinbuf) {
		eizo_monitor_failf(m, "failed to get PIN code: %ls", hid_error(dev));
		goto out;
	}

	// ---

	// Get it now, so that we have better error messages.
	uint8_t idbuf[32] = {EIZO_REPORT_ID_SERIAL_PRODUCT};
	size_t idlen = 1 + eizo_monitor_report_len(&parser.feature[idbuf[0]]);
	if (sizeof idbuf < idlen) {
		eizo_monitor_failf(m, "%s: %s",
			"failed to get serial number and product", "report too long");
		goto out;
	}
	if (hid_get_feature_report(dev, idbuf, idlen) != (int) idlen) {
		eizo_monitor_failf(m, "%s: %ls",
			"failed to get serial number and product", hid_error(dev));
		goto out;
	}
	for (size_t i = idlen; --i && idbuf[i] == ' '; )
		idbuf[i] = 0;

	m->dev = dev;
	m->pin_code = peek_u16le(&pinbuf[1]);
	memcpy(m->serial, &idbuf[1], 8);
	memcpy(m->product, &idbuf[9], idlen - 9);
	memcpy(m->report_feature, parser.feature, sizeof m->report_feature);
	memcpy(m->report_input,   parser.input,   sizeof m->report_input);

	// Note that there are also "reduced models" without secondary descriptors.
	// Those are all very old.
	if (eizo_monitor_read_secondary_descriptor(m) &&
		eizo_monitor_read_profile(m))
		return true;

out:
	hid_close(dev);
	return false;
}

static void
eizo_monitor_close(struct eizo_monitor *m)
{
	if (m->dev)
		hid_close(m->dev);

	*m = (struct eizo_monitor) {};
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static const struct parser_report *
eizo_monitor_subreport(const struct eizo_monitor *m, uint32_t usage)
{
	// It doesn't really matter how efficient this is.
	size_t len = sizeof m->subreports_feature / sizeof m->subreports_feature[0];
	for (size_t i = 0; i < len; i++)
		if (m->subreports_feature[i].usage == usage)
			return &m->subreports_feature[i];
	return NULL;
}

static bool
eizo_monitor_set(
	struct eizo_monitor *m, uint32_t usage, const uint8_t *data, size_t len)
{
	const struct parser_report *subr = eizo_monitor_subreport(m, usage),
		*set1 = &m->report_feature[EIZO_REPORT_ID_SET],
		*set2 = &m->report_feature[EIZO_REPORT_ID_SET_LONG];
	if (!subr)
		return eizo_monitor_failf(m, "set: usage not found: %#08x", usage);

	size_t len1 = 1 + eizo_monitor_report_len(set1);
	size_t len2 = 1 + eizo_monitor_report_len(set2);

	// We need to encapsulate it.
	uint8_t buf[1024] = {};
	enum { HEADER_LEN = 1 + 4 + 2 };
	if (len != eizo_monitor_report_len(subr) ||
		sizeof buf < HEADER_LEN + len ||
		sizeof buf < len1 || sizeof buf < len2)
		return eizo_monitor_failf(m, "set: length check failed");

	put_u16le(&buf[1], usage >> 16);
	put_u16le(&buf[3], usage);
	put_u16le(&buf[5], m->pin_code);
	memcpy(&buf[7], data, len);

	const struct parser_report *r = len1 >= HEADER_LEN + len ? set1 : set2;
	size_t lenr = 1 + eizo_monitor_report_len(r);
	buf[0] = r->report_id;
	if (hid_send_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"set: Set_Feature failed: %ls", hid_error(m->dev));

	// Don't use EIZO_REPORT_ID_RESULT now.
	return true;
}

static bool
eizo_monitor_get(
	struct eizo_monitor *m, uint32_t usage, uint8_t *data, size_t len)
{
	const struct parser_report *subr = eizo_monitor_subreport(m, usage),
		*get1 = &m->report_feature[EIZO_REPORT_ID_GET],
		*get2 = &m->report_feature[EIZO_REPORT_ID_GET_LONG];
	if (!subr)
		return eizo_monitor_failf(m, "get: usage not found: %#08x", usage);

	size_t len1 = 1 + eizo_monitor_report_len(get1);
	size_t len2 = 1 + eizo_monitor_report_len(get2);

	// We need to encapsulate it.
	uint8_t buf[1024] = {};
	enum { HEADER_LEN = 1 + 4 + 2 };
	if (len != eizo_monitor_report_len(subr) ||
		sizeof buf < HEADER_LEN + len ||
		sizeof buf < len1 || sizeof buf < len2)
		return eizo_monitor_failf(m, "get: length check failed");

	put_u16le(&buf[1], usage >> 16);
	put_u16le(&buf[3], usage);
	put_u16le(&buf[5], m->pin_code);

	const struct parser_report *r = len1 >= HEADER_LEN + len ? get1 : get2;
	size_t lenr = 1 + eizo_monitor_report_len(r);
	buf[0] = r->report_id;
	if (hid_send_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"get: Set_Feature failed: %ls", hid_error(m->dev));
	if (hid_get_feature_report(m->dev, buf, lenr) < 0)
		return eizo_monitor_failf(m,
			"get: Get_Feature failed: %ls", hid_error(m->dev));

	if ((uint32_t) (peek_u16le(&buf[1]) << 16 | peek_u16le(&buf[3])) != usage ||
		peek_u16le(&buf[5]) != m->pin_code)
		return eizo_monitor_failf(m, "get: invalid result");

	memcpy(data, buf + HEADER_LEN, len);
	return true;
}

// --- EIZO monitor utilities --------------------------------------------------

enum {
	DSUB1 = 0x100,
	DSUB2 = 0x101,
	DVI1  = 0x200,
	DVI2  = 0x201,
	DP1   = 0x300,
	DP2   = 0x301,
	HDMI1 = 0x400,
	HDMI2 = 0x401,
};

static const char
	// USB-C maps to a DisplayPort port, if present.
	*g_port_names_usb_c[] = {"USB-C", "USBC", NULL},

	**g_port_names[] = {
		NULL,
		(const char *[]) {"D-Sub", "DSub", "VGA", NULL},
		(const char *[]) {"DVI", NULL},
		(const char *[]) {"DisplayPort", "DP", NULL},
		(const char *[]) {"HDMI", NULL},
	};

// Monitors may or may not report these in their profile.
static const struct eizo_product {
	const char *product;
	const uint16_t *ports;
} g_products[] = {
	{"CG243W",  (const uint16_t[]) {DVI1, DVI2, DP1, 0}},
	{"CG223W",  (const uint16_t[]) {DVI1, DVI2, DP1, 0}},
	{"CG245W",  (const uint16_t[]) {DVI1, DVI2, DP1, 0}},
	{"CG275W",  (const uint16_t[]) {DVI1, DP1, DP2, 0}},
	{"SX2462W", (const uint16_t[]) {DVI1, DVI2, DP1, 0}},
	{"SX2262W", (const uint16_t[]) {DVI1, DVI2, DP1, 0}},
	{"SX2762W", (const uint16_t[]) {DVI1, DP1, DP2, 0}},
	{"S2232W",  (const uint16_t[]) {DVI1, DSUB1, 0}},
	{"S2432W",  (const uint16_t[]) {DVI1, DSUB1, 0}},
	{"S2242W",  (const uint16_t[]) {DVI1, DSUB1, 0}},
	{"S2233W",  (const uint16_t[]) {DP1, DVI1, DSUB1, 0}},
	{"S2433W",  (const uint16_t[]) {DP1, DVI1, DSUB1, 0}},
	{"S2243W",  (const uint16_t[]) {DP1, DVI1, DSUB1, 0}},
	{"EV2333W", (const uint16_t[]) {DP1, DVI1, DSUB1, 0}},
	{"EV2334W", (const uint16_t[]) {HDMI1, DVI1, DSUB1, 0}},
	{"EV2436W", (const uint16_t[]) {DP1, DVI1, DSUB1, 0}},
	{"EV3237",  (const uint16_t[]) {DVI1, DP1, DP2, HDMI1, 0}},
	{"EV2450",  (const uint16_t[]) {DSUB1, DVI1, DP1, HDMI1, 0}},
	{"EV2455",  (const uint16_t[]) {DSUB1, DVI1, DP1, HDMI1, 0}},
	{"EV2750",  (const uint16_t[]) {DVI1, DP1, HDMI1, 0}},
	{"EV2451",  (const uint16_t[]) {DSUB1, DVI1, DP1, HDMI1, 0}},
	{"EV2456",  (const uint16_t[]) {DSUB1, DVI1, DP1, HDMI1, 0}},
	{"EV2457",  (const uint16_t[]) {DVI1, DP1, HDMI1, 0}},
	{"EV2480",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2485",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2490",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2495",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2780",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2795",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV3895",  (const uint16_t[]) {DP1, DP2, HDMI1, HDMI2, 0}},
	{"CG3145",  (const uint16_t[]) {DP1, DP2, HDMI1, HDMI2, 0}},
	{"CG3146",  (const uint16_t[]) {
		0xa00, 0xa01, 0xa02, 0xa03, 0xa10, 0xa11, 0xa20, DP1, HDMI1, 0}},
	{"EV2785",  (const uint16_t[]) {DP1, DP2, HDMI1, HDMI2, 0}},
	{"EV3285",  (const uint16_t[]) {DP1, DP2, HDMI1, HDMI2, 0}},
	{"CG319X",  (const uint16_t[]) {DP1, DP2, HDMI1, HDMI2, 0}},
	{"CG279X",  (const uint16_t[]) {DVI1, DP1, DP2, HDMI1, 0}},
	{"CG2700X", (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"CG2700S", (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"CS2731",  (const uint16_t[]) {DVI1, DP1, DP2, HDMI1, 0}},
	{"CS2410",  (const uint16_t[]) {DVI1, DP1, HDMI1, 0}},
	{"CS2740",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2760",  (const uint16_t[]) {DVI1, DP1, DP2, HDMI1, 0}},
	{"EV2360",  (const uint16_t[]) {DSUB1, DP1, HDMI1, 0}},
	{"EV2460",  (const uint16_t[]) {DSUB1, DVI1, DP1, HDMI1, 0}},
	{"EV2781",  (const uint16_t[]) {DP1, DP2, HDMI1, 0}},
	{"EV2736W", (const uint16_t[]) {DP1, DVI1, 0}},
	{}
};

static const uint16_t *
eizo_ports_by_product_name(const char *product)
{
	for (size_t i = 0; g_products[i].product; i++)
		if (!strcmp(g_products[i].product, product))
			return g_products[i].ports;
	return NULL;
}

// Match port names case-insensitively, with an optional one-based suffix.
static bool
eizo_port_by_name_in_group(const char *name, const char **group, uint8_t *index)
{
	for (; *group; group++) {
		size_t len = strlen(*group);
		if (strncasecmp(*group, name, len))
			continue;
		if (!*(name += len))
			return true;

		char *end = NULL;
		errno = 0;
		long n = strtol(name, &end, 10);
		if (errno || *end || n < 1 || n > 0x100)
			return false;

		*index = --n;
		return true;
	}
	return false;
}

static uint16_t
eizo_port_by_name(const char *name)
{
	char *end = NULL;
	errno = 0;
	long n = strtol(name, &end, 16);
	if (!errno && !*end && n >= 0x100 && n <= UINT16_MAX)
		return n;

	uint8_t index = 0;
	for (size_t i = 1; i < sizeof g_port_names / sizeof g_port_names[0]; i++)
		if (eizo_port_by_name_in_group(name, g_port_names[i], &index))
			return i * 0x100 | index;
	return index;
}

static char *
eizo_port_to_name(uint16_t port)
{
	const char *stem = NULL;
	uint16_t group = port >> 8, number = port & 0xff;
	if (group && group < sizeof g_port_names / sizeof g_port_names[0])
		stem = g_port_names[group][0];

	static char buffer[32] = "";
	if (!stem)
		snprintf(buffer, sizeof buffer, "%x", port);
	else if (!number)
		snprintf(buffer, sizeof buffer, "%s", stem);
	else
		snprintf(buffer, sizeof buffer, "%s %d", stem, number);
	return buffer;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

enum {
	EIZO_USAGE_BRIGHTNESS = 0x00820010,
	EIZO_USAGE_INPUT_PORT = 0xff010048,
	EIZO_USAGE_RESTART    = 0xff0200f4,
};

static bool
eizo_get_brightness(struct eizo_monitor *m, double *brightness)
{
	const struct parser_report *subr =
		eizo_monitor_subreport(m, EIZO_USAGE_BRIGHTNESS);
	if (!subr)
		return eizo_monitor_failf(m, "missing HID usage");

	// NOTE: this oddly doesn't work when there's no signal.
	uint8_t buf[2] = {};
	if (!eizo_monitor_get(m, EIZO_USAGE_BRIGHTNESS, buf, sizeof buf))
		return false;

	*brightness = (double) peek_u16le(buf) / subr->logical_maximum;
	return true;
}

static bool
eizo_set_brightness(struct eizo_monitor *m, double brightness)
{
	const struct parser_report *subr =
		eizo_monitor_subreport(m, EIZO_USAGE_BRIGHTNESS);
	if (!subr)
		return eizo_monitor_failf(m, "missing HID usage");

	if (brightness < 0)
		brightness = 0;
	if (brightness > 1)
		brightness = 1;

	uint8_t buf[2] = {};
	put_u16le(buf, subr->logical_maximum * brightness);
	return eizo_monitor_set(m, EIZO_USAGE_BRIGHTNESS, buf, sizeof buf);
}

static bool
eizo_get_input_port(struct eizo_monitor *m, uint16_t *port)
{
	const struct parser_report *subr =
		eizo_monitor_subreport(m, EIZO_USAGE_INPUT_PORT);
	if (!subr)
		return eizo_monitor_failf(m, "missing HID usage");

	uint8_t buf[2] = {};
	if (!eizo_monitor_get(m, EIZO_USAGE_INPUT_PORT, buf, sizeof buf))
		return false;

	*port = peek_u16le(buf);
	return true;
}

static void
eizo_get_input_ports(struct eizo_monitor *m, uint16_t *ports, size_t size)
{
	struct eizo_profile_item *item = &m->profile[EIZO_PROFILE_KEY_INPUT_PORTS];
	if (item->len) {
		for (size_t i = 0; i < size && i < item->len / 4; i++)
			ports[i] = peek_u16le(item->data + i * 4);
	} else {
		const uint16_t *db = eizo_ports_by_product_name(m->product);
		for (size_t i = 0; i < size && db && db[i]; i++)
			ports[i] = db[i];
	}
}

static uint16_t
eizo_resolve_port(struct eizo_monitor *m, const char *port)
{
	uint8_t usb_c_index = 0;
	if (eizo_port_by_name_in_group(port, g_port_names_usb_c, &usb_c_index)) {
		struct eizo_profile_item *item =
			&m->profile[EIZO_PROFILE_KEY_USB_C_INPUT_PORTS];
		if (item->len / 2 > usb_c_index)
			return peek_u16le(item->data + usb_c_index * 2);
	}
	return eizo_port_by_name(port);
}

static bool
eizo_set_input_port(struct eizo_monitor *m, uint16_t port)
{
	const struct parser_report *subr =
		eizo_monitor_subreport(m, EIZO_USAGE_INPUT_PORT);
	if (!subr)
		return eizo_monitor_failf(m, "missing HID usage");

	uint8_t buf[2] = {};
	put_u16le(buf, port);
	return eizo_monitor_set(m, EIZO_USAGE_INPUT_PORT, buf, sizeof buf);
}

static bool
eizo_restart(struct eizo_monitor *m)
{
	const struct parser_report *subr =
		eizo_monitor_subreport(m, EIZO_USAGE_RESTART);
	if (!subr)
		return eizo_monitor_failf(m, "missing HID usage");

	uint8_t buf[1] = {};
	return eizo_monitor_set(m, EIZO_USAGE_RESTART, buf, 1);
}

// --- Main --------------------------------------------------------------------

static bool
eizo_watch(struct eizo_monitor *m)
{
	uint8_t buf[1024] = {};
	int res = 0;
	while (true) {
		if ((res = hid_read(m->dev, buf, sizeof buf)) < 0)
			return eizo_monitor_failf(m, "watch: %ls", hid_error(m->dev));

		if (buf[0] != EIZO_REPORT_ID_GET &&
			buf[0] != EIZO_REPORT_ID_GET_LONG) {
			printf("Unknown report ID\n");
			continue;
		}

		uint16_t page = peek_u16le(&buf[1]), id = peek_u16le(&buf[3]);
		uint32_t usage = page << 16 | id;
		printf("%08x", usage);

		const struct parser_report *r = eizo_monitor_subreport(m, usage);
		if (!r) {
			printf(" unknown usage\n");
			continue;
		}
		size_t rlen = r->report_size / 8 * r->report_count;
		if ((size_t) res < 7 + rlen) {
			printf(" received data too short\n");
			continue;
		}
		if (r->report_size == 16)
			for (size_t i = 0; i + 1 < rlen; i += 2)
				printf(" %04x", peek_u16le(&buf[7 + i]));
		else
			for (size_t i = 0; i < rlen; i++)
				printf(" %02x", buf[7 + i]);
		printf("\n");
	}
}

typedef void (*print_fn)(const char *format, ...) ATTRIBUTE_PRINTF(1, 2);

static int
run(int argc, char *argv[], print_fn output, print_fn error, bool verbose)
{
	const char *name = argv[0];
	const char *usage = "Usage: %s [--brightness [+-]BRIGHTNESS] [--input NAME]"
		" [--restart] [--events]\n";
	static struct option opts[] = {
		{"input", required_argument, NULL, 'i'},
		{"brightness", required_argument, NULL, 'b'},
		{"restart", no_argument, NULL, 'r'},
		{"events", no_argument, NULL, 'e'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},
		{}
	};

	double brightness = NAN;
	bool relative = false, restart = false, events = false;
	const char *port = NULL;
	int c = 0;
	while ((c = getopt_long(argc, argv, "b:i:h", opts, NULL)) != -1)
		switch (c) {
		case 'b':
			relative = *optarg == '+' || *optarg == '-';
			if (sscanf(optarg, "%lf", &brightness) && isfinite(brightness))
				break;
			error("Invalid value: %s\n", optarg);
			error(usage, name);
			return 1;
		case 'i':
			port = optarg;
			break;
		case 'r':
			restart = true;
			break;
		case 'e':
			events = true;
			break;
		case 'h':
			output(usage, name);
			return 0;
		case 'V':
			output(PROGRAM_NAME " " PROGRAM_VERSION "\n");
			return 0;
		default:
			error("Unknown option\n");
			error(usage, name);
			return 1;
		}

	argc -= optind;
	argv += optind;
	if (argc != 0) {
		error(usage, name);
		return 1;
	}

	// This is safe to call repeatedly, it just might reset the locale.
	// It's actually not needed, so we might even leave it out.
	if (hid_init()) {
		error("%ls\n", hid_error(NULL));
		return 1;
	}

	// It should be possible to choose a particular monitor,
	// but it is generally more useful to operate on all of them.
	struct hid_device_info *devs = hid_enumerate(USB_VID_EIZO, 0), *p = devs;
	for (; p; p = p->next) {
		struct eizo_monitor m = {};
		if (!eizo_monitor_open(&m, p)) {
			error("%s\n", m.error);
			continue;
		}

		if (isfinite(brightness)) {
			double prev = 0.;
			if (!eizo_get_brightness(&m, &prev)) {
				error("Failed to get brightness: %s\n", m.error);
			} else {
				double next = relative ? brightness + prev : brightness;
				if (!eizo_set_brightness(&m, next))
					error("Failed to set brightness: %s\n", m.error);
				else if (verbose)
					output("%s %s: brightness: %.2f -> %.2f\n",
						m.product, m.serial, prev, next);
			}
		}
		if (port) {
			uint16_t prev = 0;
			uint16_t next = eizo_resolve_port(&m, port);
			if (!eizo_get_input_port(&m, &prev)) {
				error("Failed to get input port: %s\n", m.error);
			} else if (!strcmp(port, "?")) {
				output("%s %s: input: %s\n",
					m.product, m.serial, eizo_port_to_name(prev));
			} else if (!next) {
				error("Failed to resolve port name: %s\n", port);
			} else {
				if (!eizo_set_input_port(&m, next))
					error("Failed to set input port: %s\n", m.error);
				else if (verbose)
					output("%s %s: input: %s -> %s\n",
						m.product, m.serial, eizo_port_to_name(prev), port);
			}
		}
		if (restart) {
			if (!eizo_restart(&m))
				error("Failed to restart: %s\n", m.error);
			else if (verbose)
				output("%s %s: restart\n", m.product, m.serial);
		}
		if (events) {
			if (!verbose)
				error("Watching events is not possible in this mode\n");
			else if (!eizo_watch(&m))
				error("%s\n", m.error);
		}

		eizo_monitor_close(&m);
	}
	hid_free_enumeration(devs);
	return 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if !defined TRAY

static void
stdio_output(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

static void
stdio_error(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

int
main(int argc, char *argv[])
{
	return run(argc, argv, stdio_output, stdio_error, true);
}

// --- Windows -----------------------------------------------------------------
#elif defined _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <shellapi.h>
#include <powrprof.h>

#include <wchar.h>

static wchar_t *
message_printf(const char *format, va_list ap)
{
	size_t format_wide_len = mbstowcs(NULL, format, 0) + 1;
	wchar_t *format_wide = calloc(format_wide_len, sizeof *format_wide);
	if (!format_wide)
		return NULL;
	mbstowcs(format_wide, format, format_wide_len);

	int message_len = vswprintf(NULL, 0, format_wide, ap) + 1;
	wchar_t *message = calloc(message_len, sizeof *message);
	if (message_len > 0 && message)
		vswprintf(message, message_len, format_wide, ap);

	free(format_wide);
	return message;
}

static void message_output(const char *format, ...) ATTRIBUTE_PRINTF(1, 2);
static void message_error(const char *format, ...) ATTRIBUTE_PRINTF(1, 2);

static void
message_output(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	wchar_t *message = message_printf(format, ap);
	va_end(ap);
	if (message) {
		MessageBox(
			NULL, message, NULL, MB_ICONINFORMATION | MB_OK | MB_APPLMODAL);
		free(message);
	}
}

static void
message_error(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	wchar_t *message = message_printf(format, ap);
	va_end(ap);
	if (message) {
		MessageBox(NULL, message, NULL, MB_ICONERROR | MB_OK | MB_APPLMODAL);
		free(message);
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static struct {
	HWND hwnd;
} g;

enum {
	IDM_QUIT = 1,
	IDM_BRIGHTER,
	IDM_DARKER,
	IDM_INPUT_0,
};

static void
append_monitor(struct eizo_monitor *m, HMENU menu, UINT_PTR base)
{
	wchar_t buf[256] = L"";
	snwprintf(buf, sizeof buf, L"%s %s", m->product, m->serial);
	AppendMenu(menu, MF_STRING | MF_GRAYED, IDM_QUIT, buf);
	AppendMenu(menu, MF_SEPARATOR, 0, NULL);

	double brightness = 0;
	(void) eizo_get_brightness(m, &brightness);

	UINT flags_brighter = MF_STRING;
	if (brightness == 1)
		flags_brighter |= MF_GRAYED;
	UINT flags_darker = MF_STRING;
	if (brightness == 0)
		flags_darker |= MF_GRAYED;

	// XXX: These are some stupid choices.
	AppendMenu(menu, flags_brighter, base + IDM_BRIGHTER, L"Brighter");
	AppendMenu(menu, flags_darker,   base + IDM_DARKER,   L"Darker");
	AppendMenu(menu, MF_SEPARATOR, 0, NULL);

	uint16_t ports[16] = {0}, current = 0;
	eizo_get_input_ports(m, ports, sizeof ports / sizeof ports[0] - 1);
	(void) eizo_get_input_port(m, &current);
	if (!ports[0])
		ports[0] = current;

	// USB-C ports are a bit tricky, they only need to be /displayed/ as such.
	struct eizo_profile_item *item =
		&m->profile[EIZO_PROFILE_KEY_USB_C_INPUT_PORTS];
	for (size_t i = 0; ports[i]; i++) {
		uint8_t usb_c = 0;
		for (size_t u = 0; u < item->len / 2; u++)
			if (ports[i] == peek_u16le(item->data + u * 2))
				usb_c = u + 1;

		if (!usb_c)
			snwprintf(buf, sizeof buf, L"%s", eizo_port_to_name(ports[i]));
		else if (usb_c == 1)
			snwprintf(buf, sizeof buf, L"%s", g_port_names_usb_c[0]);
		else
			snwprintf(buf, sizeof buf, L"%s %u", g_port_names_usb_c[0], usb_c);

		UINT flags = MF_STRING;
		if (ports[i] == current)
			flags |= MF_CHECKED;

		AppendMenu(menu, flags, base + IDM_INPUT_0 + ports[i], buf);
	}
}

static bool
process_any_power_request(void)
{
	if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
		if (ExitWindowsEx(EWX_POWEROFF,
				SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED))
			return true;
		message_error("Shut down request failed.");
		return false;
	}
	if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
		if (SetSuspendState(FALSE, FALSE, FALSE))
			return true;
		message_error("Suspend request failed.");
		return false;
	}
	return true;
}

static void
show_menu(void)
{
	struct hid_device_info *devs = hid_enumerate(USB_VID_EIZO, 0);
	size_t monitors_size = 0, monitors_len = 0;
	for (struct hid_device_info *p = devs; p; p = p->next)
		monitors_size++;

	HMENU popup = CreatePopupMenu();
	struct eizo_monitor *monitors = calloc(monitors_size, sizeof *monitors);
	if (monitors) {
		for (struct hid_device_info *p = devs; p; p = p->next) {
			struct eizo_monitor *m = monitors + monitors_len;
			if (!eizo_monitor_open(m, p))
				continue;

			UINT_PTR base = 0x1000 * ++monitors_len;
			append_monitor(m, popup, base);
			AppendMenu(popup, MF_SEPARATOR, 0, NULL);
		}
	}
	if (!monitors_len) {
		AppendMenu(popup, MF_STRING | MF_GRAYED, 0, L"No monitors found");
		AppendMenu(popup, MF_SEPARATOR, 0, NULL);
	}

	AppendMenu(popup, MF_STRING, IDM_QUIT, L"&Quit");

	UINT flags = TPM_NONOTIFY | TPM_RETURNCMD | TPM_RIGHTBUTTON;
	if (GetSystemMetrics(SM_MENUDROPALIGNMENT) != 0)
		flags |= TPM_RIGHTALIGN;
	else
		flags |= TPM_LEFTALIGN;

	// When invoked using the keyboard,
	// the cursor gets automatically warped to where we want it.
	POINT pt = {};
	GetCursorPos(&pt);

	SetForegroundWindow(g.hwnd);
	UINT id = TrackPopupMenuEx(popup, flags, pt.x, pt.y, g.hwnd, NULL);
	UINT id_monitor = id / 0x1000;
	if (id == IDM_QUIT) {
		PostQuitMessage(0);
	} else if (id_monitor && id_monitor <= monitors_len) {
		struct eizo_monitor *m = &monitors[--id_monitor];
		id = id % 0x1000;
		double brightness = 0.;
		if (id >= IDM_INPUT_0) {
			if (process_any_power_request())
				eizo_set_input_port(m, id - IDM_INPUT_0);
		} else if (id == IDM_BRIGHTER) {
			if (eizo_get_brightness(m, &brightness))
				eizo_set_brightness(m, min(1., brightness + .1));
		} else if (id == IDM_DARKER) {
			if (eizo_get_brightness(m, &brightness))
				eizo_set_brightness(m, max(0., brightness - .1));
		}
	}

	DestroyMenu(popup);
	while (monitors_len--)
		eizo_monitor_close(&monitors[monitors_len]);
	free(monitors);
}

static LRESULT CALLBACK
window_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {
	case WM_APP + 0:
		// We get the mouse events synthesized.
		switch (LOWORD(lParam)) {
		case WM_LBUTTONUP:
		case WM_RBUTTONUP:
			show_menu();
		}
		return 0;
	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

static bool
enable_shutdown_privilege(void)
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	TOKEN_PRIVILEGES tkp = {
		.PrivilegeCount = 1,
		.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED,
	};
	bool result =
		LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid) &&
		AdjustTokenPrivileges(
			hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES) NULL, 0) &&
		GetLastError() != ERROR_NOT_ALL_ASSIGNED;

	CloseHandle(hToken);
	return result;
}

int WINAPI
wWinMain(
	HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	(void) hPrevInstance;
	(void) nCmdShow;

	// Not having a console window is desirable for automation.
	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(pCmdLine, &argc);
	if (*pCmdLine) {
		char **mbargv = calloc(argc + 1, sizeof *mbargv);
		mbargv[0] = calloc(MAX_PATH + 1, sizeof *mbargv[0]);
		GetModuleFileNameA(hInstance, mbargv[0], MAX_PATH);
		for (int i = 0; i < argc; i++) {
			// On conversion error, this ends up being an empty string.
			size_t len = wcstombs(NULL, argv[i], 0) + 1;
			char *mb = mbargv[i + 1] = calloc(len, sizeof *mb);
			wcstombs(mb, argv[i], len);
		}
		return run(argc + 1, mbargv, message_output, message_error, false);
	}
	LocalFree(argv);

	(void) enable_shutdown_privilege();

	// This is actually not needed, so we might even leave it out.
	if (hid_init()) {
		message_error("%ls", hid_error(NULL));
		return 1;
	}

	WNDCLASSEX wc = {
		.cbSize = sizeof wc,
		.lpfnWndProc = window_proc,
		.hInstance = hInstance,
		.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(1)),
		.hCursor = LoadCursor(NULL, IDC_ARROW),
		.hbrBackground = GetSysColorBrush(COLOR_3DFACE),
		.lpszClassName = TEXT(PROGRAM_NAME),
	};
	if (!RegisterClassEx(&wc))
		return 1;

	// We need a window, but it can stay hidden.
	g.hwnd = CreateWindowEx(WS_EX_CONTROLPARENT,
		wc.lpszClassName, TEXT(PROGRAM_NAME), WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, NULL, NULL, hInstance, NULL);
	NOTIFYICONDATA nid = {
		.cbSize = sizeof nid,
		.hWnd = g.hwnd,
		.uID = 0,
		.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
		.uCallbackMessage = WM_APP + 0,
		// TODO(p): LoadIconMetric is suggested for high-DPI displays.
		.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(1)),
		.szTip = TEXT(PROGRAM_NAME),
	};
	if (!Shell_NotifyIcon(NIM_ADD, &nid)) {
		message_error("Failed to add notification area icon.");
		return 1;
	}

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	(void) Shell_NotifyIcon(NIM_DELETE, &nid);
	return msg.wParam;
}

// --- macOS -------------------------------------------------------------------
#elif defined __APPLE__

#include <AppKit/AppKit.h>
#include <AppKit/NSStatusBar.h>
#include <Foundation/Foundation.h>

static void message_output(const char *format, ...) ATTRIBUTE_PRINTF(1, 2);
static void message_error(const char *format, ...) ATTRIBUTE_PRINTF(1, 2);

static void
message_output(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	NSString *message = [[NSString alloc]
		initWithFormat:[NSString stringWithUTF8String: format] arguments:ap];
	va_end(ap);

	NSAlert *alert = [NSAlert new];
	[alert setMessageText:message];
	[alert setAlertStyle:NSAlertStyleInformational];
	// XXX: How to make the OK button the first responder?
	[alert addButtonWithTitle:@"OK"];
	[NSApp activate];
	[alert.window makeKeyAndOrderFront:nil];
	[alert runModal];
}

static void
message_error(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	NSString *message = [[NSString alloc]
		initWithFormat:[NSString stringWithUTF8String: format] arguments:ap];
	va_end(ap);

	NSAlert *alert = [NSAlert new];
	[alert setMessageText:message];
	[alert setAlertStyle:NSAlertStyleCritical];
	[alert addButtonWithTitle:@"OK"];
	[NSApp activate];
	[alert.window makeKeyAndOrderFront:nil];
	[alert runModal];
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

/// Monitor provides reference counting, and enables use of NSArray.
@interface Monitor : NSObject
@property (assign, nonatomic) struct eizo_monitor *monitor;
- (instancetype)initWithMonitor:(struct eizo_monitor *)monitor;
@end

@implementation Monitor

- (instancetype)initWithMonitor:(struct eizo_monitor *)monitor {
	if (self = [super init]) {
		_monitor = monitor;
	}
	return self;
}

- (void)dealloc {
	if (_monitor) {
		eizo_monitor_close(_monitor);
		free(_monitor);
		_monitor = NULL;
	}
}

@end

@interface ApplicationDelegate
	: NSObject <NSApplicationDelegate, NSMenuDelegate>
@property (strong, nonatomic) NSStatusItem *statusItem;
@property (strong, nonatomic) NSMutableArray<Monitor *> *monitors;
@end

@implementation ApplicationDelegate

- (Monitor *)getMonitorFrom:(NSControl *)control {
	NSInteger index = control.tag / 0x1000;
	if (!self.monitors || index < 0 || index >= self.monitors.count)
		return nil;
	return self.monitors[index];
}

- (void)setBrightness:(NSControl *)sender {
	Monitor *m = [self getMonitorFrom:sender];
	if (!m)
		return;
	eizo_set_brightness(m.monitor, sender.doubleValue);
}

- (void)setInputPort:(NSControl *)sender {
	Monitor *m = [self getMonitorFrom:sender];
	NSUInteger input = sender.tag % 0x1000;
	if (!m)
		return;
	eizo_set_input_port(m.monitor, input);

	NSEventModifierFlags mods = [NSEvent modifierFlags];
	if (mods & NSEventModifierFlagShift) {
		NSTask *task = [[NSTask alloc] init];
		task.launchPath = @"/usr/bin/pmset";
		task.arguments = @[@"sleepnow"];
		[task launch];
	}
}

- (void)appendMonitor:(Monitor *)m toMenu:(NSMenu *)menu base:(NSInteger)base {
	NSMenuItem *titleItem = [NSMenuItem new];
	titleItem.attributedTitle = [[NSAttributedString alloc]
		initWithString:[NSString stringWithFormat:@"%s %s",
			m.monitor->product, m.monitor->serial]
		attributes:@{ NSFontAttributeName: [NSFont boldSystemFontOfSize:0] }];
	[menu addItem:titleItem];
	[menu addItem:[NSMenuItem separatorItem]];
	[menu addItem:[NSMenuItem sectionHeaderWithTitle:@"Brightness"]];

	double brightness = 0;
	(void) eizo_get_brightness(m.monitor, &brightness);

	// XXX: So, while having a slider is strictly more useful,
	// this is not something you're supposed to do in AppKit, if only because:
	//  - It does not respond to keyboard.
	//  - Positioning it properly is dark magic.
	NSSlider *slider = [NSSlider
		sliderWithValue:brightness minValue:0. maxValue:1.
		target:self action:@selector(setBrightness:)];
	slider.tag = base;
	slider.continuous = true;

	NSView *sliderView = [[NSView alloc]
		initWithFrame:NSMakeRect(0, 0, 200., slider.knobThickness + 2.)];
	[sliderView addSubview:slider];
	slider.translatesAutoresizingMaskIntoConstraints = false;
	[NSLayoutConstraint activateConstraints:@[
        [slider.leftAnchor
			constraintEqualToAnchor:sliderView.leftAnchor constant:+23.],
        [slider.rightAnchor
			constraintEqualToAnchor:sliderView.rightAnchor constant:-6.],
        [slider.centerYAnchor
			constraintEqualToAnchor:sliderView.centerYAnchor]
    ]];

	NSMenuItem *brightnessItem = [[NSMenuItem alloc]
		initWithTitle:@"" action:nil keyEquivalent:@""];
	brightnessItem.view = sliderView;

	[menu addItem:brightnessItem];
	[menu addItem:[NSMenuItem separatorItem]];
	[menu addItem:[NSMenuItem sectionHeaderWithTitle:@"Input ports"]];

	uint16_t ports[16] = {0}, current = 0;
	eizo_get_input_ports(m.monitor, ports, sizeof ports / sizeof ports[0] - 1);
	(void) eizo_get_input_port(m.monitor, &current);
	if (!ports[0])
		ports[0] = current;

	// USB-C ports are a bit tricky, they only need to be /displayed/ as such.
	struct eizo_profile_item *item =
		&m.monitor->profile[EIZO_PROFILE_KEY_USB_C_INPUT_PORTS];
	for (size_t i = 0; ports[i]; i++) {
		uint8_t usb_c = 0;
		for (size_t u = 0; u < item->len / 2; u++)
			if (ports[i] == peek_u16le(item->data + u * 2))
				usb_c = u + 1;

		NSString *title = nil;
		if (!usb_c)
			title = [NSString stringWithUTF8String:eizo_port_to_name(ports[i])];
		else if (usb_c == 1)
			title = [NSString stringWithUTF8String:g_port_names_usb_c[0]];
		else
			title = [NSString stringWithFormat:@"%s %u",
				g_port_names_usb_c[0], usb_c];

		NSMenuItem *inputPortItem = [[NSMenuItem alloc]
			initWithTitle:title action:@selector(setInputPort:)
			keyEquivalent:@""];
		inputPortItem.tag = base + ports[i];
		if (ports[i] == current)
			inputPortItem.state = NSControlStateValueOn;
		[menu addItem:inputPortItem];
	}
}

- (void)showMenu {
	struct hid_device_info *devs = hid_enumerate(USB_VID_EIZO, 0);
	NSMutableArray<Monitor *> *monitors = [NSMutableArray array];
	NSMenu *menu = [NSMenu new];
	[menu setDelegate:self];
	for (struct hid_device_info *p = devs; p; p = p->next) {
		struct eizo_monitor *m = calloc(1, sizeof *m);
		if (!m)
			continue;

		if (!eizo_monitor_open(m, p)) {
			message_error("%s", m->error);
			free(m);
			continue;
		}

		Monitor *monitor = [[Monitor alloc] initWithMonitor:m];
		[self appendMonitor:monitor toMenu:menu base:0x1000 * monitors.count];
		[menu addItem:[NSMenuItem separatorItem]];
		[monitors addObject:monitor];
	}
	if (!monitors.count) {
		NSMenuItem *item = [[NSMenuItem alloc]
			initWithTitle:@"No monitors found" action:nil keyEquivalent:@""];
		item.enabled = false;
		[menu addItem:item];
	}

	[menu addItem:[NSMenuItem separatorItem]];
	[menu addItem:[[NSMenuItem alloc]
		initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"]];

	self.monitors = monitors;

	// XXX: Unfortunately, this is not how menus should behave,
	// but we really want to generate the menu on demand.
	self.statusItem.menu = menu;
	[self.statusItem.button performClick:nil];
	self.statusItem.menu = nil;
}

- (void)menuDidClose:(NSMenu *)menu {
	// Close and free up the devices as soon as possible, but no sooner.
	dispatch_async(dispatch_get_main_queue(), ^{
		self.monitors = nil;
	});
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	NSStatusBar *systemBar = [NSStatusBar systemStatusBar];
	self.statusItem = [systemBar statusItemWithLength:NSSquareStatusItemLength];
	if (!self.statusItem.button)
		return;

	// Not bothering with templates,
	// the icon would need to have a hole through it to look better.
	NSImage *image = [NSApp applicationIconImage];
	// One would expect the status bar to pick a reasonable size
	// automatically, but that is not what happens.
	image.size = NSMakeSize(systemBar.thickness, systemBar.thickness);
	self.statusItem.button.image = image;
	self.statusItem.button.action = @selector(showMenu);
}

@end

int
main(int argc, char *argv[])
{
	@autoreleasepool {
		if (argc > 1)
			return run(argc, argv, message_output, message_error, true);

		NSApplication *app = [NSApplication sharedApplication];
		ApplicationDelegate *delegate = [ApplicationDelegate new];
		app.delegate = delegate;
		[app setActivationPolicy:NSApplicationActivationPolicyAccessory];
		[app run];
	}
	return 0;
}

#endif
