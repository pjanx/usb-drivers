/*
 * elksmart-comm.c: ELK Smart infrared dongle tool (for EKX4S and EKX5S-T)
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

#include "config.h"
#undef PROGRAM_NAME
#define PROGRAM_NAME "elksmart-comm"
#include "liberty/liberty.c"

#include <libusb.h>

// --- Utilities ---------------------------------------------------------------

/// Search for a device with given vendor and product ID.
/// This is quite similar to libusb_open_device_with_vid_pid().
static libusb_device_handle *
find_device (int vendor, int product, int *error)
{
	libusb_device **list = NULL;
	libusb_device_handle *handle = NULL;
	int result = 0;

	ssize_t len = libusb_get_device_list (NULL, &list);
	if (len < 0)
	{
		result = len;
		goto out;
	}

	for (ssize_t i = 0; i < len; i++)
	{
		libusb_device *device = list[i];
		struct libusb_device_descriptor desc = {};
		if ((result = libusb_get_device_descriptor (device, &desc)))
			print_debug ("%s", libusb_strerror (result));
		else if (desc.idVendor != vendor || desc.idProduct != product)
			continue;
		else if (!(result = libusb_open (device, &handle)))
			break;
	}

	libusb_free_device_list (list, true);
out:
	if (error != NULL && result != 0)
		*error = result;
	return handle;
}

static void
wait_ms (long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000 * 1000 };
	nanosleep (&ts, NULL);
}

static void
dump_hex (const unsigned char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf ("%02x", buf[i]);
	printf ("\n");
}

static bool
read_hex (const char *string, struct str *out)
{
	static const char *alphabet = "0123456789abcdef";
	str_reset (out);
	while (true)
	{
		while (*string && strchr (" \t\n\r\v\f", *string))
			string++;
		if (!*string)
			return true;

		const char *hi, *lo;
		if (!(hi = strchr (alphabet, tolower_ascii (*string++))) || !*string
		 || !(lo = strchr (alphabet, tolower_ascii (*string++))))
			return false;

		str_pack_u8 (out, (hi - alphabet) << 4 | (lo - alphabet));
	}
}

// --- Coding ------------------------------------------------------------------

// Values are in microseconds.
struct pulse { unsigned on, off; };

static bool
pulse_equal (struct pulse a, struct pulse b)
{
	return a.on == b.on && a.off == b.off;
}

static size_t
decode_learned_direct (const uint8_t *b, size_t b_len, struct pulse *pulses)
{
	size_t pulses_len = 0;
	for (size_t i = 0; i < b_len; )
	{
		struct pulse *pulse = &pulses[pulses_len++];
		while (b[i] == 0xff)
		{
			pulse->on += 4080;
			if (++i == b_len)
				return 0;
		}
		pulse->on += b[i++] * 16;

		// Who cares, presumably it stays off.
		if (i == b_len)
			break;

		while (b[i] == 0xff)
		{
			pulse->off += 4080;
			if (++i == b_len)
				return 0;
		}
		pulse->off += b[i++] * 16;
	}
	return pulses_len;
}

static struct pulse *
decode_learned (const struct str *code, size_t *len, struct error **e)
{
	// This conveniently has an upper bound.
	struct pulse *pulses = xcalloc (code->len, sizeof *pulses);
	if (!(*len = decode_learned_direct
		((const uint8_t *) code->str, code->len, pulses)))
	{
		error_set (e, "code ends unexpectedly");
		free (pulses);
		return NULL;
	}
	return pulses;
}

static struct pulse *
encode_nec_byte (struct pulse *p, uint8_t byte)
{
	for (int i = 7; i >= 0; i--)
		*p++ = (struct pulse)
			{ .on = 550, .off = ((byte >> i) & 1) ? 1650 : 550 };
	return p;
}

static struct pulse *
encode_nec (const struct str *code, size_t *len, struct error **e)
{
	if (code->len % 2)
	{
		error_set (e, "NEC transmission format requires pairs");
		return NULL;
	}

	// The timings seem to be rather tolerant.
	*len = code->len / 2 * (1 /* leader */ + 32 + 1 /* stop */);
	struct pulse *pulses = xcalloc (*len, sizeof *pulses), *p = pulses;
	for (size_t i = 0; i < code->len; i += 2)
	{
		*p++ = (struct pulse) { .on = 8500, .off = 4250 };
		p = encode_nec_byte (p, code->str[i + 0]);
		p = encode_nec_byte (p, ~code->str[i + 0]);
		p = encode_nec_byte (p, code->str[i + 1]);
		p = encode_nec_byte (p, ~code->str[i + 1]);
		*p++ = (struct pulse) { .on = 550, .off = 25000 };
	}
	return pulses;
}

static void
compress_value (unsigned value, struct str *encoded)
{
	if (value <= 2032)
	{
		// We fix a minor problem in the original Ocrustar algorithm.
		uint8_t v = value / 16. + .5;
		str_pack_u8 (encoded, MAX (2, v));
	}
	else
		do
		{
			uint8_t v = value & 0x7f;
			if ((value >>= 7))
				v |= 0x80;
			str_pack_u8 (encoded, v);
		} while (value);
}

static void
compress_pulses (const struct pulse *pulses, size_t len, struct str *encoded)
{
	unsigned counts[len];
	memset (counts, 0, sizeof counts);
	for (size_t i = 0; i < len; i++)
		for (size_t k = 0; k < len; k++)
			if (pulse_equal (pulses[i], pulses[k]))
				counts[i]++;

	struct pulse p1 = {}, p2 = {};
	size_t top1 = 0, top2 = 0;
	for (size_t i = 0; i < len; i++)
		if (counts[i] > counts[top1])
			p1 = pulses[top1 = i];
	for (size_t i = 0; i < len; i++)
		if (counts[i] < counts[top1]
		 && counts[i] > counts[top2])
			p2 = pulses[top2 = i];
		else if (counts[top2] == counts[top1])
			p2 = pulses[top2 = i];

	// Although I haven't really tried it, something tells me that
	// this will work even in the degenerated case of len <= 2.
	// XXX: The receiver might not like multibyte values here,
	//   Ocrustar also oddly replaces 0xff with 0xfe for these fields.
	compress_value (p2.on, encoded);
	compress_value (p2.off, encoded);
	compress_value (p1.on, encoded);
	compress_value (p1.off, encoded);
	str_pack_u8 (encoded, -1);
	str_pack_u8 (encoded, -1);
	str_pack_u8 (encoded, -1);

	for (size_t i = 0; i < len; i++)
	{
		if (pulse_equal (pulses[i], p1))
			str_pack_u8 (encoded, 0);
		else if (pulse_equal (pulses[i], p2))
			str_pack_u8 (encoded, 1);
		else
		{
			compress_value (pulses[i].on, encoded);
			compress_value (pulses[i].off, encoded);
		}
	}
}

// --- Device interaction ------------------------------------------------------

enum
{
	USB_VENDOR_SMTCTL = 0x045c,

	// 0x134 (EKX5S ~ 5s, 5th generation remote)
	// 0x195 (EKX4S ~ 4s, 4th generation remote)
	// 0x184 (EKX5S-T, international edition)
	USB_PRODUCT_SMTCTL_SMART_EKX4S = 0x0195,
	USB_PRODUCT_SMTCTL_SMART_EKX5S_T = 0x0184,

	// There should only ever be one interface.
	USB_INTERFACE = 0,
};

static uint8_t
	c_transmit[] = { -1, -1, -1, -1 },
	c_learn[]    = { -2, -2, -2, -2 },
	c_stop[]     = { -3, -3, -3, -3 },
	c_identify[] = { -4, -4, -4, -4 };

static struct
{
	unsigned char endpoint_out;         ///< Outgoing endpoint
	unsigned char endpoint_in;          ///< Incoming endpoint
}
g;

static bool
init_device_from_desc (struct libusb_config_descriptor *desc, struct error **e)
{
	// We're not being particuarly strict in here.
	if (desc->bNumInterfaces != 1)
		return error_set (e, "unexpected USB interface count");
	if (desc->interface->num_altsetting != 1)
		return error_set (e, "unexpected alternate setting count");

	const struct libusb_interface_descriptor *asd = desc->interface->altsetting;
	if (asd->bInterfaceClass != LIBUSB_CLASS_COMM)
		return error_set (e, "unexpected USB interface class");
	if (asd->bNumEndpoints != 2)
		return error_set (e, "unexpected endpoint count");

	bool have_out = false, have_in = false;
	for (uint8_t i = 0; i < asd->bNumEndpoints; i++)
	{
		const struct libusb_endpoint_descriptor *epd = asd->endpoint + i;
		if ((epd->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
			!= LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK)
			return error_set (e, "unexpected endpoint transfer type");

		switch ((epd->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK))
		{
		break; case LIBUSB_ENDPOINT_OUT:
			have_out = true;
			g.endpoint_out = epd->bEndpointAddress;
		break; case LIBUSB_ENDPOINT_IN:
			have_in = true;
			g.endpoint_in = epd->bEndpointAddress;
		}
	}
	if (!have_out || !have_in)
		return error_set (e, "USB interface is not bidirectional");
	return true;
}

static bool
init_device (libusb_device_handle *device, struct error **e)
{
	struct libusb_config_descriptor *desc = NULL;
	int result =
		libusb_get_active_config_descriptor (libusb_get_device (device), &desc);
	if (result)
		return error_set (e, "%s", libusb_strerror (result));

	bool ok = true;
	if ((result = libusb_kernel_driver_active (device, USB_INTERFACE)) == 1)
		ok = error_set (e, "device is claimed by a kernel driver");
	else if (result)
		ok = error_set (e, "%s", libusb_strerror (result));
	else
		ok = init_device_from_desc (desc, e);

	libusb_free_config_descriptor (desc);
	return ok;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static uint8_t
mangle (uint8_t value)
{
	uint8_t reversed = 0;
	for (int i = 0; i < 8; i++)
	{
		reversed = (reversed << 1) | (value & 1);
		value >>= 1;
	}
	return ~reversed;
}

static uint8_t
checksum (const uint8_t *b, size_t len)
{
	uint32_t sum = 0;
	for (size_t i = 0; i < len; i++)
		sum += b[i];
	return mangle ((sum & 0xF0) | ((sum >> 8) & 0x0F));
}

static bool
send_transmit (libusb_device_handle *device, unsigned long frequency,
	const struct pulse *pulses, size_t pulses_len, struct error **e)
{
	if (g_debug_mode)
		for (size_t i = 0; i < pulses_len; )
		{
			printf ("%u,%u", pulses[i].on, pulses[i].off);
			putchar (++i == pulses_len ? '\n' : ',');
		}

	struct str compressed = str_make ();
	compress_pulses (pulses, pulses_len, &compressed);

	struct str message = str_make ();
	str_append_data (&message, c_transmit, sizeof c_transmit);
	frequency += 0x7ffff;
	str_pack_u8 (&message, mangle (frequency >> 8));
	str_pack_u8 (&message, mangle (frequency >> 16));
	str_pack_u8 (&message, mangle (frequency));
	str_pack_u8 (&message, mangle (compressed.len >> 8));
	str_pack_u8 (&message, mangle (compressed.len));
	str_append_str (&message, &compressed);
	str_free (&compressed);

	size_t i = 0;
	uint8_t buffer[64];
	bool ok = true;
	while (i != message.len)
	{
		size_t chunk = MIN (62, message.len - i);
		memcpy (buffer, message.str + i, chunk);
		i += chunk;
		if (chunk == 62)
		{
			buffer[chunk] = checksum (buffer, chunk);
			chunk++;
		}

		int result = 0, len = 0;
		if ((result = libusb_bulk_transfer (device, g.endpoint_out,
			buffer, chunk, &len, 100)))
		{
			ok = error_set (e, "send: %s", libusb_strerror (result));
			break;
		}
		wait_ms (2);
	}
	str_free (&message);
	return ok;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
pulse_is_likely_leader (const struct pulse *p)
{
	return p->on >= 2048 && p->off >= 2048;
}

static void
try_to_depulse (const struct str *code)
{
	size_t len = 0;
	struct pulse *pulses = decode_learned (code, &len, NULL);
	if (!pulses)
		return;

	struct pulse *p = pulses, *end = p + len;
	while (p != end && pulse_is_likely_leader (p))
	{
		p++;
		printf ("Attempted pulse decode:\n");

		uint8_t bits = 0, nibble = 0;
		for (; p != end && !pulse_is_likely_leader (p); p++)
		{
			nibble = nibble << 1 | (p->off > 2 * p->on);
			if (++bits == 4)
			{
				putchar ("0123456789abcdef"[nibble]);
				bits = nibble = 0;
			}
		}
		putchar ('\n');
	}
	free (pulses);
}

static bool
recv_learn (libusb_device_handle *device, struct str *data, struct error **e)
{
	uint8_t buffer[64] = {};
	int result = 0, len = 0;
	while ((result = libusb_bulk_transfer (device, g.endpoint_in,
		buffer, sizeof buffer, &len, 100)))
	{
		if (result != LIBUSB_ERROR_TIMEOUT)
			return error_set (e, "learn/recv: %s", libusb_strerror (result));
		print_debug ("learn/recv: %s", libusb_strerror (result));
	}
	if (len < 6 || memcmp (buffer, c_learn, sizeof c_learn))
		return error_set (e, "learn/recv: %s", "unexpected response");

	// This field might only make sense for a later device,
	// because it doesn't always correspond with how much data we receive.
	// Nonetheless, it does match exactly often enough.
	size_t size = buffer[4] << 8 | buffer[5];
	print_debug ("learn: code size: %zu", size);

	str_append_data (data, buffer + 6, len - 6);
	dump_hex ((const unsigned char *) data->str, data->len);
	while (data->len < size)
	{
		if (!(result = libusb_bulk_transfer (device, g.endpoint_in,
			buffer, sizeof buffer, &len, 100)))
		{
			dump_hex (buffer, len);

			str_append_data (data, buffer, len);
			print_debug ("learn: received %d (have %zu of %zu)",
				len, data->len, size);
			continue;
		}
		if (result != LIBUSB_ERROR_TIMEOUT)
			return error_set (e, "learn/recv: %s", libusb_strerror (result));

		// The device seems to queue up its output with pauses.
		print_debug ("learn/recv: %s", libusb_strerror (result));
	}

	// As far as I know, this doesn't do anything,
	// and the device doesn't accept it while scanning infrared codes either.
	if ((result = libusb_bulk_transfer (device, g.endpoint_out,
		c_stop, sizeof c_stop, &len, 100)))
		return error_set (e, "learn/send: %s", libusb_strerror (result));
	return true;
}

static bool
send_learn (libusb_device_handle *device, struct error **e)
{
	int result = 0, len = 0;
	if ((result = libusb_bulk_transfer (device, g.endpoint_out,
		c_learn, sizeof c_learn, &len, 100)))
		return error_set (e, "learn/send: %s", libusb_strerror (result));

	printf ("Reading remote control codes.\n");
	printf ("Press a remote control button from less than a centimeter.\n");
	printf ("The dongle may be unusable until it returns some data.\n");
	// ... Resetting the device using libusb_reset_device() doesn't help then.
	printf ("If the code fails to replay, retry the capture.\n");

	struct str data = str_make ();
	bool ok = recv_learn (device, &data, e);
	if (ok)
	{
		printf ("Full command:\n");
		dump_hex ((const unsigned char *) data.str, data.len);
		try_to_depulse (&data);
	}

	str_free (&data);
	return ok;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
send_identify (libusb_device_handle *device, struct error **e)
{
	uint8_t buffer[64] = {};
	int result = 0, len = 0;
	while (!(result = libusb_bulk_transfer (device, g.endpoint_in,
		buffer, sizeof buffer, &len, 10)))
		/* Flush buffers. */;

	if ((result = libusb_bulk_transfer (device, g.endpoint_out,
		c_identify, sizeof c_identify, &len, 100)))
		return error_set (e, "identify/send: %s", libusb_strerror (result));
	if ((result = libusb_bulk_transfer (device, g.endpoint_in,
		buffer, sizeof buffer, &len, 100)))
		return error_set (e, "identify/recv: %s", libusb_strerror (result));

	// XXX: Sometimes, the device doesn't send any identification values.
	if (len != 6 || memcmp (buffer, c_identify, sizeof c_identify)
	 || buffer[4] != 0x70 || buffer[5] != 0x01)
		return error_set (e, "device busy or not supported");

#if 0
	// The EKX4S does not respond to this request.
	static uint8_t c_serial[] = { -5, -5, -5, -5 };
	if ((result = libusb_bulk_transfer (device, g.endpoint_out,
		c_serial, sizeof c_serial, &len, 100)))
		return error_set (e, "serial/send: %s", libusb_strerror (result));
	if ((result = libusb_bulk_transfer (device, g.endpoint_in,
		buffer, sizeof buffer, &len, 100)))
		return error_set (e, "serial/recv: %s", libusb_strerror (result));
	if (len < (int) sizeof c_serial
	 || memcmp (buffer, c_serial, sizeof c_serial))
		return error_set (e, "serial retrieval failed");
#endif
	return true;
}

static bool
run (libusb_device_handle *device, unsigned long frequency, bool nec,
	char **codes, size_t codes_len, struct error **e)
{
	if (!send_identify (device, e))
		return false;
	if (!codes_len)
		return send_learn (device, e);

	struct str code = str_make ();
	bool ok = true;
	for (size_t i = 0; i < codes_len; i++)
	{
		if (!read_hex (codes[i], &code))
		{
			ok = error_set (e, "invalid hex string");
			break;
		}

		size_t pulses_len = 0;
		struct pulse *pulses = nec
			? encode_nec (&code, &pulses_len, e)
			: decode_learned (&code, &pulses_len, e);

		ok = pulses && send_transmit (device, frequency, pulses, pulses_len, e);
		free (pulses);
		if (!ok)
			break;

		wait_ms (100);
	}
	str_free (&code);
	return ok;
}

// --- Main --------------------------------------------------------------------

int
main (int argc, char *argv[])
{
	unsigned long frequency = 38000;
	bool nec = false;
	static const struct opt opts[] =
	{
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'f', "frequency", "HZ", 0, "frequency (38000 Hz by default)" },
		{ 'n', "nec", NULL, 0, "use the NEC transmission format" },
		{ 'h', "help", NULL, 0, "display this help and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh = opt_handler_make (argc, argv, opts, "[COMMAND...]",
		"Transmit or receive infrared commands.");

	int c;
	while ((c = opt_handler_get (&oh)) != -1)
	switch (c)
	{
	case 'd':
		g_debug_mode = true;
		break;
	case 'f':
		if (!xstrtoul (&frequency, optarg, 10) || !frequency)
			exit_fatal ("invalid frequency");
		break;
	case 'n':
		nec = true;
		break;
	case 'h':
		opt_handler_usage (&oh, stdout);
		exit (EXIT_SUCCESS);
	case 'V':
		printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
		exit (EXIT_SUCCESS);
	default:
		print_error ("wrong options");
		opt_handler_usage (&oh, stderr);
		exit (EXIT_FAILURE);
	}

	argc -= optind;
	argv += optind;

	opt_handler_free (&oh);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#if LIBUSB_API_VERSION >= 0x0100010A
	const struct libusb_init_option option =
	{
		.option = LIBUSB_OPTION_LOG_LEVEL,
		.value.ival = LIBUSB_LOG_LEVEL_DEBUG,
	};
	int result = libusb_init_context (NULL, &option, g_debug_mode);
#else
	int result = libusb_init (NULL);
#endif
	if (result)
		exit_fatal ("libusb: %s", libusb_strerror (result));

	libusb_device_handle *device = NULL;
	if (!device && !result)
		device = find_device (USB_VENDOR_SMTCTL,
			USB_PRODUCT_SMTCTL_SMART_EKX4S, &result);
	if (!device && !result)
		device = find_device (USB_VENDOR_SMTCTL,
			USB_PRODUCT_SMTCTL_SMART_EKX5S_T, &result);

	if (result)
		exit_fatal ("couldn't open device: %s", libusb_strerror (result));
	else if (!device)
		exit_fatal ("no suitable device found");

	struct error *e = NULL;
	if (!init_device (device, &e))
		exit_fatal ("%s", e->message);
	if ((result = libusb_claim_interface (device, USB_INTERFACE)) == 1)
		exit_fatal ("couldn't claim interface: %s", libusb_strerror (result));

	if (!run (device, frequency, nec, argv, argc, &e))
	{
		print_error ("%s", e->message);
		error_free (e);
	}

	if ((result = libusb_release_interface (device, USB_INTERFACE)) == 1)
		exit_fatal ("couldn't release interface: %s", libusb_strerror (result));

	libusb_close (device);
	libusb_exit (NULL);
	return 0;
}
