/*
 * razer-bw-te-ctl.c: Razer BlackWidow Tournament Edition control utility
 *
 * Everything has been reverse-engineered via Wireshark/usbmon and VirtualBox.
 *
 * Copyright (c) 2013, Přemysl Eric Janouch <p@janouch.name>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <getopt.h>
#include <strings.h>
#include <libusb.h>

#include "config.h"
#undef PROGRAM_NAME
#define PROGRAM_NAME "razer-bw-te-ctl"

// --- Utilities ---------------------------------------------------------------

/// Search for a device with given vendor and product ID.
/// This is quite similar to libusb_open_device_with_vid_pid().
static libusb_device_handle *
find_device(int vendor, int product, int *error)
{
	libusb_device **list = NULL;
	libusb_device_handle *handle = NULL;
	int result = 0;

	ssize_t len = libusb_get_device_list(NULL, &list);
	if (len < 0) {
		result = len;
		goto out;
	}

	for (ssize_t i = 0; i < len; i++) {
		libusb_device *device = list[i];
		struct libusb_device_descriptor desc = {};
		if ((result = libusb_get_device_descriptor(device, &desc)))
			(void) libusb_strerror(result);
		else if (desc.idVendor != vendor || desc.idProduct != product)
			continue;
		else if (!(result = libusb_open(device, &handle)))
			break;
	}

	libusb_free_device_list(list, true);
out:
	if (error != NULL && result != 0)
		*error = result;
	return handle;
}

// --- Device configuration ----------------------------------------------------

enum {
	USB_VENDOR_RAZER = 0x1532,
	USB_PRODUCT_RAZER_BW_TE = 0x011c,

	USB_GET_REPORT = 0x01,
	USB_SET_REPORT = 0x09,

	BW_CTL_IFACE = 0,
};

/// Razer logo backlight mode.
enum bw_led_mode {
	LED_BRIGHTNESS = 0,
	LED_BLINK,
	LED_PULSATE
};

/// Overall device configuration.
struct bw_config {
	enum bw_led_mode led_mode;
	unsigned led_brightness;
	unsigned macro_led_on        : 1;
	unsigned macro_led_blinking  : 1;
	unsigned gaming_mode         : 1;
};

/// Send a command to the mouse via SET_REPORT.
static int
bw_send_command(
	libusb_device_handle *device, unsigned char *data, uint16_t length)
{
	unsigned char packet[90] = {0x00};
	assert(length <= sizeof packet - 5);
	memcpy(packet + 5, data, length);

	unsigned char checksum = 0;
	while (length--)
		checksum ^= data[length];
	packet[sizeof packet - 2] = checksum;

	// XXX: wIndex should actually be 0x0002 but that doesn't work.
	int result = libusb_control_transfer(device, LIBUSB_ENDPOINT_OUT |
		LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE,
		USB_SET_REPORT, 0x0300, 0x0000, packet, sizeof packet, 0);
	return result < 0 ? result : 0;
}

/// Set Razer logo backlight mode.
static int
bw_set_led_mode(libusb_device_handle *device, enum bw_led_mode mode)
{
	unsigned char cmd[] = {0x03, 0x03, 0x02, 0x01, 0x04, mode};
	return bw_send_command(device, cmd, sizeof cmd);
}

/// Set Razer logo backlight brightness.
static int
bw_set_led_brightness(libusb_device_handle *device, unsigned char brightness)
{
	unsigned char cmd[] = {0x03, 0x03, 0x03, 0x01, 0x04, brightness};
	return bw_send_command(device, cmd, sizeof cmd);
}

/// Set the on/off state of the macro LED.
static int
bw_set_macro_led(libusb_device_handle *device, bool on)
{
	unsigned char cmd[] = {0x03, 0x03, 0x00, 0x00, 0x07, on};
	return bw_send_command(device, cmd, sizeof cmd);
}

/// Set whether the macro LED should blink.
static int
bw_set_macro_led_blinking(libusb_device_handle *device, bool blinking)
{
	unsigned char cmd[] = {0x03, 0x03, 0x02, 0x00, 0x07, blinking};
	return bw_send_command(device, cmd, sizeof cmd);
}

/// Set the gaming mode (whether the Windows key should be ignored).
static int
bw_set_gaming_mode(libusb_device_handle *device, bool on)
{
	unsigned char cmd[] = {0x03, 0x03, 0x00, 0x01, 0x08, on};
	return bw_send_command(device, cmd, sizeof cmd);
}

// --- Control utility ---------------------------------------------------------

struct options {
	unsigned set_led_mode            : 1;
	unsigned set_led_brightness      : 1;
	unsigned set_macro_led_on        : 1;
	unsigned set_macro_led_blinking  : 1;
	unsigned set_gaming_mode         : 1;
};

static void
show_usage(const char *program_name)
{
	printf("Usage: %s [OPTION]...\n", program_name);
	printf("Configure Razer BlackWidow Tournament Edition devices.\n\n");
	printf("  -h, --help          Show this help\n");
	printf("  --version           Show program version and exit\n");
	printf("  --led-mode X        Set the mode of the Razer logo LED"
								" (can be 'normal', 'blink' or 'pulsate')\n");
	printf("  --led-brightness X  Set Razer logo LED brightness"
								" (from 0 to 255)\n");
	printf("  --macro-led X       Set the macro LED mode"
								" ('off', 'on' or 'blink')\n");
	printf("  --gaming-mode BOOL  Set whether the Windows key is ignored\n");
	printf("\n");
}

static void
parse_options(int argc, char *argv[],
	struct options *options, struct bw_config *new_config)
{
	static struct option long_opts[] = {
		{"help",           no_argument,       0, 'h'},
		{"version",        no_argument,       0, 'V'},
		{"led-mode",       required_argument, 0, 'l'},
		{"led-brightness", required_argument, 0, 'L'},
		{"macro-led",      required_argument, 0, 'm'},
		{"gaming-mode",    required_argument, 0, 'g'},
		{0}
	};

	if (argc == 1) {
		show_usage (argv[0]);
		exit (EXIT_FAILURE);
	}

	int c;
	while ((c = getopt_long(argc, argv, "h", long_opts, NULL)) != -1)
	switch (c) {
	case 'h':
		show_usage(argv[0]);
		exit(EXIT_SUCCESS);
	case 'V':
		printf(PROGRAM_NAME " " PROGRAM_VERSION "\n");
		exit(EXIT_SUCCESS);
	case 'l':
		if (!strcasecmp(optarg, "normal")) {
			new_config->led_mode = LED_BRIGHTNESS;
		} else if (!strcasecmp(optarg, "blink")) {
			new_config->led_mode = LED_BLINK;
		} else if (!strcasecmp(optarg, "pulsate")) {
			new_config->led_mode = LED_PULSATE;
		} else {
			fprintf(stderr, "Error: invalid LED mode: %s\n", optarg);
			exit(EXIT_FAILURE);
		}
		options->set_led_mode = true;
		break;
	case 'L': {
		char *end;
		long bri = strtol(optarg, &end, 10);
		if (!*optarg || *end || bri < 0 || bri > 255) {
			fprintf(stderr, "Error: invalid LED brightness value\n");
			exit(EXIT_FAILURE);
		}
		options->set_led_brightness = true;
		break;
	}
	case 'm':
		if (!strcasecmp(optarg, "off")) {
			new_config->macro_led_on = false;
			new_config->macro_led_blinking = false;
		} else if (!strcasecmp(optarg, "blink")) {
			new_config->macro_led_on = true;
			new_config->macro_led_blinking = true;
		} else if (!strcasecmp(optarg, "on")) {
			new_config->macro_led_on = true;
			new_config->macro_led_blinking = false;
		} else {
			fprintf(stderr, "Error: invalid macro LED mode: %s\n", optarg);
			exit(EXIT_FAILURE);
		}
		options->set_macro_led_blinking = true;
		options->set_macro_led_on = true;
		break;
	case 'g':
		if (!strcasecmp(optarg, "true") ||
			!strcasecmp(optarg, "on") ||
			!strcasecmp(optarg, "yes")) {
			new_config->gaming_mode = true;
		} else if (!strcasecmp (optarg, "false") ||
			!strcasecmp(optarg, "off") ||
			!strcasecmp(optarg, "no")) {
			new_config->gaming_mode = false;
		} else {
			fprintf(stderr, "Error: invalid gaming mode"
				" setting: %s\n", optarg);
			exit(EXIT_FAILURE);
		}
		options->set_gaming_mode = true;
		break;
	case '?':
		exit(EXIT_FAILURE);
	}

	if (optind < argc) {
		fprintf(stderr, "Error: extra parameters\n");
		exit(EXIT_FAILURE);
	}
}

static int
apply_options(libusb_device_handle *device,
	struct options *options, struct bw_config *new_config)
{
	int result = 0;

	if (options->set_led_mode)
		if ((result = bw_set_led_mode(
				device, new_config->led_mode)))
			return result;
	if (options->set_led_brightness)
		if ((result = bw_set_led_brightness(
				device, new_config->led_brightness)))
			return result;

	if (options->set_macro_led_on)
		if ((result = bw_set_macro_led(
				device, new_config->macro_led_on)))
			return result;
	if (options->set_macro_led_blinking)
		if ((result = bw_set_macro_led_blinking(
				device, new_config->macro_led_blinking)))
			return result;

	if (options->set_gaming_mode)
		if ((result = bw_set_gaming_mode(
				device, new_config->gaming_mode)))
			return result;

	return 0;
}

#define ERROR(label, ...)                        \
	do {                                         \
		fprintf(stderr, "Error: " __VA_ARGS__);  \
		status = 1;                              \
		goto label;                              \
	} while (0)

int
main(int argc, char *argv[])
{
	struct options options = {0};
	struct bw_config new_config = {0};

	parse_options(argc, argv, &options, &new_config);

	int result, status = 0;
	if ((result = libusb_init(NULL)))
		ERROR(error_0, "libusb initialisation failed: %s\n",
			libusb_error_name(result));

	result = 0;
	libusb_device_handle *device =
		find_device(USB_VENDOR_RAZER, USB_PRODUCT_RAZER_BW_TE, &result);
	if (!device) {
		if (result)
			ERROR(error_1, "couldn't open device: %s\n",
				libusb_error_name(result));
		else
			ERROR(error_1, "no suitable device found\n");
	}

	bool reattach_driver = false;
	switch ((result = libusb_kernel_driver_active(device, BW_CTL_IFACE))) {
	case 0:
	case LIBUSB_ERROR_NOT_SUPPORTED:
		break;
	case 1:
		reattach_driver = true;
		if ((result = libusb_detach_kernel_driver(device, BW_CTL_IFACE)))
			ERROR(error_2, "couldn't detach kernel driver: %s\n",
				libusb_error_name(result));
		break;
	default:
		ERROR(error_2, "coudn't detect kernel driver presence: %s\n",
			libusb_error_name(result));
	}

	if ((result = libusb_claim_interface(device, BW_CTL_IFACE)))
		ERROR(error_3, "couldn't claim interface: %s\n",
			libusb_error_name(result));

	if ((result = apply_options(device, &options, &new_config)))
		ERROR(error_4, "operation failed: %s\n",
			libusb_error_name (result));
error_4:
	if ((result = libusb_release_interface(device, BW_CTL_IFACE)))
		ERROR(error_3, "couldn't release interface: %s\n",
			libusb_error_name(result));
error_3:
	if (reattach_driver) {
		if ((result = libusb_attach_kernel_driver(device, BW_CTL_IFACE)))
			ERROR(error_2, "couldn't reattach kernel driver: %s\n",
				libusb_error_name(result));
	}

error_2:
	libusb_close(device);
error_1:
	libusb_exit(NULL);
error_0:
	return status;
}
