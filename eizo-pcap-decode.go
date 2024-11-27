// Usage: tshark { -r FILE | -i INTERFACE } -l -T ek --disable-protocol usbhid \
// | go run eizo-pcap-decode.go [ | less -R]
//
// This cannot be done through -T json, because tshark doesn't immediately
// flush the current object's trailing newline, but rather waits to decide
// if it should follow it with a comma. Even with -l, it will flush it late.
// It would be good if we could convince it not to wrap packets in a big array.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type Packet struct {
	Layers struct {
		USB struct {
			Source          string `json:"usb_usb_src"`
			Destination     string `json:"usb_usb_dst"`
			Direction       string `json:"usb_usb_endpoint_address_direction"`
			MacEndpointType string `json:"usb_usb_darwin_endpoint_type"`
			TransferType    string `json:"usb_usb_transfer_type"`
		} `json:"usb"`
		CapData         string `json:"usb_usb_capdata"`
		ControlResponse string `json:"usb_usb_control_Response"`
		DataFragment    string `json:"usb_usb_data_fragment"`
	} `json:"layers"`
}

func (p *Packet) addr() string {
	if p.Layers.USB.Source == "host" {
		return p.Layers.USB.Destination
	} else {
		return p.Layers.USB.Source
	}
}

func (p *Packet) isInterrupt() bool {
	return p.Layers.USB.MacEndpointType == "3" ||
		p.Layers.USB.TransferType == "0x01"
}

func (p *Packet) isControl() bool {
	return p.Layers.USB.MacEndpointType == "0" ||
		p.Layers.USB.TransferType == "0x02"
}

func (p *Packet) isIncoming() bool {
	return p.Layers.USB.Direction == "1"
}

func hexDecode(encoded string) []byte {
	decoded, err := hex.DecodeString(strings.ReplaceAll(encoded, ":", ""))
	if err != nil {
		panic(err)
	}
	return decoded
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

var (
	raw *bool
	le  = binary.LittleEndian

	fmtIn, fmtOut, fmtReset string
)

func decodeSubreport(data []byte) string {
	if len(data) < 6 {
		return fmt.Sprintf("%x", data)
	}
	usage := uint32(le.Uint16(data[:2]))<<16 | uint32(le.Uint16(data[2:4]))
	filtered := make([]byte, len(data)-6)
	for i, b := range data[6:] {
		if b < 32 || b > 126 {
			filtered[i] = '.'
		} else {
			filtered[i] = b
		}
	}
	return fmt.Sprintf("<> %08x %04x %x %s", usage, le.Uint16(data[4:6]),
		data[6:], string(filtered))
}

func decodeResult(data []byte) string {
	if len(data) < 7 {
		return fmt.Sprintf("%x", data)
	}
	usage := uint32(le.Uint16(data[:2]))<<16 | uint32(le.Uint16(data[2:4]))
	return fmt.Sprintf(">< %08x %04x %02x", usage, le.Uint16(data[4:6]),
		data[6])
}

func decodeMP(data []byte) string {
	var out string
	for i := 0; i+1 < len(data); {
		sz := int(data[i+1])
		if data[i] == 0xff || i+sz > len(data) {
			break
		}
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf("[%02x] %x", data[i], data[i+2:i+2+sz])
		i += 2 + sz
	}
	return out
}

func isSetSubreport(id byte) bool {
	switch id {
	case 2, 4, 11, 13:
		return true
	}
	return false
}

func isGetSubreport(id byte) bool {
	switch id {
	case 3, 5, 12, 14:
		return true
	}
	return false
}

func isSubreport(id byte) bool {
	return isSetSubreport(id) || isGetSubreport(id)
}

func processInterrupt(p *Packet) {
	data := hexDecode(p.Layers.CapData)
	if len(data) < 1 {
		return
	}
	if *raw {
		fmt.Printf("%s INT %02x %x\n", p.addr(), data[0], data[1:])
	} else if isSubreport(data[0]) {
		fmt.Printf("%s INT %s\n", p.addr(), decodeSubreport(data[1:]))
	}
}

func processControl(p *Packet) {
	// macOS (Darwin) and Linux report Set_Feature differently.
	data := hexDecode(p.Layers.ControlResponse)
	if len(data) == 0 {
		data = hexDecode(p.Layers.DataFragment)
	}
	if len(data) < 1 {
		return
	}
	if p.isIncoming() {
		if *raw {
			fmt.Printf("%s IN  %02x %x\n", p.addr(), data[0], data[1:])
		} else if data[0] == 1 {
			fmt.Printf("%s IN  SR %x\n", p.addr(), data[5:])
		} else if isGetSubreport(data[0]) {
			fmt.Printf("%s IN  %s%s%s\n", p.addr(),
				fmtIn, decodeSubreport(data[1:]), fmtReset)
		} else if data[0] == 6 {
			fmt.Printf("%s IN  PC %04x\n", p.addr(), le.Uint16(data[1:]))
		} else if data[0] == 7 {
			fmt.Printf("%s IN  %s\n", p.addr(), decodeResult(data[1:]))
		} else if data[0] == 8 {
			fmt.Printf("%s IN  ID %s %s\n", p.addr(), data[1:9], data[9:])
		} else if data[0] == 9 {
			fmt.Printf("%s IN  MP %s\n", p.addr(), decodeMP(data[1:]))
		} else {
			fmt.Printf("%s IN  %02x %x\n", p.addr(), data[0], data[1:])
		}
	} else {
		if *raw {
			fmt.Printf("%s OUT %02x %x\n", p.addr(), data[0], data[1:])
		} else if isSetSubreport(data[0]) {
			fmt.Printf("%s OUT %s%s%s\n", p.addr(),
				fmtOut, decodeSubreport(data[1:]), fmtReset)
		} else if data[0] != 1 && !isGetSubreport(data[0]) {
			fmt.Printf("%s OUT %02x %x\n", p.addr(), data[0], data[1:])
		}
	}
}

func main() {
	raw = flag.Bool("raw", false, "Do not decode EIZO packets")
	flag.Parse()

	if _, ok := os.LookupEnv("NO_COLOR"); !ok {
		fmtIn, fmtOut, fmtReset = "\x1b[34m", "\x1b[31m", "\x1b[m"
	}

	decoder := json.NewDecoder(os.Stdin)
	for {
		var p Packet
		if err := decoder.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
		} else if p.isInterrupt() {
			processInterrupt(&p)
		} else if p.isControl() {
			processControl(&p)
		}
	}
}
