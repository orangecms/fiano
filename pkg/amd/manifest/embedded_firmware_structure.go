// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// EmbeddedFirmwareStructureSignature is a special identifier of Firmware Embedded Structure
const EmbeddedFirmwareStructureSignature = 0x55aa55aa

// EmbeddedFirmwareStructure represents Embedded Firmware Structure defined in Table 2 in (1)
// see also https://doc.coreboot.org/soc/amd/psp_integration.html#embedded-firmware-structure
type EmbeddedFirmwareStructure struct {
	Signature                      uint32
	IMC_FW                         uint32
	GBE_FW                         uint32
	XHCI_FW                        uint32
	PSPLegacyDirectoryTablePointer uint32
	PSPDirectoryTablePointer       uint32

	BIOSDirectoryTableFamily17hModels00h0FhPointer uint32
	BIOSDirectoryTableFamily17hModels10h1FhPointer uint32
	BIOSDirectoryTableFamily17hModels30h3FhPointer uint32
	Reserved2                                      uint32
	BIOSDirectoryTableFamily17hModels60h3FhPointer uint32

	Reserved3 [30]byte
}

/* Embedded Firmware Structure example
          Signature     IMC           GBE           XHCI
00020000: aa55 aa55     0000 0000     0000 0000     0000 0000  .U.U............
          PSP legacy    PSP modern    BIOS1         BIOS2
00020010: 0000 0000     0070 0e00     0000 24ff     00f0 3aff  .....p....$...:.
          BIOS3         R2 (????)     BIOS4         R3[0..3]
00020020: 00f0 5d00     feff ffff     0078 0e00     ffff ffff  ..]......x......
          R3[4..7]      R3[8..11]     R3[12..15]    R3[16..19]
00020030: 0000 0000     0000 0000     00f0 90ff     ffff ffff  ................
          R3[20..23]    R3[24..27]    R3[29,30]+?   ????
00020040: ffff ffff     ffff ffff     0055 ffff     ffff ffff  .........U......
*/

// FindEmbeddedFirmwareStructure locates and parses Embedded Firmware Structure
func FindEmbeddedFirmwareStructure(firmware Firmware) (*EmbeddedFirmwareStructure, bytes2.Range, error) {
	var addresses = []uint64{
		0xfffa0000,
		0xfff20000,
		0xffe20000,
		0xffc20000,
		0xff820000,
		0xff020000,
	}

	image := firmware.ImageBytes()

	for _, addr := range addresses {
		offset := firmware.PhysAddrToOffset(addr)
		if offset+4 > uint64(len(image)) {
			continue
		}

		actualSignature := binary.LittleEndian.Uint32(image[offset:])
		if actualSignature == EmbeddedFirmwareStructureSignature {
			result, length, err := ParseEmbeddedFirmwareStructure(bytes.NewBuffer(image[offset:]))
			return result, bytes2.Range{Offset: offset, Length: length}, err
		}
	}
	return nil, bytes2.Range{}, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParseEmbeddedFirmwareStructure converts input bytes into EmbeddedFirmwareStructure
func ParseEmbeddedFirmwareStructure(r io.Reader) (*EmbeddedFirmwareStructure, uint64, error) {
	var result EmbeddedFirmwareStructure
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, 0, err
	}

	if result.Signature != EmbeddedFirmwareStructureSignature {
		return nil, 0, fmt.Errorf("incorrect signature: %d", result.Signature)
	}
	return &result, uint64(binary.Size(result)), nil
}
