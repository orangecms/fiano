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

// TODO: Expand for server
// see coreboot `util/amdfwtool/amdfwtool.h`
type SecondGenEFS struct {
	_    uint8
	_    uint8
	_    uint8
	_    bool
	_    bool
	_    bool
	_    bool
	_    bool
	_    bool
	_    bool
	Gen1 bool // per coreboot: client products only use bit 0
}

// EmbeddedFirmwareStructure represents Embedded Firmware Structure defined in Table 2 in (1)
// see also https://doc.coreboot.org/soc/amd/psp_integration.html#embedded-firmware-structure
// and coreboot `util/amdfwtool/amdfwtool.h`
type EmbeddedFirmwareStructure struct {
	Signature                      uint32
	IMC_FW                         uint32
	GBE_FW                         uint32
	XHCI_FW                        uint32
	PSPLegacyDirectoryTablePointer uint32
	PSPDirectoryTablePointer       uint32 // can be "new" or "combo"

	BIOSDirectoryTableFamily17hModels00h0FhPointer uint32
	BIOSDirectoryTableFamily17hModels10h1FhPointer uint32
	BIOSDirectoryTableFamily17hModels30h3FhPointer uint32
	EFSGen                                         SecondGenEFS
	BIOSDirectoryTableFamily17hModels60h3FhPointer uint32

	Reserved2Ch                       uint32
	PromontoryFWPointer               uint32
	LPPromontoryFWPointer             uint32
	Reserved38h                       uint32
	Reserved3Ch                       uint32
	SPIReadmodeFamily15Models60h6Fh   uint8
	FastSpeedNewFamily15Models60h6Fh  uint8
	Reserved42h                       uint8
	SPIReadmodeFamily17Models00h2Fh   uint8
	SPIFastspeedFamily17Models00h2Fh  uint8
	QPRDummyCycleFamily17Models00h2Fh uint8
	Reserved46h                       uint8
	SPIReadmodeFamily17Models30h3Fh   uint8
	SPIFastspeedFamily17Models30h3Fh  uint8
	MicronDetectFamily17Models30h3Fh  uint8
	Reserved4Ah                       uint8
	Reserved4Bh                       uint8
	Reserved4Ch                       uint32
}

/* Embedded Firmware Structure example
          Signature     IMC           GBE           XHCI
00020000: aa55 aa55     0000 0000     0000 0000     0000 0000  .U.U............
          PSP legacy    PSP modern    BIOS0         BIOS1
00020010: 0000 0000     0070 0e00     0000 24ff     00f0 3aff  .....p....$...:.
          BIOS2         EFS gener.    BIOS3         Reserved 2Ch
00020020: 00f0 5d00     feff ffff     0078 0e00     ffff ffff  ..]......x......
          Promontory FW LP Promon. FW Reserved 38h  Reserved 3Ch
00020030: 0000 0000     0000 0000     00f0 90ff     ffff ffff  ................
          S F  R S      F Q  R S      F M  R R      Reserved 4Ch
00020040: ffff ffff     ffff ffff     0055 ffff     ffff ffff  .........U......
                                        ^ Micron detect fam 17 models 30-3F
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
