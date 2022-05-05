// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"encoding/json"
	"fmt"
	"os"

	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
)

// Firmware is an abstraction of a firmware image, obtained for example via flashrom
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
	OffsetToPhysAddr(offset uint64) uint64
}

type BIOSDir struct {
	BIOSDirectoryLevel1      *BIOSDirectoryTable
	BIOSDirectoryLevel1Range bytes2.Range
	BIOSDirectoryLevel2      *BIOSDirectoryTable
	BIOSDirectoryLevel2Range bytes2.Range
}

type PSPDir struct {
	PSPDirectoryLevel1 *PSPDirectoryTable
	PSPDirectoryLevel2 *[]PSPDirectoryTable
}

// PSPFirmware contains essential parts of the AMD's PSP firmware internals
type PSPFirmware struct {
	EmbeddedFirmware      EmbeddedFirmwareStructure
	EmbeddedFirmwareRange bytes2.Range
	BIOSDirectories       []BIOSDir
	PSPDirectories        []PSPDir
}

// AMDFirmware represents an instance of firmware that exposes AMD specific
// meatadata and structure.
type AMDFirmware struct {
	// firmware is a reference to a generic firmware interface
	firmware Firmware

	// pspFirmware is a reference to PSPFirmware structure. It is built at
	// construction time and not exported.
	pspFirmware *PSPFirmware
}

// Firmware returns the internal reference to Firmawre interface
func (a *AMDFirmware) Firmware() Firmware {
	return a.firmware
}

// PSPFirmware returns the PSPFirmware reference held by the AMDFirmware object
func (a *AMDFirmware) PSPFirmware() *PSPFirmware {
	return a.pspFirmware
}

func AddBiosL2Entry(d *BIOSDir, image []byte) {
	fmt.Fprintf(os.Stderr, " - BIOS L2 dir scan\n")
	for _, entry := range d.BIOSDirectoryLevel1.Entries {
		if entry.Type != BIOSDirectoryTableLevel2Entry {
			continue
		}
		// TODO: This is hardcoded, and likely the wrong place to do it.
		// It stems from the memory mapping in running systems.
		if entry.SourceAddress > 0xff000000 {
			entry.SourceAddress -= 0xff000000
		}
		fmt.Fprintf(os.Stderr, "   BIOS L2 dir at %x\n", entry.SourceAddress)
		if entry.SourceAddress != 0 && entry.SourceAddress < uint64(len(image)) {
			biosDirectoryLevel2, length, err := ParseBIOSDirectoryTable(image[entry.SourceAddress:])
			fmt.Fprintf(os.Stderr, "   BIOS L2 dir size %x\n", length)
			if err == nil {
				d.BIOSDirectoryLevel2 = biosDirectoryLevel2
				d.BIOSDirectoryLevel2Range.Offset = entry.SourceAddress
				d.BIOSDirectoryLevel2Range.Length = length
			}
		}
		break
	}
}

func AddPspL2Entry(p *PSPDir, image []byte) {
	fmt.Fprintf(os.Stderr, " - PSP L2 dir scan\n")
	var dirs []PSPDirectoryTable

	for _, entry := range p.PSPDirectoryLevel1.Entries {
		if !IsPSPDirLevel2Entry(entry) {
			continue
		}
		// TODO: This is hardcoded, and likely the wrong place to do it.
		// It stems from the memory mapping in running systems.
		if entry.LocationOrValue > 0xff000000 {
			entry.LocationOrValue -= 0xff000000
		}
		fmt.Fprintf(os.Stderr, "   PSP L2 dir at %x\n", entry.LocationOrValue)
		if entry.LocationOrValue != 0 && entry.LocationOrValue < uint64(len(image)) {
			pspDirectoryLevel2, length, err := ParsePSPDirectoryTable(image[entry.LocationOrValue:])
			fmt.Fprintf(os.Stderr, "   PSP L2 dir size %x\n", length)
			if length == 0 && (entry.Type == PSPDirectoryTableLevel2RecovAEntry ||
				entry.Type == PSPDirectoryTableLevel2RecovBEntry) {
				fmt.Fprintf(os.Stderr, "%x recov pointer location\n", entry.LocationOrValue)
				recovDir, _ := ParseRecovEntry(image[entry.LocationOrValue:])
				fmt.Fprintf(os.Stderr, "%x recovDir\n", recovDir.Location)
				pspDirectoryLevel2, length, err = ParsePSPDirectoryTable(image[recovDir.Location:])
				fmt.Fprintf(os.Stderr, "   PSP L2 recov dir size %x\n", length)
			}
			if err == nil {
				pspDirectoryLevel2.Range.Offset = entry.LocationOrValue
				pspDirectoryLevel2.Range.Length = length
				dirs = append(dirs, *pspDirectoryLevel2)
			}
		}
	}
	p.PSPDirectoryLevel2 = &dirs
}

// parsePSPFirmware parses input firmware as PSP firmware image and
// collects Embedded firmware, PSP directory and BIOS directory structures
func parsePSPFirmware(firmware Firmware) (*PSPFirmware, error) {
	image := firmware.ImageBytes()

	var result PSPFirmware
	efs, r, err := FindEmbeddedFirmwareStructure(firmware)
	if err != nil {
		return nil, err
	}
	result.EmbeddedFirmware = *efs
	result.EmbeddedFirmwareRange = r

	result.PSPDirectories = []PSPDir{}

	var offset uint64 = 0

	// legacy PSP directory
	if efs.PSPLegacyDirectoryTablePointer > 0xff000000 {
		efs.PSPLegacyDirectoryTablePointer -= 0xff000000
	}
	if efs.PSPLegacyDirectoryTablePointer != 0 && efs.PSPLegacyDirectoryTablePointer < uint32(len(image)) {
		var pspDirectoryLevel1 *PSPDirectoryTable
		var pspDirectoryLevel1Range bytes2.Range
		var length uint64
		fmt.Fprintf(os.Stderr, "Parse legacy PSPDir at %x\n", efs.PSPDirectoryTablePointer)
		pspDirectoryLevel1, length, err = ParsePSPDirectoryTable(image[efs.PSPLegacyDirectoryTablePointer:])
		if err == nil {
			offset = uint64(efs.PSPDirectoryTablePointer)
			pspDirectoryLevel1Range.Offset = offset
			pspDirectoryLevel1Range.Length = length
		}
		if pspDirectoryLevel1 == nil {
			pspDirectoryLevel1, pspDirectoryLevel1Range, err = FindPSPDirectoryTable(image)
			if err != nil {
				offset = pspDirectoryLevel1Range.Offset
			}
		}
		if pspDirectoryLevel1 != nil {
			pspDir := PSPDir{}
			pspDirectoryLevel1.Range = pspDirectoryLevel1Range
			pspDir.PSPDirectoryLevel1 = pspDirectoryLevel1
			AddPspL2Entry(&pspDir, image)
			result.PSPDirectories = append(result.PSPDirectories, pspDir)
		}
	}
	// modern PSP directory
	if efs.PSPDirectoryTablePointer > 0xff000000 {
		efs.PSPDirectoryTablePointer -= 0xff000000
	}
	if efs.PSPDirectoryTablePointer != 0 && efs.PSPDirectoryTablePointer < uint32(len(image)) {
		var pspDirectoryLevel1 *PSPDirectoryTable
		var pspDirectoryLevel1Range bytes2.Range
		var length uint64
		fmt.Fprintf(os.Stderr, "Parse modern PSPDir at %x\n", efs.PSPDirectoryTablePointer)
		pspDirectoryLevel1, length, err = ParsePSPDirectoryTable(image[efs.PSPDirectoryTablePointer:])
		if err == nil {
			offset = uint64(efs.PSPDirectoryTablePointer)
			pspDirectoryLevel1Range.Offset = offset
			pspDirectoryLevel1Range.Length = length
		}
		if pspDirectoryLevel1 == nil {
			pspDirectoryLevel1, pspDirectoryLevel1Range, err = FindPSPDirectoryTable(image[offset+20:])
			if err != nil {
				// save offset for further seeking
				offset = pspDirectoryLevel1Range.Offset
			}
		}
		if pspDirectoryLevel1 != nil {
			pspDir := PSPDir{}
			pspDirectoryLevel1.Range = pspDirectoryLevel1Range
			pspDir.PSPDirectoryLevel1 = pspDirectoryLevel1
			AddPspL2Entry(&pspDir, image)
			result.PSPDirectories = append(result.PSPDirectories, pspDir)
		}
	}

	result.BIOSDirectories = []BIOSDir{}

	var biosDirectoryLevel1 *BIOSDirectoryTable
	var biosDirectoryLevel1Range bytes2.Range

	biosDirectoryOffsets := []uint32{
		efs.BIOSDirectoryTableFamily17hModels00h0FhPointer,
		efs.BIOSDirectoryTableFamily17hModels10h1FhPointer,
		efs.BIOSDirectoryTableFamily17hModels30h3FhPointer,
		efs.BIOSDirectoryTableFamily17hModels60h3FhPointer,
	}

	for _, offset := range biosDirectoryOffsets {
		if offset == 0 || offset == 0xffffffff {
			continue
		}
		// TODO: This is hardcoded, and likely the wrong place to do it.
		// It stems from the memory mapping in running systems.
		if int(offset) > len(image) {
			offset -= 0xff000000
		}
		if int(offset) > len(image) {
			continue
		}
		var length uint64
		fmt.Fprintf(os.Stderr, "Parse BIOSDir at %x\n", offset)
		biosDirectoryLevel1, length, err = ParseBIOSDirectoryTable(image[offset:])

		if err != nil {
			continue
		}
		biosDirectoryLevel1Range.Offset = uint64(offset)
		biosDirectoryLevel1Range.Length = length

		if biosDirectoryLevel1 != nil {
			// fmt.Fprintf(os.Stderr, "BIOS DIR FOUND %v (%v)\n", biosDirectoryLevel1.BIOSCookie, length)
			result.BIOSDirectories = append(result.BIOSDirectories, BIOSDir{})
			bd := &result.BIOSDirectories[len(result.BIOSDirectories)-1]
			bd.BIOSDirectoryLevel1 = biosDirectoryLevel1
			bd.BIOSDirectoryLevel1Range = biosDirectoryLevel1Range
			AddBiosL2Entry(bd, image)
		}
	}

	// TODO: Manually scan in addition and compare offsets to existing findings
	// NOTE: Some images do not have level 2 directory references in directory 1.
	biosDir, biosDirRange, err := FindBIOSDirectoryTable(image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "BIOS DIR SCAN: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "BIOS DIR SCAN: %v / %v files\n", biosDirRange, biosDir.TotalEntries)
		d, _ := json.MarshalIndent(biosDir.Entries, "", "  ")
		fmt.Fprintf(os.Stderr, "BIOS DIR SCAN: %v\n", string(d))
		result.BIOSDirectories = append(result.BIOSDirectories, BIOSDir{})
		bd := &result.BIOSDirectories[len(result.BIOSDirectories)-1]
		bd.BIOSDirectoryLevel1 = biosDir
		bd.BIOSDirectoryLevel1Range = biosDirRange
	}

	return &result, nil
}

// NewAMDFirmware returns an AMDFirmware structure or an error if internal firmare structures cannot be parsed
func NewAMDFirmware(firmware Firmware) (*AMDFirmware, error) {
	pspFirmware, err := parsePSPFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not construct AMDFirmware, cannot parse PSP firmware: %w", err)
	}
	return &AMDFirmware{firmware: firmware, pspFirmware: pspFirmware}, nil

}
