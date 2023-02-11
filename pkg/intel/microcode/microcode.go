// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package microcode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type Microcode struct {
	Header
	Data               []byte
	ExtSigTable        ExtendedSigTable
	ExtendedSignatures []ExtendedSignature
}

func (m *Microcode) String() string {
	s := fmt.Sprintf("sig=0x%x, pf=0x%x, rev=0x%x, total size=0x%x, date = %04x-%02x-%02x",
		m.HeaderProcessorSignature, m.HeaderProcessorFlags, m.HeaderRevision,
		getTotalSize(m.Header), m.HeaderDate&0xffff, m.HeaderDate>>24, (m.HeaderDate>>16)&0xff)
	if len(m.ExtendedSignatures) > 0 {
		s += "\n"
	}
	for i := range m.ExtendedSignatures {
		s += fmt.Sprintf("Extended signature[%d]: %s\n", i, m.ExtendedSignatures[i].String())
	}
	return s
}

type Header struct {
	HeaderVersion            uint32 // must be 0x1
	HeaderRevision           uint32
	HeaderDate               uint32 // packed BCD, MMDDYYYY
	HeaderProcessorSignature uint32
	HeaderChecksum           uint32
	HeaderLoaderRevision     uint32
	HeaderProcessorFlags     uint32
	HeaderDataSize           uint32 // 0 means 2000
	HeaderTotalSize          uint32 // 0 means 2048
	Reserved1                [3]uint32
}

type ExtendedSignature struct {
	Signature      uint32
	ProcessorFlags uint32
	Checksum       uint32
}

func (e *ExtendedSignature) String() string {
	return fmt.Sprintf("sig=0x%x, pf=0x%x", e.Signature, e.ProcessorFlags)
}

type ExtendedSigTable struct {
	Count    uint32
	Checksum uint32
	Reserved [3]uint32
}

func getTotalSize(h Header) uint32 {
	if h.HeaderDataSize > 0 {
		return h.HeaderTotalSize
	} else {
		return uint32(binary.Size(Header{}) + 0x2000)
	}
}

func getDataSize(h Header) uint32 {
	if h.HeaderDataSize > 0 {
		return h.HeaderDataSize
	} else {
		return 0x2000
	}
}

// ParseIntelFirmware parses the Intel microcode
func ParseIntelMicrocode(r io.Reader) (*Microcode, error) {
	var m Microcode

	if err := binary.Read(r, binary.LittleEndian, &m.Header); err != nil {
		return nil, fmt.Errorf("Failed to read header: %v", err)
	}

	// Sanitychecks
	if getTotalSize(m.Header) < getDataSize(m.Header)+uint32(binary.Size(Header{})) {
		return nil, fmt.Errorf("Bad data file size")
	}
	if m.HeaderLoaderRevision != 1 || m.HeaderVersion != 1 {
		return nil, fmt.Errorf("Invalid version or revision")
	}
	if getDataSize(m.Header)%4 > 0 {
		return nil, fmt.Errorf("Data size not 32bit aligned")
	}
	if getTotalSize(m.Header)%4 > 0 {
		return nil, fmt.Errorf("Total size not 32bit aligned")
	}
	// Read data
	dataSize := getDataSize(m.Header)
	m.Data = make([]byte, dataSize)
	b := &bytes.Buffer{}
	r = io.TeeReader(r, b)
	if err := binary.Read(r, binary.LittleEndian, &m.Data); err != nil {
		bf := &bytes.Buffer{}
		bufferSize, _ := io.Copy(bf, b)
		return nil, fmt.Errorf("Failed to read data (reading %v bytes from buffer of size %v): %v", dataSize, bufferSize, err)
	}

	// Calculcate checksum
	buf := bytes.NewBuffer([]byte{})
	buf.Grow(int(getDataSize(m.Header)) + binary.Size(Header{}))
	_ = binary.Write(buf, binary.LittleEndian, &m.Header)
	_ = binary.Write(buf, binary.LittleEndian, &m.Data)

	var checksum uint32
	for {
		var data uint32
		if err := binary.Read(buf, binary.LittleEndian, &data); err != nil {
			break
		}
		checksum += data
	}
	if checksum != 0 {
		return nil, fmt.Errorf("Checksum is not null: %#x", checksum)
	}

	if getTotalSize(m.Header) <= getDataSize(m.Header)+uint32(binary.Size(Header{})) {
		return &m, nil
	}

	// Read extended header
	if err := binary.Read(r, binary.LittleEndian, &m.ExtSigTable); err != nil {
		return nil, fmt.Errorf("Failed to read extended sig table: %v", err)
	}
	for i := uint32(0); i < m.ExtSigTable.Count; i++ {
		var signature ExtendedSignature
		if err := binary.Read(r, binary.LittleEndian, &signature); err != nil {
			return nil, fmt.Errorf("Failed to read extended signature: %v", err)
		}
		m.ExtendedSignatures = append(m.ExtendedSignatures, signature)
	}

	// Calculcate checksum
	buf = bytes.NewBuffer([]byte{})
	buf.Grow(binary.Size(ExtendedSigTable{}) +
		int(m.ExtSigTable.Count)*binary.Size(ExtendedSignature{}))
	_ = binary.Write(buf, binary.LittleEndian, &m.ExtSigTable)
	for i := uint32(0); i < m.ExtSigTable.Count; i++ {
		_ = binary.Write(buf, binary.LittleEndian, &m.ExtendedSignatures[i])
	}

	checksum = 0
	for {
		var data uint32
		if err := binary.Read(buf, binary.LittleEndian, &data); err != nil {
			break
		}
		checksum += data
	}
	if checksum != 0 {
		return nil, fmt.Errorf("Extended header checksum is not null: %#x", checksum)
	}

	return &m, nil
}
