// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package manifest

// TODO: move out to generic util pkg
import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Uint24 is a 24 bit unsigned little-endian integer value.
type Uint24 struct {
	Value [3]byte
}

// Uint32 returns the value as parsed uint32.
//
// If the value is used in "Size" then in the most cases the value should be
// shifted with "<< 4" to get the real size value.
//
// See also the code of EntryHeaders.getDataCoordinates()
func (size Uint24) Uint32() uint32 {
	b := make([]byte, 4)
	copy(b[:], size.Value[:])
	return binary.LittleEndian.Uint32(b)
}

// SetUint32 sets the value. See also Uint32.
func (size *Uint24) SetUint32(newValue uint32) {
	if newValue >= 1<<24 {
		panic(fmt.Errorf("too big integer: %d >= %d", newValue, 1<<24))
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, newValue)
	copy(size.Value[:], b[:])
}

// MarshalJSON just implements encoding/json.Marshaler
func (size Uint24) MarshalJSON() ([]byte, error) {
	return json.Marshal(size.Uint32())
}

// UnmarshalJSON just implements encoding/json.Unmarshaler
func (size *Uint24) UnmarshalJSON(b []byte) error {
	var parsed uint32
	err := json.Unmarshal(b, &parsed)
	if err != nil {
		return err
	}
	if parsed >= 1<<24 {
		return fmt.Errorf("too big integer: %d >= %d", parsed, 1<<24)
	}
	size.SetUint32(parsed)
	return nil
}
