package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	amd "github.com/linuxboot/fiano/pkg/amd/manifest"
)

const (
	// This needed a look at the image; how can we fully automate it?
	mapping = 0xff000000
)

// this is only for Go - would be 5 lines inline in JS, thanks...
type dummyFirmware struct {
	image []byte
}

func (f dummyFirmware) ImageBytes() []byte {
	return f.image
}

func (f dummyFirmware) PhysAddrToOffset(physAddr uint64) uint64 {
	return physAddr - mapping
}

func (f dummyFirmware) OffsetToPhysAddr(offset uint64) uint64 {
	return offset + mapping
}

func main() {
	flag.Parse()
	args := flag.Args()

	var path string
	var amdfw dummyFirmware

	if len(args) > 0 {
		path = args[0]
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		amdfw.image = data
		fw, err := amd.NewAMDFirmware(amdfw)
		if err != nil {
			log.Fatal(err)
		}
		a := fw.PSPFirmware()
		j, err := json.MarshalIndent(a, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf(string(j))
	}
}
