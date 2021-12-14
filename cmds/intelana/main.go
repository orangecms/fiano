package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	// "os"

	//fit "github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	ifd "github.com/linuxboot/fiano/pkg/tools"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func main() {
	flag.Parse()
	args := flag.Args()

	var path string

	if len(args) > 0 {
		path = args[0]
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		// file, err := os.Open(path)
		// a, err := fit.ParseEntryHeadersFrom(file)
		// j, err := json.MarshalIndent(a, "", "  ")
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Printf(string(j))
		a, b, err := ifd.GetRegion(data, uefi.RegionTypeBIOS)
		fmt.Printf("BIOS  offset %x size %x\n", a, b)
		a, b, err = ifd.GetRegion(data, uefi.RegionTypeME)
		fmt.Printf("ME    offset %x size %x\n", a, b)
		a, b, err = ifd.GetRegion(data, uefi.RegionTypeGBE)
		fmt.Printf("GBE   offset %x size %x\n", a, b)
		a, b, err = ifd.GetRegion(data, uefi.RegionTypePTT)
		fmt.Printf("PTT   offset %x size %x\n", a, b)
		a, b, err = ifd.GetRegion(data, uefi.RegionTypeEC)
		fmt.Printf("EC    offset %x size %x\n", a, b)
		a, b, err = ifd.GetRegion(data, uefi.RegionTypeMicrocode)
		fmt.Printf("ucode offset %x size %x\n", a, b)
	}
}
