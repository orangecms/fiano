package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	ucode "github.com/linuxboot/fiano/pkg/intel/microcode"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) > 0 {
		path := args[0]
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		m, err := ucode.ParseIntelMicrocode(file)
		if err != nil {
			log.Fatalf("Could not parse ucode: %v", err)
		}

		if m == nil {
			fmt.Println("no ucode for you")
			return
		}
		fmt.Printf("ucode header: %v\n", m.Header)
		fmt.Printf("ucode: %v\n", m.String())
		if false {
			j, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%v\n", string(j))
		}
	}
}
