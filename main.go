// ipfar-uploader is a CLI tool for uploading files to Arweave
// following the IPFAR V1 data specification.
//
// It packages files as CAR v2 format with index, computes PoW for small files,
// and uploads both the CAR data and metadata to the Arweave network.
package main

import (
	"fmt"
	"os"

	"github.com/LWDJD/ipfar-uploader/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
