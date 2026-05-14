// ipfar-uploader is a CLI tool for uploading files to Arweave
// following the IPFAR V1 data specification.
//
// It packages files as CAR v2 format with index, computes PoW for small files,
// and uploads both the CAR data and metadata to the Arweave network.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LWDJD/ipfar-uploader/cmd"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := cmd.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
