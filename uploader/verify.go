// Package uploader — remote CAR verification for dedup safety.
package uploader

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/LWDJD/ipfar-uploader/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/ipfs/go-cid"
)

// remoteCarReader implements io.ReaderAt over HTTP range requests to an
// Arweave gateway.  Each ReadAt call issues a single range request; the
// SDK's CarParser only touches the header / index regions so the total
// number of round-trips is small.
type remoteCarReader struct {
	gateway *arweave.GatewayClient
	txID    string
	size    int64 // total file size in bytes
	ctx     context.Context
}

func newRemoteCarReader(ctx context.Context, gateway *arweave.GatewayClient, txID string, size int64) *remoteCarReader {
	return &remoteCarReader{
		gateway: gateway,
		txID:    txID,
		size:    size,
		ctx:     ctx,
	}
}

// ReadAt implements io.ReaderAt.
func (r *remoteCarReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= r.size {
		return 0, io.EOF
	}

	end := off + int64(len(p)) - 1
	if end >= r.size {
		end = r.size - 1
	}

	data, err := r.gateway.DownloadTransactionDataRange(r.ctx, r.txID, off, end)
	if err != nil {
		return 0, fmt.Errorf("remote read [%d-%d]: %w", off, end, err)
	}

	n = copy(p, data)
	if off+int64(n) >= r.size {
		return n, io.EOF
	}
	return n, nil
}

// getRemoteFileSize fetches the total byte size of a remote transaction's
// data via a HEAD request to the Arweave gateway.  Returns 0 and an error
// when the gateway does not expose a Content-Length header.
func getRemoteFileSize(ctx context.Context, gateway *arweave.GatewayClient, txID string) (int64, error) {
	url := gateway.GatewayURL + "/" + txID

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HEAD request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HEAD %s returned %d", url, resp.StatusCode)
	}

	if resp.ContentLength <= 0 {
		return 0, fmt.Errorf("gateway did not provide Content-Length for %s", txID)
	}

	return resp.ContentLength, nil
}

// VerifyRemoteCAR downloads key portions of a remote CAR file from Arweave
// and validates it using the SDK's CAR parser (ipfar-sdk/verify/ipfs).
//
// Checks performed:
//  1. CAR version == 2
//  2. HasIndex == true
//  3. Root CID matches expectedRootCID
//  4. Index passes ValidateIndex (boundary sanity)
//
// Returns (true, nil) when the CAR passes every check.
func VerifyRemoteCAR(ctx context.Context, gateway *arweave.GatewayClient, txID string, expectedRootCID string) (bool, error) {
	// ── 1. Get remote file size ─────────────────────────────────────────
	fileSize, err := getRemoteFileSize(ctx, gateway, txID)
	if err != nil {
		return false, fmt.Errorf("failed to get remote file size: %w", err)
	}

	// ── 2. Create SDK parser backed by remote reader ────────────────────
	reader := newRemoteCarReader(ctx, gateway, txID, fileSize)
	parser, err := sdkcar.NewCarParserFromReader(reader, fileSize)
	if err != nil {
		return false, fmt.Errorf("failed to create CAR parser: %w", err)
	}
	defer parser.Close()

	// ── 3. Parse CAR metadata (headers only) ────────────────────────────
	info, err := parser.ParseInfo()
	if err != nil {
		return false, fmt.Errorf("failed to parse CAR info: %w", err)
	}

	// ── 4. Check version ────────────────────────────────────────────────
	if info.Version != 2 {
		return false, fmt.Errorf("expected CAR v2, got v%d", info.Version)
	}

	// ── 5. Check index presence ─────────────────────────────────────────
	if !info.HasIndex {
		return false, fmt.Errorf("CAR file has no index")
	}

	// ── 6. Root CID match ───────────────────────────────────────────────
	expectedCID, err := cid.Decode(expectedRootCID)
	if err != nil {
		return false, fmt.Errorf("invalid expected root CID %q: %w", expectedRootCID, err)
	}

	found := false
	for _, root := range info.Roots {
		if root.Equals(expectedCID) {
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("root CID mismatch: expected %s, roots in CAR: %v",
			expectedRootCID, info.Roots)
	}

	// ── 7. Validate index integrity ─────────────────────────────────────
	if err := parser.ValidateIndex(); err != nil {
		return false, fmt.Errorf("index validation failed: %w", err)
	}

	return true, nil
}
