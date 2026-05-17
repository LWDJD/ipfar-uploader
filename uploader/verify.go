// Package uploader — remote CAR verification for dedup safety.
package uploader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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
// data from an Arweave gateway.  Several strategies are tried in order
// because some CDN frontends (most notably arweave.net) do not return
// Content-Length on HEAD requests against the /raw/ path.
//
// Strategies (tried in order):
//  1. HEAD /{txID}                       – read Content-Length
//  2. GET  /{txID}  Range: bytes=0-0     – parse Content-Range
//  3. GET  /{txID}  (limited to 4 KiB)   – read Content-Length or drain body
func getRemoteFileSize(ctx context.Context, gateway *arweave.GatewayClient, txID string) (int64, error) {
	url := gateway.GatewayURL + "/" + txID

	// ── Strategy 1: HEAD ──────────────────────────────────────────────
	if size, err := headFileSize(ctx, url); err == nil {
		return size, nil
	}

	// ── Strategy 2: Range bytes=0-0 ───────────────────────────────────
	if size, err := rangeFileSize(ctx, url); err == nil {
		return size, nil
	}

	// ── Strategy 3: limited GET ───────────────────────────────────────
	if size, err := limitedGetFileSize(ctx, url); err == nil {
		return size, nil
	}

	return 0, fmt.Errorf("all strategies exhausted to get file size for %s", txID)
}

// headFileSize tries a HEAD request and returns Content-Length.
func headFileSize(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, fmt.Errorf("HEAD: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HEAD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HEAD returned %d", resp.StatusCode)
	}

	if resp.ContentLength <= 0 {
		return 0, fmt.Errorf("HEAD: no Content-Length")
	}

	return resp.ContentLength, nil
}

// rangeFileSize sends GET with Range: bytes=0-0 and parses the
// Content-Range response header (format: "bytes 0-0/1048746").
func rangeFileSize(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("Range: %w", err)
	}
	req.Header.Set("Range", "bytes=0-0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Range: %w", err)
	}
	defer resp.Body.Close()

	// Accept both 206 Partial Content and 200 OK (some servers ignore Range)
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Range returned %d", resp.StatusCode)
	}

	cr := resp.Header.Get("Content-Range")
	if cr == "" {
		return 0, fmt.Errorf("Range: no Content-Range header")
	}

	// Content-Range format: "bytes start-end/total" or "bytes start-end/*"
	slash := strings.LastIndexByte(cr, '/')
	if slash < 0 {
		return 0, fmt.Errorf("Range: malformed Content-Range %q", cr)
	}
	totalStr := cr[slash+1:]
	if totalStr == "*" {
		return 0, fmt.Errorf("Range: Content-Range has unknown total")
	}

	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Range: invalid Content-Range total %q: %w", totalStr, err)
	}
	if total <= 0 {
		return 0, fmt.Errorf("Range: Content-Range total <= 0 (%d)", total)
	}

	return total, nil
}

// limitedGetFileSize issues a GET and reads at most 4 KiB from the body.
// It first checks Content-Length; if missing, it uses io.LimitReader to
// read up to 4 KiB.  If EOF is reached within the limit, the file size
// is known exactly (totalBytesRead); otherwise we cannot determine the
// size without downloading the whole file.
func limitedGetFileSize(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("GET: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET returned %d", resp.StatusCode)
	}

	// If the server gave us Content-Length, use it.
	if resp.ContentLength > 0 {
		return resp.ContentLength, nil
	}

	// Drain up to 4 KiB to see if the file is small enough to fully read.
	const maxRead = 4 * 1024
	limited := io.LimitReader(resp.Body, maxRead+1) // +1 to detect overflow
	n, readErr := io.Copy(io.Discard, limited)
	if readErr != nil {
		return 0, fmt.Errorf("GET: read error: %w", readErr)
	}

	if n <= maxRead {
		// Reached EOF within the limit — we read the entire file.
		return n, nil
	}

	return 0, fmt.Errorf("GET: no Content-Length and file larger than %d bytes", maxRead)
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
