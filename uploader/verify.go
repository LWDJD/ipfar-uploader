// Package uploader — remote CAR verification for dedup safety.
package uploader

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/LWDJD/ipfar-uploader/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/ipfs/go-cid"
)

// fallbackGatewayURLs are public Arweave gateways tried when the primary
// gateway fails to serve raw transaction data (404 or network error).
// The list is deduplicated against the primary gateway at runtime.
var fallbackGatewayURLs = []string{
	"https://ar-io.dev",
	"https://arweave.net",
}

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

// carv2Pragma is the legacy non‑standard CAR v2 pragma.
var carv2Pragma = []byte{0x63, 0x61, 0x72, 0x02} // "car\x02"

// carv2SpecPragma is the CBOR-encoded CAR v2 pragma: {"version": 2}
var carv2SpecPragma = []byte{
	0x0a,                                     // uint(10) — outer CBOR length
	0xa1,                                     // map(1)
	0x67,                                     // string(7)
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
	0x02,                                     // uint(2)
}

// parseV2Header validates the CAR v2 header bytes and returns the total
// file size derived from the header fields (legacy format only).  For
// standard CBOR format the returned size is 0 — the caller must obtain
// the total size from the HTTP Content-Range header instead.
//
// The function also checks that:
//   - dataOffset is non-zero
//   - indexOffset is non-zero (index is present)
//   - data section fits before the index (legacy only)
func parseV2Header(buf []byte) (derivedSize int64, err error) {
	if len(buf) < 11 {
		return 0, fmt.Errorf("buffer too small for CAR header: %d bytes", len(buf))
	}

	// ── Legacy format ("car\x02") ───────────────────────────────────
	if bytes.Equal(buf[:4], carv2Pragma) {
		if len(buf) < 52 {
			return 0, fmt.Errorf("buffer too small for legacy v2 header (need 52, got %d)", len(buf))
		}
		hdr := buf[4:52] // 48-byte legacy header

		dataOffset := binary.LittleEndian.Uint64(hdr[16:24])
		dataSize := binary.LittleEndian.Uint64(hdr[24:32])
		indexOffset := binary.LittleEndian.Uint64(hdr[32:40])
		indexSize := binary.LittleEndian.Uint64(hdr[40:48])

		if dataOffset == 0 {
			return 0, fmt.Errorf("invalid data offset in legacy CAR v2 header")
		}
		if indexOffset == 0 || indexSize == 0 {
			return 0, fmt.Errorf("CAR v2 has no index (indexOffset=%d, indexSize=%d)", indexOffset, indexSize)
		}

		total := int64(indexOffset + indexSize)

		// Sanity: data section must fit before the index.
		if int64(dataOffset+dataSize) > total {
			return 0, fmt.Errorf("CAR v2 header: data section extends beyond file (dataEnd=%d, total=%d)",
				dataOffset+dataSize, total)
		}

		return total, nil
	}

	// ── Standard CBOR format ────────────────────────────────────────
	if bytes.Equal(buf[:len(carv2SpecPragma)], carv2SpecPragma) {
		if len(buf) < 51 {
			return 0, fmt.Errorf("buffer too small for standard v2 header (need 51, got %d)", len(buf))
		}
		hdr := buf[11:51] // 40-byte standard header

		dataOffset := binary.LittleEndian.Uint64(hdr[16:24])
		indexOffset := binary.LittleEndian.Uint64(hdr[32:40])

		if dataOffset == 0 {
			return 0, fmt.Errorf("invalid data offset in standard CAR v2 header")
		}
		if indexOffset == 0 {
			return 0, fmt.Errorf("CAR v2 has no index (indexOffset=0)")
		}

		// IndexSize is not in the header; size must come from Content-Range.
		return 0, nil
	}

	return 0, fmt.Errorf("unknown CAR pragma: %x", buf[:minInt(len(buf), 16)])
}

// minInt returns the smaller of a and b.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseContentRangeTotal extracts the total file size from a Content-Range
// header value like "bytes 0-199/1048746".  Returns an error if the header
// is missing, malformed, or has an unknown total (*).
func parseContentRangeTotal(cr string) (int64, error) {
	if cr == "" {
		return 0, fmt.Errorf("Content-Range header missing")
	}
	slash := strings.LastIndexByte(cr, '/')
	if slash < 0 {
		return 0, fmt.Errorf("malformed Content-Range %q", cr)
	}
	totalStr := cr[slash+1:]
	if totalStr == "*" {
		return 0, fmt.Errorf("Content-Range has unknown total (*)")
	}
	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid Content-Range total %q: %w", totalStr, err)
	}
	if total <= 0 {
		return 0, fmt.Errorf("Content-Range total <= 0 (%d)", total)
	}
	return total, nil
}

// VerifyRemoteCAR downloads key portions of a remote CAR file from Arweave
// and validates it using the SDK's CAR parser (ipfar-sdk/verify/ipfs).
//
// Multi‑gateway fallback: if the primary gateway returns 404 or a network
// error when serving raw transaction data, alternate public gateways are
// tried in sequence.  If every gateway returns 404 the function falls back
// to trusting on‑chain confirmation (at least 1 confirmation).
//
// Checks performed (when raw data is reachable):
//  1. CAR version == 2
//  2. HasIndex == true
//  3. Root CID matches expectedRootCID
//  4. Index passes ValidateIndex (boundary sanity)
//
// Returns (true, nil) when the CAR passes every check, or when the trust
// fallback is engaged.
func VerifyRemoteCAR(ctx context.Context, gateway *arweave.GatewayClient, txID string, expectedRootCID string) (bool, error) {
	// Collect unique gateway URLs (primary + fallbacks, deduplicated).
	gwURLs := collectGatewayURLs(gateway)

	var lastErr error
	allNotFound := true

	for _, gwURL := range gwURLs {
		gw := arweave.NewGatewayClient(gwURL)
		verified, err := verifyRemoteCARWithGateway(ctx, gw, txID, expectedRootCID)
		if err == nil && verified {
			return true, nil
		}
		lastErr = err
		if !isNotFoundError(err) {
			allNotFound = false
		}
	}

	// ── Trust fallback: every gateway returned 404 ──────────────────
	if allNotFound {
		status, statusErr := gateway.GetTransactionStatus(ctx, txID)
		if statusErr == nil && status.Confirmed && status.BlockHeight > 0 {
			fmt.Printf("Warning: unable to verify CAR via public gateways, trusting on-chain confirmation at height %d\n", status.BlockHeight)
			return true, nil
		}
	}

	if lastErr != nil {
		return false, fmt.Errorf("all gateways failed to verify CAR %s: %w", txID, lastErr)
	}
	return false, fmt.Errorf("all gateways failed to verify CAR %s", txID)
}

// verifyRemoteCARWithGateway attempts to verify a remote CAR using a single
// gateway.  It is the per‑gateway workhorse called by VerifyRemoteCAR.
func verifyRemoteCARWithGateway(ctx context.Context, gateway *arweave.GatewayClient, txID string, expectedRootCID string) (bool, error) {
	// ── 1. Get file size from /tx/{txID} ────────────────────────────
	fileSize, err := gateway.GetTransactionDataSize(ctx, txID)
	if err != nil {
		return false, fmt.Errorf("failed to get data size from /tx/%s: %w", txID, err)
	}

	// ── 2. Create SDK parser backed by remote reader ────────────────
	reader := newRemoteCarReader(ctx, gateway, txID, fileSize)
	parser, err := sdkcar.NewCarParserFromReader(reader, fileSize)
	if err != nil {
		return false, fmt.Errorf("failed to create CAR parser: %w", err)
	}
	defer parser.Close()

	// ── 3. Parse CAR metadata (headers only) ────────────────────────
	info, err := parser.ParseInfo()
	if err != nil {
		return false, fmt.Errorf("failed to parse CAR info: %w", err)
	}

	// ── 4. Check version ────────────────────────────────────────────
	if info.Version != 2 {
		return false, fmt.Errorf("expected CAR v2, got v%d", info.Version)
	}

	// ── 5. Check index presence ─────────────────────────────────────
	if !info.HasIndex {
		return false, fmt.Errorf("CAR file has no index")
	}

	// ── 6. Root CID match ───────────────────────────────────────────
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

	// ── 7. Validate index integrity ─────────────────────────────────
	if err := parser.ValidateIndex(); err != nil {
		return false, fmt.Errorf("index validation failed: %w", err)
	}

	return true, nil
}

// collectGatewayURLs returns a deduplicated list of gateway URLs starting
// with the primary gateway followed by fallbackGatewayURLs.
func collectGatewayURLs(primary *arweave.GatewayClient) []string {
	seen := make(map[string]bool)
	var urls []string

	primaryURL := strings.TrimRight(primary.GatewayURL, "/")
	seen[primaryURL] = true
	urls = append(urls, primaryURL)

	for _, u := range fallbackGatewayURLs {
		u = strings.TrimRight(u, "/")
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}

// isNotFoundError returns true when err indicates an HTTP 404 from a gateway.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "gateway returned 404") ||
		strings.Contains(s, " 404 ") ||
		strings.HasSuffix(s, "404")
}
