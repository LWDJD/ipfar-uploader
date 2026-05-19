// Package arweave bridges ipfar-uploader to ipfar-sdk/arweave.
//
// Most types and methods are re-exported from the SDK.  This adapter
// adds only the two methods missing from the SDK:
//   - UploadDataRaw(ctx, data []byte) (string, error)
//   - DownloadTransactionDataRange(ctx, txID string, start, end int64) ([]byte, error)
//
// It also provides backward-compatible aliases for ChunkSize and
// a legacy UploadData helper.
package arweave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	sdk "github.com/LWDJD/ipfar-sdk/arweave"
)

// =============================================================================
// Re-exports from SDK
// =============================================================================

// Types
type (
	Wallet             = sdk.Wallet
	JWK                = sdk.JWK
	Transaction        = sdk.Transaction
	TransactionStatus  = sdk.TransactionStatus
	Tag                = sdk.Tag
	TransactionBuilder = sdk.TransactionBuilder
)

// Constructor functions
var (
	LoadWalletFromFile    = sdk.LoadWalletFromFile
	LoadWalletFromJSON    = sdk.LoadWalletFromJSON
	NewTransactionBuilder = sdk.NewTransactionBuilder
)

// Constants
const (
	ChunkSize    = sdk.MaxChunkSize
	MaxChunkSize = sdk.MaxChunkSize
)

// =============================================================================
// GatewayClient wrapper
// =============================================================================

// GatewayClient wraps the SDK GatewayClient and adds uploader-specific
// methods.  All SDK methods are promoted through embedding.
type GatewayClient struct {
	*sdk.GatewayClient
}

// NewGatewayClient creates a new wrapped GatewayClient.
func NewGatewayClient(gatewayURL string) *GatewayClient {
	return &GatewayClient{GatewayClient: sdk.NewGatewayClient(gatewayURL)}
}

// UploadDataRaw uploads already-signed raw transaction bytes to the gateway
// via POST /tx with Content-Type: application/octet-stream.
// Returns the transaction ID parsed from the gateway response.
func (gc *GatewayClient) UploadDataRaw(ctx context.Context, data []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/tx", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	start := debugHTTPStart(req.Method, req.URL.String())
	resp, err := gc.HTTPClient().Do(req)
	if err != nil {
		debugHTTPDone(start, 0, nil, err)
		return "", fmt.Errorf("failed to submit raw data: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	debugHTTPDone(start, resp.StatusCode, respBody, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse TX ID from response
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err == nil {
		if id, ok := result["id"].(string); ok {
			return id, nil
		}
	}

	return strings.TrimSpace(string(respBody)), nil
}

// DownloadTransactionDataRange downloads a byte range of a transaction's data.
// start and end are inclusive.  Use -1 for end to download to EOF.
func (gc *GatewayClient) DownloadTransactionDataRange(ctx context.Context, txID string, start, end int64) ([]byte, error) {
	url := gc.GatewayURL + "/" + txID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if end < 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}

	startDbg := debugHTTPStart(req.Method, req.URL.String())
	resp, err := gc.HTTPClient().Do(req)
	if err != nil {
		debugHTTPDone(startDbg, 0, nil, err)
		return nil, fmt.Errorf("failed to download data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		debugHTTPDone(startDbg, resp.StatusCode, nil, fmt.Errorf("gateway returned %d", resp.StatusCode))
		return nil, fmt.Errorf("gateway returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		debugHTTPDone(startDbg, resp.StatusCode, nil, err)
		return nil, err
	}

	debugHTTPDone(startDbg, resp.StatusCode, data, nil)
	return data, nil
}

// UploadData is a legacy wrapper that delegates to UploadDataChunked.
// All uploads now go through the chunked path.
func (gc *GatewayClient) UploadData(ctx context.Context, wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	return gc.UploadDataChunked(ctx, wallet, data, tags)
}

// =============================================================================
// Debug helpers
// =============================================================================

// DebugEnabled controls whether debug logs are written to stderr.
// Set from CLI (--debug flag).
var DebugEnabled bool

// debugLog prints a formatted message to stderr when DebugEnabled is true.
func debugLog(format string, args ...interface{}) {
	if !DebugEnabled {
		return
	}
	prefix := "[DEBUG]"
	if _, file, line, ok := runtime.Caller(1); ok {
		for i := len(file) - 1; i >= 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}
		prefix = fmt.Sprintf("[DEBUG] %s:%d", file, line)
	}
	fmt.Fprintf(os.Stderr, prefix+" "+format+"\n", args...)
}

// debugHTTPStart logs the start of an HTTP request and returns the start time.
func debugHTTPStart(method, url string) time.Time {
	debugLog("HTTP %s %s — start", method, url)
	return time.Now()
}

// debugHTTPDone logs the completion of an HTTP request.
func debugHTTPDone(start time.Time, statusCode int, body []byte, err error) {
	elapsed := time.Since(start)
	if err != nil {
		debugLog("HTTP %d (%v) error=%v", statusCode, elapsed, err)
		return
	}
	preview := string(body)
	if len(preview) > 200 {
		preview = preview[:200] + "...(truncated)"
	}
	debugLog("HTTP %d (%v) body=%s", statusCode, elapsed, preview)
}
