// Package uploader 提供 IPFAR 文件上传的核心编排逻辑。
package uploader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LWDJD/ipfar-uploader/arweave"

	"github.com/LWDJD/ipfar-sdk/ipfar"
	sdkpow "github.com/LWDJD/ipfar-sdk/pow"
	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// Config holds uploader configuration.
type Config struct {
	Wallet     *arweave.Wallet
	Gateway    *arweave.GatewayClient
	UseBundle  bool
	BundleSize int  // max items per bundle (0 = all in one)
	PoWWorkers int  // number of parallel PoW workers (0 = use sdkpow.DefaultWorkers())
	Debug      bool // enable verbose debug logging to stderr
}

// NewDefaultConfig creates a config with default Arweave.net gateway.
func NewDefaultConfig() *Config {
	return &Config{
		Gateway:    arweave.NewGatewayClient("https://arweave.net"),
		UseBundle:  false,
		BundleSize: 0,
	}
}

// UploadResult holds the result of a single file upload.
type UploadResult struct {
	FilePath     string
	OriginalName string
	ContentType  string
	DataSize     int64
	RootCID      string
	DataTXID     string
	BundleTXID   string
	DataHeight   int
	MetaTXID     string
	PoW          string
	Method       string
	Error        error
}

// Uploader orchestrates the upload pipeline.
type Uploader struct {
	cfg *Config
}

// New creates a new Uploader.
func New(cfg *Config) *Uploader {
	return &Uploader{cfg: cfg}
}

// UploadFile uploads a single file through the full IPFAR pipeline.
//
// State management: persists progress to {file}.upload.json for dedup & resume.
// The core upload pipeline is delegated to the SDK's ipfar.Upload().
func (u *Uploader) UploadFile(ctx context.Context, filePath string) (*UploadResult, error) {
	debugLog("UploadFile: path=%s", filePath)

	// ── 1. Read file data ────────────────────────────────────────────
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// ── 2. Compute file hash and CID ─────────────────────────────────
	fileHash := computeFileHash(fileData)
	rootCID, err := ipfar.ComputeCID(fileData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute CID: %w", err)
	}
	rootCIDStr := rootCID.String()

	dataSize := int64(len(fileData))
	originalName := filepath.Base(filePath)
	contentType := detectContentType(filePath)

	// Determine method
	method := sdkmeta.MethodRaw
	if u.cfg.UseBundle {
		method = sdkmeta.MethodBundle
	}

	debugLog("UploadFile: dataSize=%d, rootCID=%s, method=%s", dataSize, rootCIDStr, method)

	// ── 3. Load or create state ──────────────────────────────────────
	state, err := LoadState(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}
	if state == nil {
		state = NewUploadState(filePath, rootCIDStr, fileHash, dataSize, method)
	} else if state.FileHash != fileHash {
		// File changed — reset state
		fmt.Printf("   File hash changed, resetting upload state\n")
		state = NewUploadState(filePath, rootCIDStr, fileHash, dataSize, method)
	}

	// ── 4. If already complete, return early ─────────────────────────
	if state.IsComplete() {
		fmt.Printf("   ✅ Already uploaded (car=%s, meta=%s)\n", state.CarTXID, state.MetaTXID)
		return resultFromState(state, filePath, originalName, contentType, method), nil
	}

	// ── 5. Prepare upload options ────────────────────────────────────
	opts := &ipfar.UploadOptions{
		PoWWorkers: u.cfg.PoWWorkers,
		Bundle:     u.cfg.UseBundle,
	}

	// ── 6. Call SDK to upload ────────────────────────────────────────
	fmt.Printf("   Uploading %s (%d bytes)...\n", originalName, dataSize)
	state.TransitionTo(StatusUploading)
	state.Save()

	sdkResult, err := ipfar.Upload(ctx, u.cfg.Gateway.GatewayClient, u.cfg.Wallet, filePath, opts)
	if err != nil {
		state.SetError(err)
		state.Save()
		return nil, fmt.Errorf("upload failed: %w", err)
	}

	// ── 7. Sync results to state ─────────────────────────────────────
	state.CarTXID = sdkResult.DataTXID
	state.MetaTXID = sdkResult.MetaTXID
	state.CarHeight = sdkResult.DataHeight
	state.RootCID = sdkResult.RootCID
	state.DataSize = sdkResult.DataSize
	if u.cfg.UseBundle {
		state.BundleTXID = sdkResult.DataTXID
	}
	state.RetryCount = 0
	state.LastError = ""
	state.TransitionTo(StatusDone)
	state.Save()

	// ── 8. Build and return result ───────────────────────────────────
	result := &UploadResult{
		FilePath:     filePath,
		OriginalName: originalName,
		ContentType:  contentType,
		DataSize:     sdkResult.DataSize,
		RootCID:      sdkResult.RootCID,
		DataTXID:     sdkResult.DataTXID,
		BundleTXID:   state.BundleTXID,
		DataHeight:   sdkResult.DataHeight,
		MetaTXID:     sdkResult.MetaTXID,
		Method:       method,
	}

	fmt.Printf("   ✅ Upload complete (car=%s, meta=%s)\n", result.DataTXID, result.MetaTXID)
	return result, nil
}

// resultFromState builds an UploadResult from a completed state.
func resultFromState(state *UploadState, filePath, originalName, contentType, method string) *UploadResult {
	return &UploadResult{
		FilePath:     filePath,
		OriginalName: originalName,
		ContentType:  contentType,
		DataSize:     state.DataSize,
		RootCID:      state.RootCID,
		DataTXID:     state.CarTXID,
		BundleTXID:   state.BundleTXID,
		DataHeight:   state.CarHeight,
		MetaTXID:     state.MetaTXID,
		Method:       method,
	}
}

// UploadDir uploads all files in a directory.
func (u *Uploader) UploadDir(ctx context.Context, dirPath string) ([]*UploadResult, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(dirPath, entry.Name()))
		}
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no files in directory")
	}

	var results []*UploadResult
	for _, f := range files {
		result, err := u.UploadFile(ctx, f)
		results = append(results, result)
		if err != nil {
			fmt.Printf("   Warning: %v\n", err)
		}
	}

	return results, nil
}

// =============================================================================
// Helpers (retained)
// =============================================================================

// detectContentType returns a MIME type based on file extension.
func detectContentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	mimeTypes := map[string]string{
		".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".png": "image/png", ".gif": "image/gif",
		".webp": "image/webp", ".svg": "image/svg+xml",
		".mp4": "video/mp4", ".webm": "video/webm",
		".mp3": "audio/mpeg", ".wav": "audio/wav",
		".ogg": "audio/ogg", ".flac": "audio/flac",
		".pdf": "application/pdf",
		".json": "application/json", ".xml": "application/xml",
		".html": "text/html", ".htm": "text/html",
		".css": "text/css", ".js": "application/javascript",
		".txt": "text/plain", ".md": "text/markdown",
		".zip": "application/zip", ".tar": "application/x-tar",
		".gz": "application/gzip", ".bz2": "application/x-bzip2",
		".car": "application/vnd.ipld.car",
	}
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

func toArweaveTags(tags []sdkmeta.Tag) []arweave.Tag {
	result := make([]arweave.Tag, len(tags))
	for i, t := range tags {
		result[i] = arweave.Tag{Name: t.Name, Value: t.Value}
	}
	return result
}

// effectivePoWWorkers returns the actual number of PoW workers to use.
func effectivePoWWorkers(cfgWorkers int) int {
	if cfgWorkers > 0 {
		return cfgWorkers
	}
	return sdkpow.DefaultWorkers()
}

// reportPoWProgress prints a one-line PoW progress report.
func reportPoWProgress(label string, workers int, attempts uint64, speed float64, found bool, salt string) {
	const expectedTotal = 65536
	pct := float64(attempts) / float64(expectedTotal) * 100
	eta := ""
	if speed > 0 {
		remaining := int((float64(expectedTotal) - float64(attempts)) / speed)
		if remaining > 0 {
			if remaining >= 3600 {
				eta = fmt.Sprintf("%dh%dm", remaining/3600, (remaining%3600)/60)
			} else if remaining >= 60 {
				eta = fmt.Sprintf("%dm%ds", remaining/60, remaining%60)
			} else {
				eta = fmt.Sprintf("%ds", remaining)
			}
		}
	}
	saltInfo := ""
	if found && salt != "" {
		saltInfo = fmt.Sprintf(", salt=%s", salt)
	}
	if eta != "" {
		fmt.Printf("\r   %s PoW (%d workers): %s hashes (%s) - %.1f%% ETA %s%s     ",
			label, workers, sdkpow.FormatNumber(attempts), sdkpow.FormatSpeed(speed), pct, eta, saltInfo)
	} else {
		fmt.Printf("\r   %s PoW (%d workers): %s hashes (%s) - %.1f%%%s     ",
			label, workers, sdkpow.FormatNumber(attempts), sdkpow.FormatSpeed(speed), pct, saltInfo)
	}
}
