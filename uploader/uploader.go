// Package uploader 提供 IPFAR 文件上传的核心编排逻辑。
package uploader

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LWDJD/ipfar-uploader/arweave"
	"github.com/LWDJD/ipfar-uploader/car"
	"github.com/LWDJD/ipfar-uploader/metadata"
	"github.com/LWDJD/ipfar-uploader/pow"
)

// Config holds uploader configuration.
type Config struct {
	Wallet     *arweave.Wallet
	Gateway    *arweave.GatewayClient
	UseBundle  bool
	BundleSize int // max items per bundle (0 = all in one)
	PoWWorkers int // number of parallel PoW workers (0 = use pow.DefaultWorkers())
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
// Three upload methods are supported:
//   - raw:          PoW → upload CAR (wait) → build metadata → upload metadata
//                   data_height = actual block height, no bundle_txid.
//   - bundle:       PoW → sign CAR item → build metadata → sign metadata item
//                   → bundle both → upload bundle as raw tx.
//                   data_height = -1, bundle_txid = "none".
//   - cross-bundle: PoW → sign CAR item → upload CAR as single-item bundle
//                   → build metadata → upload metadata separately.
//                   data_height = actual block height, bundle_txid = actual bundle TX ID.
func (u *Uploader) UploadFile(ctx context.Context, filePath string) (*UploadResult, error) {
	result := &UploadResult{
		FilePath: filePath,
	}

	// 1. Read file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to read file: %w", err)
		return result, result.Error
	}

	result.DataSize = int64(len(fileData))
	result.OriginalName = filepath.Base(filePath)
	result.ContentType = detectContentType(filePath)

	// 2. Create CAR v2 in memory
	carBytes, rootCID, err := car.CreateCarV2FromBytes(fileData)
	if err != nil {
		result.Error = fmt.Errorf("failed to create CAR v2: %w", err)
		return result, result.Error
	}
	result.RootCID = rootCID.String()

	// Determine method
	method := metadata.MethodRaw
	if u.cfg.UseBundle {
		method = metadata.MethodBundle
	}
	result.Method = method

	cachePath := filePath + ".pow.json"
	carTags := metadata.BuildCARTags(result.RootCID, result.DataSize)
	arTags := toArweaveTags(carTags)

	switch method {
	case metadata.MethodRaw:
		return u.uploadRaw(ctx, result, carBytes, cachePath, arTags)
	case metadata.MethodBundle:
		return u.uploadBundle(ctx, result, carBytes, cachePath, arTags)
	default:
		result.Error = fmt.Errorf("unknown method: %s", method)
		return result, result.Error
	}
}

// uploadRaw handles the raw Arweave transaction flow:
// PoW → upload CAR (wait) → build metadata → upload metadata.
func (u *Uploader) uploadRaw(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	// 3a. Compute PoW (first pass with empty data_txid)
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWFirstPass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, err
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	// 4a. Upload CAR file
	fmt.Printf("   Uploading CAR file (%d bytes)...\n", len(carBytes))
	dataTX, dataStatus, err := u.cfg.Gateway.UploadData(u.cfg.Wallet, carBytes, arTags)
	if err != nil {
		result.Error = fmt.Errorf("CAR upload failed: %w", err)
		return result, result.Error
	}
	result.DataTXID = dataTX.ID
	result.DataHeight = dataStatus.BlockHeight
	fmt.Printf("   CAR uploaded: %s (height=%d)\n", result.DataTXID, result.DataHeight)

	// 5a. Recompute PoW with actual data_txid
	if pow.NeedsPoW(result.DataSize) {
		if err := u.recomputePoW(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, err
		}
	}

	// 6a. Build and upload metadata
	if err := u.uploadMetadata(ctx, result); err != nil {
		result.Error = err
		return result, err
	}

	return result, nil
}

// uploadBundle handles the same-bundle flow:
// Sign CAR item → compute PoW → build metadata item → bundle both → upload.
func (u *Uploader) uploadBundle(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	// 3b. Sign CAR data as a bundle item (data_txid is known at this point)
	carItem, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign CAR bundle item: %w", err)
		return result, result.Error
	}
	carItemID := base64.RawURLEncoding.EncodeToString(carItem.ID)
	result.DataTXID = carItemID
	fmt.Printf("   CAR item signed: %s\n", carItemID)

	// 4b. Compute PoW with actual data_txid (single pass)
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWSinglePass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, err
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	// 5b. Build metadata JSON (data_height=-1, bundle_txid="none")
	result.DataHeight = -1
	result.BundleTXID = "none"

	meta := &metadata.Metadata{
		Version:      metadata.Version1,
		Method:       metadata.MethodBundle,
		RootCID:      result.RootCID,
		DataTXID:     result.DataTXID,
		BundleTXID:   result.BundleTXID,
		DataHeight:   result.DataHeight,
		DataSize:     int(result.DataSize),
		ContentType:  result.ContentType,
		OriginalName: result.OriginalName,
	}
	if pow.NeedsPoW(result.DataSize) {
		meta.PoW = result.PoW
		meta.PoWAlg = pow.Algorithm
	}

	metaJSON, err := meta.ToJSON()
	if err != nil {
		result.Error = fmt.Errorf("failed to serialize metadata: %w", err)
		return result, result.Error
	}
	metaBase64 := base64.RawURLEncoding.EncodeToString(metaJSON)

	// 6b. Sign metadata as a bundle item
	metaTags := metadata.BuildMetaTags(result.RootCID, result.DataTXID)
	metaArTags := toArweaveTags(metaTags)
	metaItem, err := arweave.SignBundleItem([]byte(metaBase64), metaArTags, u.cfg.Wallet, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign metadata bundle item: %w", err)
		return result, result.Error
	}
	metaItemID := base64.RawURLEncoding.EncodeToString(metaItem.ID)
	result.MetaTXID = metaItemID
	fmt.Printf("   Metadata item signed: %s\n", metaItemID)

	// 7b. Bundle both items together
	bb := arweave.NewBundleBuilder()
	bb.AddItem(*carItem)
	bb.AddItem(*metaItem)
	bundleData, err := bb.Build()
	if err != nil {
		result.Error = fmt.Errorf("failed to build bundle: %w", err)
		return result, result.Error
	}

	// 8b. Upload bundle as raw tx
	fmt.Printf("   Uploading bundle (2 items, %d bytes)...\n", len(bundleData))
	bundleTXID, err := u.cfg.Gateway.UploadDataRaw(bundleData)
	if err != nil {
		result.Error = fmt.Errorf("bundle upload failed: %w", err)
		return result, result.Error
	}
	fmt.Printf("   Bundle uploaded: %s\n", bundleTXID)

	// Wait for confirmation (best effort)
	status, err := u.cfg.Gateway.WaitForConfirmation(bundleTXID, 120, 3*time.Second)
	if err != nil {
		fmt.Printf("   Warning: bundle confirmation check failed: %v\n", err)
	} else {
		fmt.Printf("   Bundle confirmed at height=%d\n", status.BlockHeight)
	}

	return result, nil
}

// uploadCrossBundle handles the cross-bundle flow:
// Sign CAR item → upload as single-item bundle → build metadata → upload metadata separately.
// Reserved for future use; not wired into the public API yet.
func (u *Uploader) uploadCrossBundle(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	// 3c. Sign CAR data as a bundle item
	carItem, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign CAR bundle item: %w", err)
		return result, result.Error
	}
	carItemID := base64.RawURLEncoding.EncodeToString(carItem.ID)
	result.DataTXID = carItemID

	// First pass PoW (empty data_txid for now, will recompute later)
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWFirstPass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, err
		}
	}

	// 4c. Wrap in single-item bundle and upload
	bundleData, err := buildSingleItemBundle(carItem)
	if err != nil {
		result.Error = fmt.Errorf("failed to build bundle: %w", err)
		return result, result.Error
	}
	bundleTXID, err := u.cfg.Gateway.UploadDataRaw(bundleData)
	if err != nil {
		result.Error = fmt.Errorf("bundle upload failed: %w", err)
		return result, result.Error
	}
	result.BundleTXID = bundleTXID
	fmt.Printf("   CAR bundle uploaded: bundle_tx=%s, item=%s\n", bundleTXID, carItemID)

	// Wait for confirmation to get block height
	status, err := u.cfg.Gateway.WaitForConfirmation(bundleTXID, 120, 3*time.Second)
	if err != nil {
		result.Error = fmt.Errorf("bundle confirmation failed: %w", err)
		return result, result.Error
	}
	result.DataHeight = status.BlockHeight
	fmt.Printf("   Bundle confirmed at height=%d\n", result.DataHeight)

	// 5c. Compute PoW with actual data_txid
	if pow.NeedsPoW(result.DataSize) {
		if err := u.recomputePoW(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, err
		}
	}

	// 6c. Build and upload metadata with bundle_txid set
	if err := u.uploadMetadata(ctx, result); err != nil {
		result.Error = err
		return result, err
	}

	return result, nil
}

// computePoWFirstPass computes PoW with empty data_txid (for raw mode).
func (u *Uploader) computePoWFirstPass(ctx context.Context, result *UploadResult, cachePath string) error {
	powWorkers := effectivePoWWorkers(u.cfg.PoWWorkers)

	if cachedSalt, ok := pow.LoadPoWCache(cachePath, result.RootCID, ""); ok {
		result.PoW = cachedSalt
		fmt.Printf("   PoW loaded from cache (%s) — salt=%s\n", cachePath, cachedSalt)
		return nil
	}

	fmt.Printf("   Computing PoW (%d workers)", powWorkers)
	var lastPrint time.Time
	var totalAttempts uint64
	progress := func(info pow.ProgressInfo) {
		totalAttempts = info.Attempts
		now := time.Now()
		if info.Attempts == 0 || now.Sub(lastPrint) < time.Second {
			return
		}
		lastPrint = now
		reportPoWProgress("Computing", powWorkers, info)
	}

	start := time.Now()
	powSalt, err := pow.ComputePoWParallelWithProgress(ctx, result.RootCID, "", u.cfg.PoWWorkers, progress)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("PoW computation failed: %w", err)
	}
	result.PoW = powSalt
	fmt.Printf("\r   PoW completed: %s hashes in %.1fs — salt=%s                                         \n",
		pow.FormatNumber(totalAttempts), elapsed.Seconds(), powSalt)

	if saveErr := pow.SavePoWCache(cachePath, result.RootCID, "", powSalt); saveErr != nil {
		fmt.Fprintf(os.Stderr, "   Warning: failed to save PoW cache: %v\n", saveErr)
	}
	return nil
}

// computePoWSinglePass computes PoW with the already-known data_txid (for bundle mode).
func (u *Uploader) computePoWSinglePass(ctx context.Context, result *UploadResult, cachePath string) error {
	powWorkers := effectivePoWWorkers(u.cfg.PoWWorkers)

	if cachedSalt, ok := pow.LoadPoWCache(cachePath, result.RootCID, result.DataTXID); ok {
		result.PoW = cachedSalt
		fmt.Printf("   PoW loaded from cache (%s) — salt=%s\n", cachePath, cachedSalt)
		return nil
	}

	fmt.Printf("   Computing PoW (%d workers)", powWorkers)
	var lastPrint time.Time
	var totalAttempts uint64
	progress := func(info pow.ProgressInfo) {
		totalAttempts = info.Attempts
		now := time.Now()
		if info.Attempts == 0 || now.Sub(lastPrint) < time.Second {
			return
		}
		lastPrint = now
		reportPoWProgress("Computing", powWorkers, info)
	}

	start := time.Now()
	powSalt, err := pow.ComputePoWParallelWithProgress(ctx, result.RootCID, result.DataTXID, u.cfg.PoWWorkers, progress)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("PoW computation failed: %w", err)
	}
	result.PoW = powSalt
	fmt.Printf("\r   PoW completed: %s hashes in %.1fs — salt=%s                                         \n",
		pow.FormatNumber(totalAttempts), elapsed.Seconds(), powSalt)

	if saveErr := pow.SavePoWCache(cachePath, result.RootCID, result.DataTXID, powSalt); saveErr != nil {
		fmt.Fprintf(os.Stderr, "   Warning: failed to save PoW cache: %v\n", saveErr)
	}
	return nil
}

// recomputePoW recomputes PoW with the actual data_txid (second pass for raw/cross-bundle).
func (u *Uploader) recomputePoW(ctx context.Context, result *UploadResult, cachePath string) error {
	powWorkers := effectivePoWWorkers(u.cfg.PoWWorkers)

	if cachedSalt, ok := pow.LoadPoWCache(cachePath, result.RootCID, result.DataTXID); ok {
		result.PoW = cachedSalt
		fmt.Printf("   PoW loaded from cache (%s) — salt=%s\n", cachePath, cachedSalt)
		return nil
	}

	fmt.Printf("   Recomputing PoW with data_txid (%d workers)", powWorkers)
	var lastPrint time.Time
	var totalAttempts uint64
	progress := func(info pow.ProgressInfo) {
		totalAttempts = info.Attempts
		now := time.Now()
		if info.Attempts == 0 || now.Sub(lastPrint) < time.Second {
			return
		}
		lastPrint = now
		reportPoWProgress("Recomputing", powWorkers, info)
	}

	start := time.Now()
	powSalt, err := pow.ComputePoWParallelWithProgress(ctx, result.RootCID, result.DataTXID, u.cfg.PoWWorkers, progress)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("PoW recomputation failed: %w", err)
	}
	result.PoW = powSalt
	fmt.Printf("\r   PoW completed: %s hashes in %.1fs — salt=%s                                         \n",
		pow.FormatNumber(totalAttempts), elapsed.Seconds(), powSalt)

	if saveErr := pow.SavePoWCache(cachePath, result.RootCID, result.DataTXID, powSalt); saveErr != nil {
		fmt.Fprintf(os.Stderr, "   Warning: failed to save PoW cache: %v\n", saveErr)
	}
	return nil
}

// uploadMetadata builds the metadata JSON and uploads it to Arweave as a raw transaction.
func (u *Uploader) uploadMetadata(ctx context.Context, result *UploadResult) error {
	meta := &metadata.Metadata{
		Version:      metadata.Version1,
		Method:       result.Method,
		RootCID:      result.RootCID,
		DataTXID:     result.DataTXID,
		BundleTXID:   result.BundleTXID,
		DataHeight:   result.DataHeight,
		DataSize:     int(result.DataSize),
		ContentType:  result.ContentType,
		OriginalName: result.OriginalName,
	}
	if pow.NeedsPoW(result.DataSize) {
		meta.PoW = result.PoW
		meta.PoWAlg = pow.Algorithm
	}

	metaJSON, err := meta.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}
	metaBase64 := base64.RawURLEncoding.EncodeToString(metaJSON)

	metaTags := metadata.BuildMetaTags(result.RootCID, result.DataTXID)
	fmt.Printf("   Uploading metadata...\n")
	metaTX, _, err := u.cfg.Gateway.UploadData(u.cfg.Wallet, []byte(metaBase64), toArweaveTags(metaTags))
	if err != nil {
		return fmt.Errorf("metadata upload failed: %w", err)
	}
	result.MetaTXID = metaTX.ID
	fmt.Printf("   Metadata uploaded: %s\n", result.MetaTXID)
	return nil
}

// reportPoWProgress prints a one-line PoW progress report.
func reportPoWProgress(label string, workers int, info pow.ProgressInfo) {
	const expectedTotal = 65536
	pct := float64(info.Attempts) / float64(expectedTotal) * 100
	eta := ""
	if info.Speed > 0 {
		remaining := int((float64(expectedTotal) - float64(info.Attempts)) / info.Speed)
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
	if eta != "" {
		fmt.Printf("\r   %s PoW (%d workers): %s hashes (%s) - %.1f%% ETA %s, best salt=%d     ",
			label, workers, pow.FormatNumber(info.Attempts), pow.FormatSpeed(info.Speed), pct, eta, info.BestSalt)
	} else {
		fmt.Printf("\r   %s PoW (%d workers): %s hashes (%s) - %.1f%%, best salt=%d     ",
			label, workers, pow.FormatNumber(info.Attempts), pow.FormatSpeed(info.Speed), pct, info.BestSalt)
	}
}

// buildSingleItemBundle wraps a single BundleItem into a bundle binary.
func buildSingleItemBundle(item *arweave.BundleItem) ([]byte, error) {
	bb := arweave.NewBundleBuilder()
	bb.AddItem(*item)
	return bb.Build()
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

func toArweaveTags(tags []metadata.Tag) []arweave.Tag {
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
	return pow.DefaultWorkers()
}
