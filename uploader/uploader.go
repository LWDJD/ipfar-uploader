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

// UploadFile uploads a single file through the full IPFAR pipeline:
//  1. Read file
//  2. Create CAR v2
//  3. Compute PoW (if < 100 MiB)
//  4. Upload CAR to Arweave
//  5. Create and upload metadata transaction
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

	// 3. Compute PoW if needed (first pass with empty data_txid)
	if pow.NeedsPoW(result.DataSize) {
		powWorkers := effectivePoWWorkers(u.cfg.PoWWorkers)
		fmt.Printf("   Computing PoW (%d workers)", powWorkers)

		progress := func(info pow.ProgressInfo) {
			if info.Attempts > 0 && info.Attempts%10000 == 0 {
				fmt.Printf("\r   Computing PoW (%d workers): %s hashes (%s), best salt=%d",
					powWorkers, pow.FormatNumber(info.Attempts), pow.FormatSpeed(info.Speed), info.BestSalt)
			}
		}

		powSalt, err := pow.ComputePoWParallelWithProgress(ctx, result.RootCID, "", u.cfg.PoWWorkers, progress)
		if err != nil {
			result.Error = fmt.Errorf("PoW computation failed: %w", err)
			return result, result.Error
		}
		result.PoW = powSalt
		fmt.Printf("\r   PoW: salt=%s                                         \n", powSalt)
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	// 4. Upload CAR file to Arweave
	method := metadata.MethodRaw
	if u.cfg.UseBundle {
		method = metadata.MethodBundle
	}
	result.Method = method

	carTags := metadata.BuildCARTags(result.RootCID, result.DataSize)
	arTags := toArweaveTags(carTags)

	fmt.Printf("   Uploading CAR file (%d bytes)...\n", len(carBytes))

	if u.cfg.UseBundle {
		item, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
		if err != nil {
			result.Error = fmt.Errorf("failed to sign bundle item: %w", err)
			return result, result.Error
		}
		bundleData, err := buildSingleItemBundle(item)
		if err != nil {
			result.Error = fmt.Errorf("failed to build bundle: %w", err)
			return result, result.Error
		}
		// Upload bundle as raw tx
		txID, err := u.cfg.Gateway.UploadDataRaw(bundleData)
		if err != nil {
			result.Error = fmt.Errorf("bundle upload failed: %w", err)
			return result, result.Error
		}
		// For bundle, data_txid = bundle item ID (SHA-256 of signature)
		result.DataTXID = base64.RawURLEncoding.EncodeToString(item.ID)

		// Get bundle TX status
		status, err := u.cfg.Gateway.WaitForConfirmation(txID, 120, 3*time.Second)
		if err != nil {
			result.Error = fmt.Errorf("bundle confirmation failed: %w", err)
			return result, result.Error
		}
		result.DataHeight = status.BlockHeight
		fmt.Printf("   Bundle uploaded: tx=%s, item=%s (height=%d)\n", txID, result.DataTXID, result.DataHeight)
	} else {
		dataTX, dataStatus, err := u.cfg.Gateway.UploadData(u.cfg.Wallet, carBytes, arTags)
		if err != nil {
			result.Error = fmt.Errorf("CAR upload failed: %w", err)
			return result, result.Error
		}
		result.DataTXID = dataTX.ID
		result.DataHeight = dataStatus.BlockHeight
		fmt.Printf("   CAR uploaded: %s (height=%d)\n", result.DataTXID, result.DataHeight)
	}

	// 5. Recompute PoW with actual data_txid
	if pow.NeedsPoW(result.DataSize) {
		powWorkers := effectivePoWWorkers(u.cfg.PoWWorkers)
		fmt.Printf("   Recomputing PoW with data_txid (%d workers)", powWorkers)
		progress2 := func(info pow.ProgressInfo) {
			if info.Attempts > 0 && info.Attempts%10000 == 0 {
				fmt.Printf("\r   Recomputing PoW (%d workers): %s hashes (%s), best salt=%d",
					powWorkers, pow.FormatNumber(info.Attempts), pow.FormatSpeed(info.Speed), info.BestSalt)
			}
		}
		powSalt, err := pow.ComputePoWParallelWithProgress(ctx, result.RootCID, result.DataTXID, u.cfg.PoWWorkers, progress2)
		if err != nil {
			result.Error = fmt.Errorf("PoW recomputation failed: %w", err)
			return result, result.Error
		}
		result.PoW = powSalt
		fmt.Printf("\r   PoW: salt=%s                                         \n", powSalt)
	}

	// 6. Create metadata JSON
	meta := &metadata.Metadata{
		Version:      metadata.Version1,
		Method:       method,
		RootCID:      result.RootCID,
		DataTXID:     result.DataTXID,
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

	// 7. Upload metadata transaction
	metaTags := metadata.BuildMetaTags(result.RootCID, result.DataTXID)
	fmt.Printf("   Uploading metadata...\n")
	metaTX, _, err := u.cfg.Gateway.UploadData(u.cfg.Wallet, []byte(metaBase64), toArweaveTags(metaTags))
	if err != nil {
		result.Error = fmt.Errorf("metadata upload failed: %w", err)
		return result, result.Error
	}
	result.MetaTXID = metaTX.ID
	fmt.Printf("   Metadata uploaded: %s\n", result.MetaTXID)

	return result, nil
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
