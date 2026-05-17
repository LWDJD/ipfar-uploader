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
// State management: persists progress to {file}.upload.json for dedup & resume.
func (u *Uploader) UploadFile(ctx context.Context, filePath string) (*UploadResult, error) {
	result := &UploadResult{
		FilePath: filePath,
	}

	// ── Pre-flight: compute file hash, create CAR ─────────────────────
	fileHash, err := ComputeFileHash(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to hash file: %w", err)
		return result, result.Error
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to read file: %w", err)
		return result, result.Error
	}

	result.DataSize = int64(len(fileData))
	result.OriginalName = filepath.Base(filePath)
	result.ContentType = detectContentType(filePath)

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

	// ── Load or create state ──────────────────────────────────────────
	state, err := LoadState(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to load state: %w", err)
		return result, result.Error
	}
	if state == nil {
		state = NewUploadState(filePath, result.RootCID, fileHash, result.DataSize, method)
	} else if state.FileHash != fileHash {
		// File changed — reset state
		fmt.Printf("   File hash changed, resetting upload state\n")
		state = NewUploadState(filePath, result.RootCID, fileHash, result.DataSize, method)
	}

	// ── Dedup: check GraphQL for existing CAR ─────────────────────────
	if state.NeedsCARUpload() {
		existingTX, gqlErr := u.cfg.Gateway.QueryExistingCAR(result.RootCID)
		if gqlErr != nil {
			fmt.Printf("   Warning: GraphQL dedup check failed: %v\n", gqlErr)
		} else if existingTX != "" {
			fmt.Printf("   Found existing CAR on chain: %s\n", existingTX)
			state.CarTXID = existingTX
			state.CarConfirmed = true
			state.CarHeight = 0 // unknown, but confirmed
			if err := state.TransitionTo(StatusCarConfirmed); err != nil {
				state.Status = StatusCarConfirmed
			}
			if saveErr := state.Save(); saveErr != nil {
				fmt.Printf("   Warning: failed to save state: %v\n", saveErr)
			}
		}
	}

	// ── Check if already complete ─────────────────────────────────────
	if state.IsComplete() {
		fmt.Printf("   ✅ Already uploaded (car=%s, meta=%s)\n", state.CarTXID, state.MetaTXID)
		result.DataTXID = state.CarTXID
		result.DataHeight = state.CarHeight
		result.MetaTXID = state.MetaTXID
		result.BundleTXID = state.BundleTXID
		return result, nil
	}

	// ── Resume: handle car_submitted but not confirmed ────────────────
	if state.Status == StatusCarSubmitted && !state.CarConfirmed && state.CarTXID != "" {
		u.handleCarResume(ctx, state)
	}

	// ── CAR upload (if needed) ────────────────────────────────────────
	if state.NeedsCARUpload() {
		if err := u.uploadCarWithState(ctx, result, carBytes, state); err != nil {
			result.Error = err
			state.SetError(err)
			state.Save()
			return result, err
		}
	}

	// ── Metadata upload (if needed) ───────────────────────────────────
	if state.NeedsMetaUpload() {
		if err := u.uploadMetaWithState(ctx, result, state); err != nil {
			result.Error = err
			state.SetError(err)
			state.Save()
			return result, err
		}
	}

	// ── Mark done ─────────────────────────────────────────────────────
	if err := state.TransitionTo(StatusDone); err != nil {
		state.Status = StatusDone
	}
	state.LastError = ""
	if saveErr := state.Save(); saveErr != nil {
		fmt.Printf("   Warning: failed to save final state: %v\n", saveErr)
	}

	// Sync result from state
	result.DataTXID = state.CarTXID
	result.DataHeight = state.CarHeight
	result.MetaTXID = state.MetaTXID
	result.BundleTXID = state.BundleTXID

	return result, nil
}

// =============================================================================
// CAR upload with state tracking
// =============================================================================

// uploadCarWithState uploads the CAR with full state tracking.
// Supports: raw, bundle, and chunked flows.
func (u *Uploader) uploadCarWithState(ctx context.Context, result *UploadResult, carBytes []byte, state *UploadState) error {
	cachePath := state.FilePath + ".pow.json"
	carTags := metadata.BuildCARTags(result.RootCID, result.DataSize)
	arTags := toArweaveTags(carTags)

	switch state.Method {
	case metadata.MethodRaw:
		return u.uploadCarRaw(ctx, result, carBytes, state, cachePath, arTags)
	case metadata.MethodBundle:
		return u.uploadCarBundle(ctx, result, carBytes, state, cachePath, arTags)
	default:
		return fmt.Errorf("unknown method: %s", state.Method)
	}
}

// uploadCarRaw uploads CAR as a raw Arweave transaction with state tracking.
func (u *Uploader) uploadCarRaw(ctx context.Context, result *UploadResult, carBytes []byte, state *UploadState, cachePath string, arTags []arweave.Tag) error {
	// Already confirmed?
	if state.CarConfirmed {
		result.DataTXID = state.CarTXID
		result.DataHeight = state.CarHeight
		return nil
	}

	// Compute PoW (first pass with empty data_txid)
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWFirstPass(ctx, result, cachePath); err != nil {
			return err
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	state.TransitionTo(StatusCarUploading)
	state.Save()

	// Build, sign and submit the transaction
	fmt.Printf("   Uploading CAR file (%d bytes)...\n", len(carBytes))

	anchor, err := u.cfg.Gateway.GetAnchor()
	if err != nil {
		anchor = ""
	}

	reward, err := u.cfg.Gateway.GetReward(int64(len(carBytes)))
	if err != nil {
		reward = "0"
	}

	tb := arweave.NewTransactionBuilder(u.cfg.Wallet.Owner)
	tb.SetData(carBytes)
	tb.SetTags(arTags)
	tb.SetLastTx(anchor)
	tb.SetReward(reward)

	tx := tb.Build()
	if err := tx.Sign(u.cfg.Wallet.PrivateKey); err != nil {
		state.SetError(fmt.Errorf("failed to sign CAR tx: %w", err))
		state.Save()
		return stateError(state)
	}

	txID, err := u.cfg.Gateway.SubmitTransaction(tx)
	if err != nil {
		state.SetError(fmt.Errorf("failed to submit CAR tx: %w", err))
		state.Save()
		return stateError(state)
	}
	tx.ID = txID

	state.CarTXID = txID
	state.CarSubmittedAt = TimeNow()
	state.TransitionTo(StatusCarSubmitted)
	state.Save()

	fmt.Printf("   CAR submitted: %s\n", txID)

	// Wait for confirmation
	status, err := u.cfg.Gateway.WaitForConfirmation(txID, 120, 3*time.Second)
	if err != nil {
		// Don't mark as error — allow resume
		fmt.Printf("   Warning: CAR confirmation wait failed: %v\n", err)
		state.SetError(fmt.Errorf("CAR confirmation timeout: %w", err))
		state.Save()
		return fmt.Errorf("CAR confirmation timeout (txid saved for resume): %w", err)
	}

	state.CarConfirmed = true
	state.CarHeight = status.BlockHeight
	state.TransitionTo(StatusCarConfirmed)
	state.RetryCount = 0
	state.LastError = ""
	state.Save()

	result.DataTXID = txID
	result.DataHeight = status.BlockHeight
	fmt.Printf("   CAR confirmed at height=%d\n", status.BlockHeight)

	// Recompute PoW with actual data_txid
	if pow.NeedsPoW(result.DataSize) {
		if err := u.recomputePoW(ctx, result, cachePath); err != nil {
			return err
		}
	}

	return nil
}

// uploadCarBundle uploads CAR+meta as a single bundle tx with state tracking.
func (u *Uploader) uploadCarBundle(ctx context.Context, result *UploadResult, carBytes []byte, state *UploadState, cachePath string, arTags []arweave.Tag) error {
	if state.CarConfirmed {
		result.DataTXID = state.CarTXID
		result.DataHeight = state.CarHeight
		result.BundleTXID = state.BundleTXID
		result.MetaTXID = state.MetaTXID
		return nil
	}

	// Sign CAR data as a bundle item
	carItem, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
	if err != nil {
		state.SetError(fmt.Errorf("failed to sign CAR bundle item: %w", err))
		state.Save()
		return stateError(state)
	}
	carItemID := base64.RawURLEncoding.EncodeToString(carItem.ID)
	result.DataTXID = carItemID
	fmt.Printf("   CAR item signed: %s\n", carItemID)

	// Compute PoW
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWSinglePass(ctx, result, cachePath); err != nil {
			return err
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	// Build metadata
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
		state.SetError(fmt.Errorf("failed to serialize metadata: %w", err))
		state.Save()
		return stateError(state)
	}
	metaBase64 := base64.RawURLEncoding.EncodeToString(metaJSON)

	// Sign metadata as a bundle item
	metaTags := metadata.BuildMetaTags(result.RootCID, result.DataTXID)
	metaArTags := toArweaveTags(metaTags)
	metaItem, err := arweave.SignBundleItem([]byte(metaBase64), metaArTags, u.cfg.Wallet, nil)
	if err != nil {
		state.SetError(fmt.Errorf("failed to sign metadata bundle item: %w", err))
		state.Save()
		return stateError(state)
	}
	metaItemID := base64.RawURLEncoding.EncodeToString(metaItem.ID)
	result.MetaTXID = metaItemID
	fmt.Printf("   Metadata item signed: %s\n", metaItemID)

	// Build bundle
	bb := arweave.NewBundleBuilder()
	bb.AddItem(*carItem)
	bb.AddItem(*metaItem)
	bundleData, err := bb.Build()
	if err != nil {
		state.SetError(fmt.Errorf("failed to build bundle: %w", err))
		state.Save()
		return stateError(state)
	}

	state.TransitionTo(StatusCarUploading)
	state.Save()

	// Submit bundle as raw tx
	fmt.Printf("   Uploading bundle (2 items, %d bytes)...\n", len(bundleData))
	bundleTXID, err := u.cfg.Gateway.UploadDataRaw(bundleData)
	if err != nil {
		state.SetError(fmt.Errorf("bundle upload failed: %w", err))
		state.Save()
		return stateError(state)
	}

	state.CarTXID = bundleTXID // the bundle tx is the "CAR tx" for state tracking
	state.BundleTXID = bundleTXID
	state.CarSubmittedAt = TimeNow()
	state.TransitionTo(StatusCarSubmitted)
	state.Save()
	fmt.Printf("   Bundle submitted: %s\n", bundleTXID)

	// Wait for confirmation
	status, err := u.cfg.Gateway.WaitForConfirmation(bundleTXID, 120, 3*time.Second)
	if err != nil {
		fmt.Printf("   Warning: Bundle confirmation check failed: %v\n", err)
		state.SetError(fmt.Errorf("bundle confirmation timeout: %w", err))
		state.Save()
		return fmt.Errorf("bundle confirmation timeout (txid saved for resume): %w", err)
	}

	// Bundle confirmed — both CAR and meta are done
	state.CarConfirmed = true
	state.CarHeight = status.BlockHeight
	state.MetaTXID = metaItemID
	state.MetaConfirmed = true
	state.MetaHeight = status.BlockHeight
	state.RetryCount = 0
	state.LastError = ""
	state.Status = StatusDone
	state.Save()

	result.DataTXID = carItemID
	result.DataHeight = -1
	result.BundleTXID = bundleTXID
	result.MetaTXID = metaItemID
	fmt.Printf("   Bundle confirmed at height=%d\n", status.BlockHeight)

	return nil
}

// =============================================================================
// Metadata upload with state tracking
// =============================================================================

// uploadMetaWithState uploads metadata as a raw Arweave transaction.
func (u *Uploader) uploadMetaWithState(ctx context.Context, result *UploadResult, state *UploadState) error {
	if state.MetaConfirmed {
		result.MetaTXID = state.MetaTXID
		return nil
	}

	meta := &metadata.Metadata{
		Version:      metadata.Version1,
		Method:       state.Method,
		RootCID:      state.RootCID,
		DataTXID:     state.CarTXID,
		BundleTXID:   state.BundleTXID,
		DataHeight:   state.CarHeight,
		DataSize:     int(state.DataSize),
		ContentType:  result.ContentType,
		OriginalName: result.OriginalName,
	}
	if pow.NeedsPoW(result.DataSize) {
		meta.PoW = result.PoW
		meta.PoWAlg = pow.Algorithm
	}

	metaJSON, err := meta.ToJSON()
	if err != nil {
		state.SetError(fmt.Errorf("failed to serialize metadata: %w", err))
		state.Save()
		return stateError(state)
	}
	metaBase64 := base64.RawURLEncoding.EncodeToString(metaJSON)

	metaTags := metadata.BuildMetaTags(state.RootCID, state.CarTXID)

	// Transition to uploading
	state.TransitionTo(StatusMetaUploading)
	state.Save()

	// Build, sign, submit
	fmt.Printf("   Uploading metadata...\n")

	anchor, err := u.cfg.Gateway.GetAnchor()
	if err != nil {
		anchor = ""
	}
	reward, err := u.cfg.Gateway.GetReward(int64(len(metaBase64)))
	if err != nil {
		reward = "0"
	}

	tb := arweave.NewTransactionBuilder(u.cfg.Wallet.Owner)
	tb.SetData([]byte(metaBase64))
	tb.SetTags(toArweaveTags(metaTags))
	tb.SetLastTx(anchor)
	tb.SetReward(reward)

	tx := tb.Build()
	if err := tx.Sign(u.cfg.Wallet.PrivateKey); err != nil {
		state.SetError(fmt.Errorf("failed to sign meta tx: %w", err))
		state.Save()
		return stateError(state)
	}

	metaTXID, err := u.cfg.Gateway.SubmitTransaction(tx)
	if err != nil {
		state.SetError(fmt.Errorf("failed to submit meta tx: %w", err))
		state.Save()
		return stateError(state)
	}
	tx.ID = metaTXID

	state.MetaTXID = metaTXID
	state.MetaSubmittedAt = TimeNow()
	state.TransitionTo(StatusMetaSubmitted)
	state.Save()
	fmt.Printf("   Metadata submitted: %s\n", metaTXID)

	// Wait for confirmation
	status, err := u.cfg.Gateway.WaitForConfirmation(metaTXID, 120, 3*time.Second)
	if err != nil {
		fmt.Printf("   Warning: Metadata confirmation wait failed: %v\n", err)
		state.SetError(fmt.Errorf("meta confirmation timeout: %w", err))
		state.Save()
		return fmt.Errorf("meta confirmation timeout (txid saved for resume): %w", err)
	}

	state.MetaConfirmed = true
	state.MetaHeight = status.BlockHeight
	state.RetryCount = 0
	state.LastError = ""
	state.TransitionTo(StatusMetaConfirmed)
	state.Save()

	result.MetaTXID = metaTXID
	fmt.Printf("   Metadata confirmed at height=%d\n", status.BlockHeight)

	return nil
}

// =============================================================================
// Resume: handle partially-completed uploads
// =============================================================================

// handleCarResume checks the status of a previously-submitted CAR transaction
// and updates state accordingly.
func (u *Uploader) handleCarResume(ctx context.Context, state *UploadState) {
	fmt.Printf("   Resuming: checking CAR tx %s...\n", state.CarTXID)

	status, err := u.cfg.Gateway.GetTransactionStatus(state.CarTXID)
	if err != nil {
		fmt.Printf("   Warning: failed to check CAR tx status: %v\n", err)
		// If we can't check, see if we should resubmit
		if state.CanResubmitCAR() {
			fmt.Printf("   CAR tx status unknown and timed out, will resubmit\n")
			state.CarTXID = ""
			state.CarConfirmed = false
			state.CarSubmittedAt = ""
			state.RetryCount++
			state.Status = StatusPending
			state.Save()
		}
		return
	}

	if status.Confirmed && status.BlockHeight > 0 {
		fmt.Printf("   CAR tx confirmed at height=%d\n", status.BlockHeight)
		state.CarConfirmed = true
		state.CarHeight = status.BlockHeight
		if err := state.TransitionTo(StatusCarConfirmed); err != nil {
			state.Status = StatusCarConfirmed
		}
		state.LastError = ""
		state.Save()
		return
	}

	// Not yet confirmed
	if state.CanResubmitCAR() {
		fmt.Printf("   CAR tx not confirmed after %s, will resubmit (retry %d/%d)\n",
			time.Since(parseSubmittedAt(state.CarSubmittedAt)).Round(time.Second),
			state.RetryCount+1, maxRetries)
		state.CarTXID = ""
		state.CarConfirmed = false
		state.CarSubmittedAt = ""
		state.RetryCount++
		state.Status = StatusPending
		state.Save()
	} else if state.ShouldWaitForCAR() {
		fmt.Printf("   CAR tx not yet confirmed, continuing to wait...\n")
		// Block and wait for confirmation
		status, err := u.cfg.Gateway.WaitForConfirmation(state.CarTXID, 120, 3*time.Second)
		if err != nil {
			fmt.Printf("   Warning: CAR confirmation wait failed: %v\n", err)
			state.SetError(fmt.Errorf("CAR confirmation timeout on resume: %w", err))
			state.Save()
			return
		}
		fmt.Printf("   CAR tx confirmed at height=%d\n", status.BlockHeight)
		state.CarConfirmed = true
		state.CarHeight = status.BlockHeight
		if err := state.TransitionTo(StatusCarConfirmed); err != nil {
			state.Status = StatusCarConfirmed
		}
		state.LastError = ""
		state.Save()
	} else {
		fmt.Printf("   CAR tx not confirmed and retries exhausted, will resubmit anyway\n")
		state.CarTXID = ""
		state.CarConfirmed = false
		state.CarSubmittedAt = ""
		state.RetryCount++
		state.Status = StatusPending
		state.Save()
	}
}

func parseSubmittedAt(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05-07:00",
		} {
			if t, err = time.Parse(layout, s); err == nil {
				return t
			}
		}
		return time.Time{}
	}
	return t
}

// =============================================================================
// PoW helpers (unchanged)
// =============================================================================

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

// recomputePoW recomputes PoW with the actual data_txid (second pass for raw).
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

// =============================================================================
// Legacy methods (kept for backward compatibility)
// =============================================================================

// uploadRaw handles the raw Arweave transaction flow (legacy, without state).
func (u *Uploader) uploadRaw(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWFirstPass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, result.Error
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

	fmt.Printf("   Uploading CAR file (%d bytes)...\n", len(carBytes))
	dataTX, dataStatus, err := u.cfg.Gateway.UploadData(u.cfg.Wallet, carBytes, arTags)
	if err != nil {
		result.Error = fmt.Errorf("CAR upload failed: %w", err)
		return result, result.Error
	}
	result.DataTXID = dataTX.ID
	result.DataHeight = dataStatus.BlockHeight
	fmt.Printf("   CAR uploaded: %s (height=%d)\n", result.DataTXID, result.DataHeight)

	if pow.NeedsPoW(result.DataSize) {
		if err := u.recomputePoW(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, result.Error
		}
	}

	if err := u.uploadMetadata(ctx, result); err != nil {
		result.Error = err
		return result, result.Error
	}

	return result, nil
}

// uploadBundle handles the same-bundle flow (legacy, without state).
func (u *Uploader) uploadBundle(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	carItem, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign CAR bundle item: %w", err)
		return result, result.Error
	}
	carItemID := base64.RawURLEncoding.EncodeToString(carItem.ID)
	result.DataTXID = carItemID
	fmt.Printf("   CAR item signed: %s\n", carItemID)

	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWSinglePass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, result.Error
		}
	} else {
		fmt.Printf("   File >= 100 MiB, skipping PoW\n")
	}

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

	bb := arweave.NewBundleBuilder()
	bb.AddItem(*carItem)
	bb.AddItem(*metaItem)
	bundleData, err := bb.Build()
	if err != nil {
		result.Error = fmt.Errorf("failed to build bundle: %w", err)
		return result, result.Error
	}

	fmt.Printf("   Uploading bundle (2 items, %d bytes)...\n", len(bundleData))
	bundleTXID, err := u.cfg.Gateway.UploadDataRaw(bundleData)
	if err != nil {
		result.Error = fmt.Errorf("bundle upload failed: %w", err)
		return result, result.Error
	}
	fmt.Printf("   Bundle uploaded: %s\n", bundleTXID)

	status, err := u.cfg.Gateway.WaitForConfirmation(bundleTXID, 120, 3*time.Second)
	if err != nil {
		fmt.Printf("   Warning: bundle confirmation check failed: %v\n", err)
	} else {
		fmt.Printf("   Bundle confirmed at height=%d\n", status.BlockHeight)
	}

	return result, nil
}

// uploadCrossBundle handles the cross-bundle flow (reserved for future use).
func (u *Uploader) uploadCrossBundle(ctx context.Context, result *UploadResult, carBytes []byte, cachePath string, arTags []arweave.Tag) (*UploadResult, error) {
	carItem, err := arweave.SignBundleItem(carBytes, arTags, u.cfg.Wallet, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to sign CAR bundle item: %w", err)
		return result, result.Error
	}
	carItemID := base64.RawURLEncoding.EncodeToString(carItem.ID)
	result.DataTXID = carItemID

	if pow.NeedsPoW(result.DataSize) {
		if err := u.computePoWFirstPass(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, result.Error
		}
	}

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

	status, err := u.cfg.Gateway.WaitForConfirmation(bundleTXID, 120, 3*time.Second)
	if err != nil {
		result.Error = fmt.Errorf("bundle confirmation failed: %w", err)
		return result, result.Error
	}
	result.DataHeight = status.BlockHeight
	fmt.Printf("   Bundle confirmed at height=%d\n", result.DataHeight)

	if pow.NeedsPoW(result.DataSize) {
		if err := u.recomputePoW(ctx, result, cachePath); err != nil {
			result.Error = err
			return result, result.Error
		}
	}

	if err := u.uploadMetadata(ctx, result); err != nil {
		result.Error = err
		return result, result.Error
	}

	return result, nil
}

// uploadMetadata builds the metadata JSON and uploads it to Arweave (legacy).
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

// =============================================================================
// Helpers (unchanged)
// =============================================================================

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

// stateError formats the last error from state.
func stateError(state *UploadState) error {
	if state.LastError != "" {
		return fmt.Errorf("%s", state.LastError)
	}
	return fmt.Errorf("upload failed at status: %s", state.Status)
}
