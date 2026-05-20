// Package uploader — upload state management: dedup, resume, retry.
package uploader

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// =============================================================================
// Status constants
// =============================================================================

// UploadStatus represents the current phase of an upload.
type UploadStatus string

const (
	StatusPending   UploadStatus = "pending"
	StatusUploading UploadStatus = "uploading" // SDK handles the full upload pipeline
	StatusDone      UploadStatus = "done"
)

// validTransitions defines allowed status transitions.
var validTransitions = map[UploadStatus][]UploadStatus{
	StatusPending:   {StatusUploading},
	StatusUploading: {StatusDone, StatusPending}, // retry resets to pending
	StatusDone:      {},
}

// =============================================================================
// State struct
// =============================================================================

// UploadState tracks the progress of a single file upload to Arweave.
// It is persisted as {filePath}.upload.json alongside the source file.
type UploadState struct {
	FilePath   string       `json:"file_path"`
	FileHash   string       `json:"file_hash"`
	RootCID    string       `json:"root_cid"`
	DataSize   int64        `json:"data_size"`
	Status     UploadStatus `json:"status"`
	Method     string       `json:"method,omitempty"`
	CarTXID    string       `json:"car_txid"`
	CarHeight  int          `json:"car_height"`
	MetaTXID   string       `json:"meta_txid"`
	MetaHeight int          `json:"meta_height"`
	BundleTXID string       `json:"bundle_txid,omitempty"`
	RetryCount int          `json:"retry_count"`
	LastError  string       `json:"last_error"`
}

// =============================================================================
// File path helper
// =============================================================================

// stateFilePath returns the state file path for a given input file.
func stateFilePath(filePath string) string {
	return filePath + ".upload.json"
}

// =============================================================================
// Load / Save
// =============================================================================

// LoadState reads the upload state from disk.
// Returns (nil, nil) if the state file does not exist.
func LoadState(filePath string) (*UploadState, error) {
	sp := stateFilePath(filePath)
	debugLog("LoadState: reading %s", sp)
	data, err := os.ReadFile(sp)
	if err != nil {
		if os.IsNotExist(err) {
			debugLog("LoadState: file not found, returning nil")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file %s: %w", sp, err)
	}

	var s UploadState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("failed to parse state file %s: %w", sp, err)
	}

	// Migrate legacy statuses to simplified model.
	switch s.Status {
	case StatusPending, StatusUploading, StatusDone:
		// valid
	default:
		// Old intermediate status — reset to pending so the SDK retries.
		debugLog("LoadState: migrating legacy status %q -> pending", s.Status)
		s.Status = StatusPending
	}

	debugLog("LoadState: status=%s, carTXID=%s, metaTXID=%s",
		s.Status, s.CarTXID, s.MetaTXID)
	return &s, nil
}

// Save atomically writes the upload state to disk (temp file + rename).
func (s *UploadState) Save() error {
	sp := stateFilePath(s.FilePath)
	debugLog("Save: writing %s, status=%s, carTXID=%s, retryCount=%d",
		sp, s.Status, s.CarTXID, s.RetryCount)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	tmpPath := sp + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	if err := os.Rename(tmpPath, sp); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename state file: %w", err)
	}
	return nil
}

// =============================================================================
// Transition helpers
// =============================================================================

// TransitionTo attempts to change the status to the given target.
// Returns an error if the transition is not allowed.
func (s *UploadState) TransitionTo(target UploadStatus) error {
	allowed, ok := validTransitions[s.Status]
	if !ok {
		return fmt.Errorf("unknown current status: %s", s.Status)
	}
	for _, a := range allowed {
		if a == target {
			s.Status = target
			return nil
		}
	}
	return fmt.Errorf("invalid transition: %s → %s", s.Status, target)
}

// SetError records an error and saves the state.
func (s *UploadState) SetError(err error) {
	if err != nil {
		s.LastError = err.Error()
	} else {
		s.LastError = ""
	}
}

// =============================================================================
// Query helpers
// =============================================================================

// IsComplete returns true when the upload has finished successfully.
func (s *UploadState) IsComplete() bool {
	return s.Status == StatusDone
}

// NeedsCARUpload returns true if the CAR has not been uploaded yet.
// With the simplified pipeline, this means the SDK hasn't started.
func (s *UploadState) NeedsCARUpload() bool {
	return s.Status == StatusPending
}

// NeedsMetaUpload always returns false — the SDK handles metadata
// together with the CAR in a single pass.
func (s *UploadState) NeedsMetaUpload() bool {
	return false
}

// ShouldAttemptDedup returns true when the uploader should query GraphQL
// to check for an existing transaction on chain.
//
// With the simplified pipeline, dedup is handled by the SDK internally.
// This method remains for callers that want to pre-check before invoking
// the SDK.
func (s *UploadState) ShouldAttemptDedup() bool {
	if s.Status == StatusPending {
		return true
	}
	return s.CarTXID == "" && s.Status != StatusDone
}

// =============================================================================
// Factory
// =============================================================================

// NewUploadState creates a fresh state for a new upload.
func NewUploadState(filePath, rootCID string, fileHash string, dataSize int64, method string) *UploadState {
	return &UploadState{
		FilePath: filePath,
		FileHash: fileHash,
		RootCID:  rootCID,
		DataSize: dataSize,
		Status:   StatusPending,
		Method:   method,
	}
}

// TimeNow returns the current time in RFC3339Nano format.
func TimeNow() string {
	return time.Now().Format(time.RFC3339Nano)
}

// =============================================================================
// File hash
// =============================================================================

// ComputeFileHash returns the hex-encoded SHA-256 of a file on disk.
func ComputeFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return computeFileHash(data), nil
}

// computeFileHash returns the hex-encoded SHA-256 of in-memory data.
func computeFileHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}
