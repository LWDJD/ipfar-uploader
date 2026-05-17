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
	StatusPending       UploadStatus = "pending"
	StatusCarUploading  UploadStatus = "car_uploading"
	StatusCarSubmitted  UploadStatus = "car_submitted"
	StatusCarConfirmed  UploadStatus = "car_confirmed"
	StatusMetaUploading UploadStatus = "meta_uploading"
	StatusMetaSubmitted UploadStatus = "meta_submitted"
	StatusMetaConfirmed UploadStatus = "meta_confirmed"
	StatusDone          UploadStatus = "done"
)

// validTransitions defines allowed status transitions.
var validTransitions = map[UploadStatus][]UploadStatus{
	StatusPending:       {StatusCarUploading},
	StatusCarUploading:  {StatusCarSubmitted, StatusPending},
	StatusCarSubmitted:  {StatusCarConfirmed, StatusCarUploading, StatusPending},
	StatusCarConfirmed:  {StatusMetaUploading, StatusDone}, // StatusDone for bundle (meta bundled with car)
	StatusMetaUploading: {StatusMetaSubmitted, StatusCarConfirmed},
	StatusMetaSubmitted: {StatusMetaConfirmed, StatusMetaUploading},
	StatusMetaConfirmed: {StatusDone},
	StatusDone:          {},
}

// =============================================================================
// Constants
// =============================================================================

const (
	maxRetries      = 3
	resubmitTimeout = 30 * time.Minute
)

// =============================================================================
// State struct
// =============================================================================

// UploadState tracks the progress of a single file upload to Arweave.
// It is persisted as {filePath}.upload.json alongside the source file.
type UploadState struct {
	FilePath        string       `json:"file_path"`
	FileHash        string       `json:"file_hash"`
	RootCID         string       `json:"root_cid"`
	DataSize        int64        `json:"data_size"`
	Status          UploadStatus `json:"status"`
	Method          string       `json:"method,omitempty"`
	CarTXID         string       `json:"car_txid"`
	CarSubmittedAt  string       `json:"car_submitted_at"`
	CarConfirmed    bool         `json:"car_confirmed"`
	CarHeight       int          `json:"car_height"`
	MetaTXID        string       `json:"meta_txid"`
	MetaSubmittedAt string       `json:"meta_submitted_at"`
	MetaConfirmed   bool         `json:"meta_confirmed"`
	MetaHeight      int          `json:"meta_height"`
	BundleTXID      string       `json:"bundle_txid,omitempty"`
	RetryCount      int          `json:"retry_count"`
	LastError       string       `json:"last_error"`
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
	data, err := os.ReadFile(sp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file %s: %w", sp, err)
	}

	var s UploadState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("failed to parse state file %s: %w", sp, err)
	}
	return &s, nil
}

// Save atomically writes the upload state to disk (temp file + rename).
func (s *UploadState) Save() error {
	sp := stateFilePath(s.FilePath)
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

// IsComplete returns true when both CAR and metadata are confirmed.
func (s *UploadState) IsComplete() bool {
	return s.CarConfirmed && s.MetaConfirmed
}

// NeedsCARUpload returns true if the CAR has not been confirmed yet.
func (s *UploadState) NeedsCARUpload() bool {
	return !s.CarConfirmed
}

// NeedsMetaUpload returns true if CAR is confirmed but metadata is not.
func (s *UploadState) NeedsMetaUpload() bool {
	return s.CarConfirmed && !s.MetaConfirmed
}

// CanResubmitCAR returns true when:
//   - CAR is not yet confirmed
//   - retry budget remains
//   - the previous submission timed out (>30 min) OR was never submitted
func (s *UploadState) CanResubmitCAR() bool {
	if s.CarConfirmed {
		return false
	}
	if s.RetryCount >= maxRetries {
		return false
	}
	if s.CarSubmittedAt == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, s.CarSubmittedAt)
	if err != nil {
		// Fallback: try a few common layouts
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05-07:00",
		} {
			if t, err = time.Parse(layout, s.CarSubmittedAt); err == nil {
				break
			}
		}
		if err != nil {
			return true // can't parse, assume stale
		}
	}
	return time.Since(t) > resubmitTimeout
}

// CanResubmitMeta returns true when metadata tx can be resubmitted.
func (s *UploadState) CanResubmitMeta() bool {
	if s.MetaConfirmed {
		return false
	}
	if s.RetryCount >= maxRetries {
		return false
	}
	if s.MetaSubmittedAt == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, s.MetaSubmittedAt)
	if err != nil {
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05-07:00",
		} {
			if t, err = time.Parse(layout, s.MetaSubmittedAt); err == nil {
				break
			}
		}
		if err != nil {
			return true
		}
	}
	return time.Since(t) > resubmitTimeout
}

// ShouldWaitForCAR returns true if CAR was submitted recently and we should
// keep waiting rather than resubmit.
func (s *UploadState) ShouldWaitForCAR() bool {
	if s.CarConfirmed {
		return false
	}
	if s.CarTXID == "" || s.CarSubmittedAt == "" {
		return false
	}
	if s.RetryCount >= maxRetries {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, s.CarSubmittedAt)
	if err != nil {
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02T15:04:05-07:00",
		} {
			if t, err = time.Parse(layout, s.CarSubmittedAt); err == nil {
				break
			}
		}
		if err != nil {
			return false
		}
	}
	return time.Since(t) <= resubmitTimeout
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
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

// =============================================================================
// Dedup gating
// =============================================================================

// ShouldAttemptDedup returns true when the uploader should query GraphQL
// to check for an existing CAR transaction on chain.
//
// Rules:
//   - Always attempt dedup when status is pending or car_uploading
//     (the earliest phases, before any tx is known).
//   - If CarTXID is already known (non-empty), skip dedup — we already
//     have a transaction to track.
//   - If CarTXID is empty, attempt dedup — we might find an existing
//     upload from a previous (possibly failed) run or from another uploader.
func (s *UploadState) ShouldAttemptDedup() bool {
	if s.Status == StatusPending || s.Status == StatusCarUploading {
		return true
	}
	return s.CarTXID == ""
}

// GraphQL dedup query is implemented in arweave.GatewayClient.QueryExistingCAR.
// The state package only manages local state files; network queries are done
// by the uploader using the gateway client.
