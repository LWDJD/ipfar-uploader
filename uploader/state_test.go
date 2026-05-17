package uploader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LWDJD/ipfar-uploader/metadata"
)

// =============================================================================
// State lifecycle tests
// =============================================================================

func TestStateTransition_ValidFlow(t *testing.T) {
	s := &UploadState{Status: StatusPending}

	steps := []UploadStatus{
		StatusCarUploading,
		StatusCarSubmitted,
		StatusCarConfirmed,
		StatusMetaUploading,
		StatusMetaSubmitted,
		StatusMetaConfirmed,
		StatusDone,
	}

	for _, target := range steps {
		if err := s.TransitionTo(target); err != nil {
			t.Fatalf("valid transition %s → %s failed: %v", s.Status, target, err)
		}
	}
}

func TestStateTransition_InvalidJumps(t *testing.T) {
	tests := []struct {
		from UploadStatus
		to   UploadStatus
	}{
		{StatusPending, StatusCarConfirmed},   // skip car_submitted
		{StatusPending, StatusDone},           // skip all
		{StatusCarSubmitted, StatusDone},      // skip meta (needs car_confirmed first)
		{StatusDone, StatusPending},           // can't restart
		{StatusMetaConfirmed, StatusPending},  // can't go back
	}

	for _, tt := range tests {
		s := &UploadState{Status: tt.from}
		err := s.TransitionTo(tt.to)
		if err == nil {
			t.Errorf("expected error for %s → %s, got nil", tt.from, tt.to)
		}
	}
}

func TestStateTransition_BundleFlow(t *testing.T) {
	// Bundle flow: car_submitted → car_confirmed → done
	// (meta is bundled with car, so car_confirmed implies meta_confirmed)
	s := &UploadState{Status: StatusPending}

	if err := s.TransitionTo(StatusCarUploading); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionTo(StatusCarSubmitted); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionTo(StatusCarConfirmed); err != nil {
		t.Fatal(err)
	}
	// For bundle, after car_confirmed, we set both confirm flags and go to done
	s.CarConfirmed = true
	s.MetaConfirmed = true
	s.Status = StatusDone

	if !s.IsComplete() {
		t.Error("bundle flow should be complete after car_confirmed + meta_confirmed")
	}
}

// =============================================================================
// Save / Load tests
// =============================================================================

func TestSaveLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")

	original := NewUploadState(filePath, "bafyTestCID", "abc123hash", 1024, metadata.MethodRaw)
	original.Status = StatusCarSubmitted
	original.CarTXID = "test-txid-123"
	original.CarSubmittedAt = TimeNow()

	if err := original.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	statePath := stateFilePath(filePath)
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatal("state file was not created")
	}

	// Load and verify
	loaded, err := LoadState(filePath)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadState returned nil")
	}

	if loaded.FilePath != original.FilePath {
		t.Errorf("FilePath: got %q, want %q", loaded.FilePath, original.FilePath)
	}
	if loaded.FileHash != original.FileHash {
		t.Errorf("FileHash: got %q, want %q", loaded.FileHash, original.FileHash)
	}
	if loaded.RootCID != original.RootCID {
		t.Errorf("RootCID: got %q, want %q", loaded.RootCID, original.RootCID)
	}
	if loaded.Status != original.Status {
		t.Errorf("Status: got %q, want %q", loaded.Status, original.Status)
	}
	if loaded.CarTXID != original.CarTXID {
		t.Errorf("CarTXID: got %q, want %q", loaded.CarTXID, original.CarTXID)
	}
}

func TestLoadState_NonExistent(t *testing.T) {
	s, err := LoadState("/nonexistent/path/file.bin")
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if s != nil {
		t.Error("expected nil for non-existent state file")
	}
}

func TestLoadState_CorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")
	statePath := stateFilePath(filePath)

	// Write garbage
	if err := os.WriteFile(statePath, []byte("not valid json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(filePath)
	if err == nil {
		t.Error("expected error for corrupt state file")
	}
}

func TestAtomicSave(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")

	s := NewUploadState(filePath, "bafyCID", "hash", 100, metadata.MethodRaw)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Verify no .tmp file left behind
	tmpPath := stateFilePath(filePath) + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should not exist after atomic save")
	}

	// Verify content is valid JSON
	statePath := stateFilePath(filePath)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var check UploadState
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatalf("saved state is not valid JSON: %v", err)
	}
}

// =============================================================================
// Dedup / Resume query tests
// =============================================================================

func TestIsComplete(t *testing.T) {
	tests := []struct {
		car  bool
		meta bool
		want bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, true},
	}
	for _, tt := range tests {
		s := &UploadState{CarConfirmed: tt.car, MetaConfirmed: tt.meta}
		if got := s.IsComplete(); got != tt.want {
			t.Errorf("IsComplete(car=%v, meta=%v) = %v, want %v", tt.car, tt.meta, got, tt.want)
		}
	}
}

func TestNeedsCARUpload(t *testing.T) {
	s := &UploadState{CarConfirmed: false}
	if !s.NeedsCARUpload() {
		t.Error("should need CAR upload when not confirmed")
	}
	s.CarConfirmed = true
	if s.NeedsCARUpload() {
		t.Error("should NOT need CAR upload when confirmed")
	}
}

func TestNeedsMetaUpload(t *testing.T) {
	s := &UploadState{CarConfirmed: false, MetaConfirmed: false}
	if s.NeedsMetaUpload() {
		t.Error("should NOT need meta upload when CAR not confirmed")
	}
	s.CarConfirmed = true
	if !s.NeedsMetaUpload() {
		t.Error("should need meta upload when CAR confirmed but meta not")
	}
	s.MetaConfirmed = true
	if s.NeedsMetaUpload() {
		t.Error("should NOT need meta upload when both confirmed")
	}
}

func TestCanResubmitCAR(t *testing.T) {
	t.Run("never submitted", func(t *testing.T) {
		s := &UploadState{CarConfirmed: false, RetryCount: 0}
		if !s.CanResubmitCAR() {
			t.Error("should allow resubmit when never submitted")
		}
	})

	t.Run("submitted recently", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   false,
			CarSubmittedAt: time.Now().Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if s.CanResubmitCAR() {
			t.Error("should NOT allow resubmit when just submitted")
		}
	})

	t.Run("submitted long ago", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   false,
			CarSubmittedAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if !s.CanResubmitCAR() {
			t.Error("should allow resubmit after timeout")
		}
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   false,
			CarSubmittedAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano),
			RetryCount:     maxRetries,
		}
		if s.CanResubmitCAR() {
			t.Error("should NOT allow resubmit when retries exhausted")
		}
	})

	t.Run("already confirmed", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   true,
			CarSubmittedAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if s.CanResubmitCAR() {
			t.Error("should NOT allow resubmit when already confirmed")
		}
	})
}

func TestShouldWaitForCAR(t *testing.T) {
	t.Run("recently submitted", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   false,
			CarTXID:        "test-txid",
			CarSubmittedAt: time.Now().Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if !s.ShouldWaitForCAR() {
			t.Error("should wait when recently submitted")
		}
	})

	t.Run("no txid", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   false,
			CarTXID:        "",
			CarSubmittedAt: time.Now().Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if s.ShouldWaitForCAR() {
			t.Error("should NOT wait when no txid")
		}
	})

	t.Run("already confirmed", func(t *testing.T) {
		s := &UploadState{
			CarConfirmed:   true,
			CarTXID:        "test-txid",
			CarSubmittedAt: time.Now().Format(time.RFC3339Nano),
			RetryCount:     0,
		}
		if s.ShouldWaitForCAR() {
			t.Error("should NOT wait when already confirmed")
		}
	})
}

// =============================================================================
// File hash tests
// =============================================================================

func TestComputeFileHash(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "hash_test.bin")

	data := []byte("hello world test data")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatal(err)
	}

	hash1, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatalf("ComputeFileHash failed: %v", err)
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash1), hash1)
	}

	// Same file → same hash
	hash2, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Error("hash should be deterministic")
	}

	// Different file → different hash
	if err := os.WriteFile(filePath, []byte("different data"), 0644); err != nil {
		t.Fatal(err)
	}
	hash3, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash3 {
		t.Error("different files should have different hashes")
	}
}

// =============================================================================
// State file path test
// =============================================================================

func TestStateFilePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"test.bin", "test.bin.upload.json"},
		{"/path/to/file.png", "/path/to/file.png.upload.json"},
		{"noext", "noext.upload.json"},
	}

	for _, tt := range tests {
		got := stateFilePath(tt.input)
		if got != tt.want {
			t.Errorf("stateFilePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// =============================================================================
// NewUploadState test
// =============================================================================

func TestNewUploadState(t *testing.T) {
	s := NewUploadState("file.bin", "bafyCID", "hash123", 2048, metadata.MethodRaw)

	if s.FilePath != "file.bin" {
		t.Errorf("FilePath: got %q", s.FilePath)
	}
	if s.Status != StatusPending {
		t.Errorf("Status: got %q, want %q", s.Status, StatusPending)
	}
	if s.RootCID != "bafyCID" {
		t.Errorf("RootCID: got %q", s.RootCID)
	}
	if s.FileHash != "hash123" {
		t.Errorf("FileHash: got %q", s.FileHash)
	}
	if s.DataSize != 2048 {
		t.Errorf("DataSize: got %d", s.DataSize)
	}
	if s.Method != metadata.MethodRaw {
		t.Errorf("Method: got %q", s.Method)
	}
	if s.IsComplete() {
		t.Error("new state should not be complete")
	}
	if !s.NeedsCARUpload() {
		t.Error("new state should need CAR upload")
	}
}

// =============================================================================
// ShouldAttemptDedup tests
// =============================================================================

func TestShouldAttemptDedup(t *testing.T) {
	tests := []struct {
		name   string
		status UploadStatus
		carTXID string
		want   bool
	}{
		{"pending with empty txid", StatusPending, "", true},
		{"pending with txid (shouldn't happen)", StatusPending, "tx123", true},
		{"car_uploading with empty txid", StatusCarUploading, "", true},
		{"car_uploading with txid (shouldn't happen)", StatusCarUploading, "tx123", true},
		{"car_submitted with empty txid", StatusCarSubmitted, "", true},
		{"car_submitted with txid", StatusCarSubmitted, "tx123", false},
		{"car_confirmed with empty txid", StatusCarConfirmed, "", true},
		{"car_confirmed with txid", StatusCarConfirmed, "tx123", false},
		{"meta_uploading with txid", StatusMetaUploading, "tx123", false},
		{"meta_submitted with txid", StatusMetaSubmitted, "tx123", false},
		{"meta_confirmed with txid", StatusMetaConfirmed, "tx123", false},
		{"done with txid", StatusDone, "tx123", false},
		{"done with empty txid", StatusDone, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &UploadState{Status: tt.status, CarTXID: tt.carTXID}
			if got := s.ShouldAttemptDedup(); got != tt.want {
				t.Errorf("ShouldAttemptDedup() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// SetError tests
// =============================================================================

func TestSetError(t *testing.T) {
	s := &UploadState{}
	s.SetError(nil)
	if s.LastError != "" {
		t.Error("nil error should clear LastError")
	}

	s.SetError(timeoutError())
	if s.LastError == "" {
		t.Error("error should be recorded")
	}
}

func timeoutError() error {
	return &testError{msg: "confirmation timeout"}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
