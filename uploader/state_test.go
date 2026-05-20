package uploader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// =============================================================================
// State lifecycle tests
// =============================================================================

func TestStateTransition_ValidFlow(t *testing.T) {
	s := &UploadState{Status: StatusPending}

	steps := []UploadStatus{
		StatusUploading,
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
		{StatusPending, StatusDone},          // skip uploading
		{StatusDone, StatusPending},          // can't go back
		{StatusDone, StatusUploading},        // can't restart
	}

	for _, tt := range tests {
		s := &UploadState{Status: tt.from}
		err := s.TransitionTo(tt.to)
		if err == nil {
			t.Errorf("expected error for %s → %s, got nil", tt.from, tt.to)
		}
	}
}

func TestStateTransition_RetryFlow(t *testing.T) {
	// Retry: uploading → pending → uploading → done
	s := &UploadState{Status: StatusPending}

	if err := s.TransitionTo(StatusUploading); err != nil {
		t.Fatal(err)
	}
	// Can go back to pending for retry
	if err := s.TransitionTo(StatusPending); err != nil {
		t.Fatal(err)
	}
	// Then uploading again
	if err := s.TransitionTo(StatusUploading); err != nil {
		t.Fatal(err)
	}
	// Then done
	if err := s.TransitionTo(StatusDone); err != nil {
		t.Fatal(err)
	}

	if !s.IsComplete() {
		t.Error("should be complete after done")
	}
}

// =============================================================================
// Save / Load tests
// =============================================================================

func TestSaveLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")

	original := NewUploadState(filePath, "bafyTestCID", "abc123hash", 1024, sdkmeta.MethodRaw)
	original.Status = StatusUploading
	original.CarTXID = "test-txid-123"

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

	s := NewUploadState(filePath, "bafyCID", "hash", 100, sdkmeta.MethodRaw)
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

func TestLoadState_MigratesLegacyStatus(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "legacy.bin")
	statePath := stateFilePath(filePath)

	// Write a state with legacy status "car_confirmed"
	legacy := map[string]interface{}{
		"file_path":     filePath,
		"file_hash":     "abc123",
		"root_cid":      "bafyLegacy",
		"data_size":     1024,
		"status":        "car_confirmed",
		"car_txid":      "old-txid",
		"car_confirmed": true,
		"car_height":    100,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0644); err != nil {
		t.Fatal(err)
	}

	s, err := LoadState(filePath)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil state")
	}
	if s.Status != StatusPending {
		t.Errorf("legacy status should be migrated to pending, got %q", s.Status)
	}
	// Old txid should be preserved
	if s.CarTXID != "old-txid" {
		t.Errorf("CarTXID should be preserved: got %q, want 'old-txid'", s.CarTXID)
	}
}

// =============================================================================
// Query tests
// =============================================================================

func TestIsComplete(t *testing.T) {
	tests := []struct {
		status UploadStatus
		want   bool
	}{
		{StatusPending, false},
		{StatusUploading, false},
		{StatusDone, true},
	}
	for _, tt := range tests {
		s := &UploadState{Status: tt.status}
		if got := s.IsComplete(); got != tt.want {
			t.Errorf("IsComplete(status=%s) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestNeedsCARUpload(t *testing.T) {
	s := &UploadState{Status: StatusPending}
	if !s.NeedsCARUpload() {
		t.Error("should need CAR upload when pending")
	}
	s.Status = StatusUploading
	if s.NeedsCARUpload() {
		t.Error("should NOT need CAR upload when uploading")
	}
	s.Status = StatusDone
	if s.NeedsCARUpload() {
		t.Error("should NOT need CAR upload when done")
	}
}

func TestNeedsMetaUpload(t *testing.T) {
	// With simplified pipeline, metadata is handled together with CAR.
	// NeedsMetaUpload always returns false.
	s := &UploadState{Status: StatusPending}
	if s.NeedsMetaUpload() {
		t.Error("should NOT need separate meta upload")
	}
	s.Status = StatusDone
	if s.NeedsMetaUpload() {
		t.Error("should NOT need separate meta upload when done")
	}
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

func TestComputeFileHash_InMemory(t *testing.T) {
	data := []byte("in-memory hash test")
	h := computeFileHash(data)
	if len(h) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(h), h)
	}

	// Deterministic
	h2 := computeFileHash(data)
	if h != h2 {
		t.Error("hash should be deterministic")
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
	s := NewUploadState("file.bin", "bafyCID", "hash123", 2048, sdkmeta.MethodRaw)

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
	if s.Method != sdkmeta.MethodRaw {
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
		name    string
		status  UploadStatus
		carTXID string
		want    bool
	}{
		{"pending with empty txid", StatusPending, "", true},
		{"pending with txid", StatusPending, "tx123", true},
		{"uploading with empty txid", StatusUploading, "", true},
		{"uploading with txid", StatusUploading, "tx123", false},
		{"done with empty txid", StatusDone, "", false},
		{"done with txid", StatusDone, "tx123", false},
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

// =============================================================================
// resultFromState tests
// =============================================================================

func TestResultFromState(t *testing.T) {
	state := &UploadState{
		FilePath:   "/tmp/test.bin",
		RootCID:    "bafyTest",
		DataSize:   2048,
		CarTXID:    "car-tx-123",
		MetaTXID:   "meta-tx-456",
		CarHeight:  100,
		BundleTXID: "bundle-tx-789",
	}

	result := resultFromState(state, "/tmp/test.bin", "test.bin", "image/png", "raw")

	if result.FilePath != "/tmp/test.bin" {
		t.Errorf("FilePath: got %q", result.FilePath)
	}
	if result.RootCID != "bafyTest" {
		t.Errorf("RootCID: got %q", result.RootCID)
	}
	if result.DataTXID != "car-tx-123" {
		t.Errorf("DataTXID: got %q", result.DataTXID)
	}
	if result.MetaTXID != "meta-tx-456" {
		t.Errorf("MetaTXID: got %q", result.MetaTXID)
	}
	if result.BundleTXID != "bundle-tx-789" {
		t.Errorf("BundleTXID: got %q", result.BundleTXID)
	}
	if result.OriginalName != "test.bin" {
		t.Errorf("OriginalName: got %q", result.OriginalName)
	}
	if result.ContentType != "image/png" {
		t.Errorf("ContentType: got %q", result.ContentType)
	}
	if result.Method != "raw" {
		t.Errorf("Method: got %q", result.Method)
	}
	if result.Error != nil {
		t.Errorf("Error should be nil, got %v", result.Error)
	}
}
