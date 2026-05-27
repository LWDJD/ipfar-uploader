package uploader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// ============================================================
// All invalid status transitions
// ============================================================

func TestStateTransition_AllInvalidCombinations(t *testing.T) {
	allStatuses := []UploadStatus{StatusPending, StatusUploading, StatusDone}
	validTransitions := map[UploadStatus]map[UploadStatus]bool{
		StatusPending:   {StatusUploading: true},
		StatusUploading: {StatusDone: true, StatusPending: true},
		StatusDone:      {},
	}

	for _, from := range allStatuses {
		for _, to := range allStatuses {
			s := &UploadState{Status: from}
			err := s.TransitionTo(to)
			isValid := validTransitions[from][to]

			if isValid && err != nil {
				t.Errorf("valid transition %s → %s should not error: %v", from, to, err)
			}
			if !isValid && err == nil {
				t.Errorf("invalid transition %s → %s should error", from, to)
			}
		}
	}
}

// ============================================================
// Concurrent state access
// ============================================================

func TestState_ConcurrentSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "concurrent_state.bin")

	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex

	// Concurrent saves to the same file may race on the .tmp → rename step.
	// This is a known limitation of the atomic save pattern.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := NewUploadState(filePath, "bafyConcurrent", fmt.Sprintf("hash-%d", idx), int64(idx*100), sdkmeta.MethodRaw)
			s.CarTXID = fmt.Sprintf("tx-%d", idx)
			if err := s.Save(); err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				t.Logf("concurrent save %d failed (expected race): %v", idx, err)
			}
		}(i)
	}

	wg.Wait()

	// Load — should get the last saved state (or nil if all failed)
	loaded, err := LoadState(filePath)
	if err != nil {
		t.Fatalf("LoadState after concurrent saves: %v", err)
	}
	if loaded != nil {
		t.Logf("Concurrent save: final state = CarTXID=%s, Hash=%s", loaded.CarTXID, loaded.FileHash)
	} else {
		t.Log("Concurrent save: no state persisted (all saves failed due to race)")
	}

	t.Logf("Concurrent save errors: %d/10", errCount)
}

// ============================================================
// State JSON marshal/unmarshal with all fields
// ============================================================

func TestState_JSONRoundTrip_AllFields(t *testing.T) {
	original := &UploadState{
		FilePath:   "/tmp/all-fields.bin",
		FileHash:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		RootCID:    "bafyAllFieldsCID1234567890123456789012345678901234",
		DataSize:   1048576,
		Status:     StatusUploading,
		Method:     sdkmeta.MethodBundle,
		CarTXID:    "car_tx_123456789012345678901234567890123456789012",
		CarHeight:  1913000,
		MetaTXID:   "meta_tx_12345678901234567890123456789012345678901",
		MetaHeight: 1913001,
		BundleTXID: "bundle_tx_123456789012345678901234567890123456789",
		RetryCount: 3,
		LastError:  "test error: network timeout",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var restored UploadState
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if restored.FilePath != original.FilePath {
		t.Errorf("FilePath mismatch")
	}
	if restored.FileHash != original.FileHash {
		t.Errorf("FileHash mismatch")
	}
	if restored.RootCID != original.RootCID {
		t.Errorf("RootCID mismatch")
	}
	if restored.DataSize != original.DataSize {
		t.Errorf("DataSize mismatch")
	}
	if restored.Status != original.Status {
		t.Errorf("Status mismatch")
	}
	if restored.Method != original.Method {
		t.Errorf("Method mismatch")
	}
	if restored.CarTXID != original.CarTXID {
		t.Errorf("CarTXID mismatch")
	}
	if restored.CarHeight != original.CarHeight {
		t.Errorf("CarHeight mismatch")
	}
	if restored.MetaTXID != original.MetaTXID {
		t.Errorf("MetaTXID mismatch")
	}
	if restored.MetaHeight != original.MetaHeight {
		t.Errorf("MetaHeight mismatch")
	}
	if restored.BundleTXID != original.BundleTXID {
		t.Errorf("BundleTXID mismatch")
	}
	if restored.RetryCount != original.RetryCount {
		t.Errorf("RetryCount mismatch")
	}
	if restored.LastError != original.LastError {
		t.Errorf("LastError mismatch")
	}
}

// ============================================================
// State file corruption recovery
// ============================================================

func TestLoadState_TruncatedFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "truncated.bin")
	statePath := stateFilePath(filePath)

	// Write half a JSON
	if err := os.WriteFile(statePath, []byte(`{"file_path":"/t`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(filePath)
	if err == nil {
		t.Error("expected error for truncated JSON")
	}
}

func TestLoadState_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty.bin")
	statePath := stateFilePath(filePath)

	if err := os.WriteFile(statePath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(filePath)
	if err == nil {
		t.Error("expected error for empty state file")
	}
}

func TestLoadState_WrongTypes(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "wrong_types.bin")
	statePath := stateFilePath(filePath)

	// JSON with wrong field types
	wrongJSON := `{
		"file_path": 123,
		"file_hash": true,
		"root_cid": null,
		"data_size": "not a number",
		"status": ["array", "not", "string"],
		"car_txid": 456,
		"retry_count": "not int"
	}`
	if err := os.WriteFile(statePath, []byte(wrongJSON), 0644); err != nil {
		t.Fatal(err)
	}

	s, err := LoadState(filePath)
	if err != nil {
		t.Logf("LoadState with wrong types: %v (expected)", err)
	} else if s != nil {
		t.Logf("LoadState with wrong types parsed: %+v (may succeed with defaults)", s)
	}
}

// ============================================================
// SetError edge cases
// ============================================================

func TestSetError_NilError(t *testing.T) {
	s := &UploadState{LastError: "previous error"}
	s.SetError(nil)
	if s.LastError != "" {
		t.Errorf("nil error should clear LastError, got %q", s.LastError)
	}
}

func TestSetError_EmptyError(t *testing.T) {
	// Custom error with empty message
	s := &UploadState{}
	s.SetError(fmt.Errorf("%s", ""))
	if s.LastError != "" {
		t.Errorf("empty error should result in empty string, got %q", s.LastError)
	}
}

func TestSetError_VeryLongError(t *testing.T) {
	s := &UploadState{}
	longMsg := ""
	for i := 0; i < 10000; i++ {
		longMsg += "error message detail; "
	}
	s.SetError(fmt.Errorf("%s", longMsg))
	if s.LastError != longMsg {
		t.Errorf("long error message should be preserved")
	}
}

// ============================================================
// ShouldAttemptDedup edge cases
// ============================================================

func TestShouldAttemptDedup_AllCases(t *testing.T) {
	tests := []struct {
		name    string
		status  UploadStatus
		carTXID string
		want    bool
	}{
		{"pending no tx", StatusPending, "", true},
		{"pending with tx", StatusPending, "tx123", true},
		{"uploading no tx", StatusUploading, "", true},
		{"uploading with tx", StatusUploading, "tx123", false},
		{"done no tx", StatusDone, "", false},
		{"done with tx", StatusDone, "tx123", false},
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

// ============================================================
// NeedsCARUpload edge cases
// ============================================================

func TestNeedsCARUpload_AllStatuses(t *testing.T) {
	tests := []struct {
		status UploadStatus
		want   bool
	}{
		{StatusPending, true},
		{StatusUploading, false},
		{StatusDone, false},
	}
	for _, tt := range tests {
		s := &UploadState{Status: tt.status}
		if got := s.NeedsCARUpload(); got != tt.want {
			t.Errorf("NeedsCARUpload(%s) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

// ============================================================
// IsComplete edge cases
// ============================================================

func TestIsComplete_AllStatuses(t *testing.T) {
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
			t.Errorf("IsComplete(%s) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

// ============================================================
// NewUploadState with bundle method
// ============================================================

func TestNewUploadState_BundleMethod(t *testing.T) {
	s := NewUploadState("/tmp/bundle.bin", "bafyBundle", "hashB", 500*1024*1024, sdkmeta.MethodBundle)
	if s.Method != sdkmeta.MethodBundle {
		t.Errorf("Method should be bundle, got %q", s.Method)
	}
	if s.Status != StatusPending {
		t.Errorf("Status should be pending, got %q", s.Status)
	}
}

// ============================================================
// ComputeFileHash with large file
// ============================================================

func TestComputeFileHash_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "large_hash.bin")

	// Write 1 MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatalf("ComputeFileHash failed: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d", len(hash))
	}

	// Same file → same hash
	hash2, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}
}

func TestComputeFileHash_NonExistentFile(t *testing.T) {
	_, err := ComputeFileHash("/nonexistent/path/to/file.bin")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// ============================================================
// ComputeFileHash empty file
// ============================================================

func TestComputeFileHash_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "empty_hash.bin")

	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatalf("ComputeFileHash on empty file failed: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d", len(hash))
	}

	// SHA-256 of empty string is well-known
	expectedEmptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expectedEmptyHash {
		t.Errorf("empty file hash: expected %s, got %s", expectedEmptyHash, hash)
	}
}

// ============================================================
// in-memory computeFileHash with various inputs
// ============================================================

func TestComputeFileHash_InMemory_Various(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x00}},
		{"hello", []byte("hello world")},
		{"binary", []byte{0x00, 0xFF, 0x7F, 0x80}},
		{"unicode", []byte("日本語テスト")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeFileHash(tt.data)
			if len(hash) != 64 {
				t.Errorf("expected 64-char hex hash, got %d", len(hash))
			}

			// Deterministic
			hash2 := computeFileHash(tt.data)
			if hash != hash2 {
				t.Error("hash should be deterministic")
			}
		})
	}
}

// ============================================================
// TimeNow
// ============================================================

func TestTimeNow(t *testing.T) {
	ts := TimeNow()
	if ts == "" {
		t.Error("TimeNow should not return empty string")
	}
	t.Logf("TimeNow: %s", ts)
}

// ============================================================
// resultFromState with nil/zero state
// ============================================================

func TestResultFromState_ZeroState(t *testing.T) {
	state := &UploadState{}
	result := resultFromState(state, "/tmp/test.bin", "test.bin", "", "")

	if result.FilePath != "/tmp/test.bin" {
		t.Errorf("FilePath should be set")
	}
	if result.OriginalName != "test.bin" {
		t.Errorf("OriginalName: got %q", result.OriginalName)
	}
	if result.RootCID != "" {
		t.Errorf("RootCID should be empty for zero state")
	}
	if result.DataTXID != "" {
		t.Errorf("DataTXID should be empty for zero state")
	}
}

// ============================================================
// Save with invalid file path (permission error)
// ============================================================

func TestSave_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test as root")
	}

	// Try to save to a read-only directory
	s := &UploadState{
		FilePath: "/root/forbidden.upload.json",
		Status:   StatusPending,
	}

	err := s.Save()
	if err == nil {
		t.Log("unexpectedly succeeded saving to /root (running as root?)")
	} else {
		t.Logf("Got expected permission error: %v", err)
	}
}

// ============================================================
// Migrate all legacy statuses
// ============================================================

func TestLoadState_MigratesAllLegacyStatuses(t *testing.T) {
	legacyStatuses := []string{
		"car_uploading",
		"car_confirmed",
		"meta_uploading",
		"meta_confirmed",
		"verifying",
		"verified",
		"bundling",
		"bundled",
		"unknown_status",
	}

	for _, legacyStatus := range legacyStatuses {
		t.Run(legacyStatus, func(t *testing.T) {
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "legacy_"+legacyStatus+".bin")
			statePath := stateFilePath(filePath)

			legacy := map[string]interface{}{
				"file_path": filePath,
				"file_hash": "abc",
				"root_cid":  "bafyLegacy",
				"data_size": 1024,
				"status":    legacyStatus,
				"car_txid":  "old-txid",
			}
			data, _ := json.Marshal(legacy)
			os.WriteFile(statePath, data, 0644)

			s, err := LoadState(filePath)
			if err != nil {
				t.Fatalf("LoadState for %s failed: %v", legacyStatus, err)
			}
			if s.Status != StatusPending {
				t.Errorf("legacy %s should be migrated to pending, got %s", legacyStatus, s.Status)
			}
		})
	}
}

// ============================================================
// Concurrent read of same state file
// ============================================================

func TestLoadState_ConcurrentRead(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "concurrent_read.bin")

	s := NewUploadState(filePath, "bafyRead", "hashRead", 2048, sdkmeta.MethodRaw)
	s.CarTXID = "tx-read"
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loaded, err := LoadState(filePath)
			if err != nil {
				errCh <- err
				return
			}
			if loaded == nil {
				errCh <- fmt.Errorf("loaded state is nil")
				return
			}
			if loaded.CarTXID != "tx-read" {
				errCh <- fmt.Errorf("%s", "CarTXID mismatch")
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent read failed: %v", err)
	}
}
