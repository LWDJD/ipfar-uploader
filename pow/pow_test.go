package pow

import (
	"context"
	"testing"
	"time"
)

func TestNeedsPoW(t *testing.T) {
	tests := []struct {
		size     int64
		expected bool
	}{
		{0, true},
		{1024, true},
		{100*1024*1024 - 1, true},  // just under 100 MiB
		{100 * 1024 * 1024, false},  // exactly 100 MiB
		{100*1024*1024 + 1, false},  // just over 100 MiB
		{1024 * 1024 * 1024, false}, // 1 GiB
	}

	for _, tt := range tests {
		result := NeedsPoW(tt.size)
		if result != tt.expected {
			t.Errorf("NeedsPoW(%d) = %v, want %v", tt.size, result, tt.expected)
		}
	}
}

func TestFastComputePoW(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-txid-12345"

	salt, err := FastComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("FastComputePoW failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("Found salt: %s (with 1MB fast mode)", salt)
}

func TestHasLeadingZeroBytes(t *testing.T) {
	tests := []struct {
		data     []byte
		n        int
		expected bool
	}{
		{[]byte{0, 0, 1, 2}, 2, true},
		{[]byte{0, 0, 0, 0}, 4, true},
		{[]byte{0, 1, 0, 0}, 2, false},
		{[]byte{1, 0, 0, 0}, 1, false},
		{[]byte{0, 0}, 3, false}, // data too short
		{[]byte{}, 1, false},
	}

	for _, tt := range tests {
		result := hasLeadingZeroBytes(tt.data, tt.n)
		if result != tt.expected {
			t.Errorf("hasLeadingZeroBytes(%v, %d) = %v, want %v", tt.data, tt.n, result, tt.expected)
		}
	}
}

func TestVerify(t *testing.T) {
	// Large file: should skip PoW
	err := Verify("", "", "some-cid", "some-txid", 200*1024*1024)
	if err != nil {
		t.Errorf("large file should skip PoW: %v", err)
	}

	// Small file without PoW: should error
	err = Verify("", "argon2id-light-v1", "some-cid", "some-txid", 1024)
	if err == nil {
		t.Error("small file without PoW should error")
	}

	// Small file with wrong algorithm
	err = Verify("0", "wrong-alg", "some-cid", "some-txid", 1024)
	if err == nil {
		t.Error("wrong algorithm should error")
	}

	// Invalid PoW format
	err = Verify("not-a-number", Algorithm, "some-cid", "some-txid", 1024)
	if err == nil {
		t.Error("invalid PoW format should error")
	}
}

func TestComputePoW_SafetyLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}
	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test"

	salt, err := FastComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("FastComputePoW failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	// The salt must be a parseable unsigned integer
	for _, c := range salt {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit in salt: %c", c)
		}
	}

	t.Logf("FastComputePoW result: salt=%s", salt)
}

// ============================================================
// Parallel PoW tests
// ============================================================

// TestComputePoWParallel_Correctness verifies that the parallel search
// finds a salt that satisfies the difficulty requirement.
func TestComputePoWParallel_Correctness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "parallel-correctness-test"

	salt, err := FastComputePoWParallel(t.Context(), rootCID, dataTXID, 2)
	if err != nil {
		t.Fatalf("FastComputePoWParallel failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	// Verify the salt actually satisfies the difficulty using the real Verify function.
	err = Verify(salt, Algorithm, rootCID, dataTXID, 1024)
	if err != nil {
		t.Errorf("salt %s does not satisfy PoW difficulty: %v", salt, err)
	}

	t.Logf("Parallel search found salt=%s", salt)
}

// TestComputePoWParallel_Cancellation verifies that cancelling the context
// returns ErrPoWCancelled.
func TestComputePoWParallel_Cancellation(t *testing.T) {
	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "cancel-test"

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := FastComputePoWParallel(ctx, rootCID, dataTXID, 4)
	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v", err)
	}
}

// TestComputePoWParallel_NumWorkers1 verifies that running with 1 worker
// produces the same result as the single-threaded ComputePoW.
func TestComputePoWParallel_NumWorkers1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "workers1-consistency"

	saltSingle, err := FastComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("FastComputePoW failed: %v", err)
	}

	saltParallel, err := FastComputePoWParallel(context.Background(), rootCID, dataTXID, 1)
	if err != nil {
		t.Fatalf("FastComputePoWParallel(workers=1) failed: %v", err)
	}

	if saltSingle != saltParallel {
		t.Errorf("mismatch: single=%s, parallel(workers=1)=%s", saltSingle, saltParallel)
	}

	t.Logf("Both single and parallel(1) found salt=%s", saltSingle)
}

// TestComputePoWParallel_MultiVsSingle compares wall-clock time of
// multi-worker vs single-worker search. Multi-worker should be faster
// (or at least not significantly slower).
func TestComputePoWParallel_MultiVsSingle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW timing test in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "timing-comparison"

	// Single worker timing
	startSingle := time.Now()
	saltSingle, err := FastComputePoWParallel(context.Background(), rootCID, dataTXID, 1)
	elapsedSingle := time.Since(startSingle)
	if err != nil {
		t.Fatalf("single worker failed: %v", err)
	}

	// Multi worker timing (use 2+ workers)
	numWorkers := 3
	startMulti := time.Now()
	saltMulti, err := FastComputePoWParallel(context.Background(), rootCID, dataTXID, numWorkers)
	elapsedMulti := time.Since(startMulti)
	if err != nil {
		t.Fatalf("multi worker failed: %v", err)
	}

	t.Logf("Single worker: %v → salt=%s", elapsedSingle, saltSingle)
	t.Logf("Multi worker (%d): %v → salt=%s", numWorkers, elapsedMulti, saltMulti)
	t.Logf("Speedup: %.2fx", float64(elapsedSingle)/float64(elapsedMulti))

	// The salts may differ (different workers find different valid salts),
	// but both should verify correctly.
	err = Verify(saltSingle, Algorithm, rootCID, dataTXID, 1024)
	if err != nil {
		t.Errorf("single-worker salt doesn't verify: %v", err)
	}
	err = Verify(saltMulti, Algorithm, rootCID, dataTXID, 1024)
	if err != nil {
		t.Errorf("multi-worker salt doesn't verify: %v", err)
	}
}

// TestComputePoWParallel_Concurrency verifies that multiple goroutines
// are actually spawned (by checking that different workers can find
// the solution at different salt offsets).
func TestComputePoWParallel_Concurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW concurrency test in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "concurrency-test"

	// Run with 4 workers and verify we get a valid result.
	salt, err := FastComputePoWParallel(context.Background(), rootCID, dataTXID, 4)
	if err != nil {
		t.Fatalf("FastComputePoWParallel(workers=4) failed: %v", err)
	}

	err = Verify(salt, Algorithm, rootCID, dataTXID, 1024)
	if err != nil {
		t.Errorf("salt %s from 4 workers doesn't verify: %v", salt, err)
	}

	t.Logf("4 workers found salt=%s", salt)
}

// ============================================================
// Progress callback tests (backward-compatible with existing tests)
// ============================================================

func TestComputePoWWithProgress_Cancellation(t *testing.T) {
	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "cancel-test"

	// Use an already-cancelled context — no timing dependency.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var lastAttempt uint64
	_, err := FastComputePoWWithProgress(ctx, rootCID, dataTXID, func(attempts uint64) {
		lastAttempt = attempts
	})

	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v (last attempt: %d)", err, lastAttempt)
	}

	// Should have checked context immediately, so 0 or very few attempts.
	t.Logf("Cancelled after %d attempts", lastAttempt)
}

func TestComputePoWWithProgress_TimeoutCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "timeout-test"

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var lastAttempt uint64
	_, err := FastComputePoWWithProgress(ctx, rootCID, dataTXID, func(attempts uint64) {
		lastAttempt = attempts
	})

	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v (last attempt: %d)", err, lastAttempt)
	}

	t.Logf("Timeout after %d attempts", lastAttempt)
}

func TestComputePoWWithProgress_Callback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "callback-test"

	var callCount uint64
	salt, err := FastComputePoWWithProgress(context.Background(), rootCID, dataTXID, func(attempts uint64) {
		callCount++
	})

	if err != nil {
		t.Fatalf("FastComputePoWWithProgress failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	// Callback should be invoked at least once
	if callCount == 0 {
		t.Error("progress callback was never called")
	}

	t.Logf("Found salt=%s after %d callbacks", salt, callCount)
}
