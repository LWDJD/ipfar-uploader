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
