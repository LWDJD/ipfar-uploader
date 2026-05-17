// Package arweave — context cancellation tests.
package arweave

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestContextCancellation_WaitForConfirmation verifies that WaitForConfirmation
// returns immediately when the context is cancelled.
func TestContextCancellation_WaitForConfirmation(t *testing.T) {
	// Create a test server that always returns 404 (not confirmed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := client.WaitForConfirmation(ctx, "test-tx-id", 100, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("WaitForConfirmation took too long to cancel: %v (expected < 500ms)", elapsed)
	}
	t.Logf("WaitForConfirmation cancelled after %v", elapsed)
}

// TestContextCancellation_WaitForConfirmation_PreCancelled verifies immediate
// return when context is already cancelled before the call.
func TestContextCancellation_WaitForConfirmation_PreCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"block_height":            0,
			"number_of_confirmations": 0,
		})
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	start := time.Now()
	_, err := client.WaitForConfirmation(ctx, "test-tx-id", 100, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from pre-cancelled context, got nil")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("WaitForConfirmation with pre-cancelled context took too long: %v", elapsed)
	}
	t.Logf("Pre-cancelled WaitForConfirmation returned after %v", elapsed)
}

// TestContextCancellation_GetTransactionStatus verifies HTTP request respects context.
func TestContextCancellation_GetTransactionStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.GetTransactionStatus(ctx, "test-tx-id")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed out context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("GetTransactionStatus took too long: %v (expected < 500ms)", elapsed)
	}
	t.Logf("GetTransactionStatus cancelled after %v: %v", elapsed, err)
}

// TestContextCancellation_SubmitTransaction verifies HTTP POST respects context.
func TestContextCancellation_SubmitTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	tx := &Transaction{
		Format:    2,
		ID:        "test-id",
		Owner:     "test-owner",
		DataSize:  "0",
		Signature: "test-sig",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.SubmitTransaction(ctx, tx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed out context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("SubmitTransaction took too long: %v (expected < 500ms)", elapsed)
	}
	t.Logf("SubmitTransaction cancelled after %v: %v", elapsed, err)
}

// TestContextCancellation_GetAnchor verifies GET respects context.
func TestContextCancellation_GetAnchor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`"test-anchor"`))
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.GetAnchor(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed out context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("GetAnchor took too long: %v (expected < 500ms)", elapsed)
	}
	t.Logf("GetAnchor cancelled after %v: %v", elapsed, err)
}

// TestContextCancellation_QueryExistingCARs verifies GraphQL POST respects context.
func TestContextCancellation_QueryExistingCARs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"transactions":{"edges":[]}}}`))
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.QueryExistingCARs(ctx, "test-root-cid", 5)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed out context, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("QueryExistingCARs took too long: %v (expected < 500ms)", elapsed)
	}
	t.Logf("QueryExistingCARs cancelled after %v: %v", elapsed, err)
}

// TestContextCancellation_retryWithBackoff verifies retry stops on context cancel.
func TestContextCancellation_retryWithBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := retryWithBackoff(ctx, func() error {
		return &http.ProtocolError{} // Not retryable actually
	}, 3, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("retryWithBackoff took too long: %v", elapsed)
	}
	t.Logf("retryWithBackoff cancelled after %v: %v", elapsed, err)
}

// TestContextCancellation_retryWithBackoff_RetryableError verifies context
// cancellation during sleep between retries for retryable errors.
func TestContextCancellation_retryWithBackoff_RetryableError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	callCount := 0
	start := time.Now()
	err := retryWithBackoff(ctx, func() error {
		callCount++
		return fmtError("gateway returned 502: bad gateway")
	}, 3, []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("retryWithBackoff took too long: %v (callCount=%d)", elapsed, callCount)
	}
	t.Logf("retryWithBackoff cancelled after %v: %v (callCount=%d)", elapsed, err, callCount)
}

// fmtError implements the error interface for a string.
type fmtError string

func (e fmtError) Error() string { return string(e) }
