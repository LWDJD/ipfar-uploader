package arweave

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// Merkle tree tests
// =============================================================================

func TestComputeChunksAndProofs_Empty(t *testing.T) {
	root, proofs := computeChunksAndProofs([]byte{})
	// Empty data: root = SHA256(nil)
	expected := sha256.Sum256(nil)
	if string(root) != string(expected[:]) {
		t.Errorf("empty data root mismatch: got %x, expected %x", root, expected[:])
	}
	if len(proofs) != 0 {
		t.Errorf("expected 0 proofs for empty data, got %d", len(proofs))
	}
}

func TestComputeChunksAndProofs_SingleChunk(t *testing.T) {
	data := make([]byte, 100) // less than ChunkSize
	for i := range data {
		data[i] = byte(i)
	}

	root, proofs := computeChunksAndProofs(data)

	// Root should be SHA-256 of the data
	expected := sha256.Sum256(data)
	if string(root) != string(expected[:]) {
		t.Errorf("single chunk root mismatch")
	}

	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(proofs))
	}

	if proofs[0].Offset != 0 {
		t.Errorf("expected offset 0, got %d", proofs[0].Offset)
	}
	if string(proofs[0].Chunk) != string(data) {
		t.Errorf("chunk data mismatch")
	}
	if len(proofs[0].Proof) != 0 {
		t.Errorf("single chunk proof should be empty, got %d bytes", len(proofs[0].Proof))
	}
}

func TestComputeChunksAndProofs_TwoChunks(t *testing.T) {
	// Two full chunks
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %d", len(proofs))
	}

	// Verify root manually
	h0 := sha256.Sum256(data[:ChunkSize])
	h1 := sha256.Sum256(data[ChunkSize:])
	combined := make([]byte, 64)
	copy(combined[:32], h0[:])
	copy(combined[32:], h1[:])
	expectedRoot := sha256.Sum256(combined)

	if string(root) != string(expectedRoot[:]) {
		t.Errorf("two-chunk root mismatch")
	}

	// Proof for chunk 0: sibling = h1
	if string(proofs[0].Proof) != string(h1[:]) {
		t.Errorf("chunk 0 proof mismatch: got %x, expected %x", proofs[0].Proof, h1[:])
	}

	// Proof for chunk 1: sibling = h0
	if string(proofs[1].Proof) != string(h0[:]) {
		t.Errorf("chunk 1 proof mismatch: got %x, expected %x", proofs[1].Proof, h0[:])
	}

	// Verify each proof can reconstruct the root
	for i, cp := range proofs {
		reconstructed := verifyProof(cp, root, 2)
		if !reconstructed {
			t.Errorf("proof %d failed to verify against root", i)
		}
	}
}

func TestComputeChunksAndProofs_ThreeChunks(t *testing.T) {
	data := make([]byte, ChunkSize*3)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 3 {
		t.Fatalf("expected 3 proofs, got %d", len(proofs))
	}

	// Verify manually
	h0 := sha256.Sum256(data[0*ChunkSize:1*ChunkSize])
	h1 := sha256.Sum256(data[1*ChunkSize:2*ChunkSize])
	h2 := sha256.Sum256(data[2*ChunkSize:3*ChunkSize])

	c01 := make([]byte, 64)
	copy(c01[:32], h0[:])
	copy(c01[32:], h1[:])
	h01 := sha256.Sum256(c01)

	c012 := make([]byte, 64)
	copy(c012[:32], h01[:])
	copy(c012[32:], h2[:])
	expectedRoot := sha256.Sum256(c012)

	if string(root) != string(expectedRoot[:]) {
		t.Errorf("three-chunk root mismatch")
	}

	// Proof for chunk 0: h1 || h2
	expectedP0 := make([]byte, 64)
	copy(expectedP0[:32], h1[:])
	copy(expectedP0[32:], h2[:])
	if string(proofs[0].Proof) != string(expectedP0) {
		t.Errorf("chunk 0 proof mismatch")
	}

	// Proof for chunk 1: h0 || h2
	expectedP1 := make([]byte, 64)
	copy(expectedP1[:32], h0[:])
	copy(expectedP1[32:], h2[:])
	if string(proofs[1].Proof) != string(expectedP1) {
		t.Errorf("chunk 1 proof mismatch")
	}

	// Proof for chunk 2: h01 (no leaf sibling, one parent sibling)
	expectedP2 := h01[:]
	if string(proofs[2].Proof) != string(expectedP2) {
		t.Errorf("chunk 2 proof mismatch: got %x, expected %x", proofs[2].Proof, expectedP2)
	}

	// Verify all proofs
	for i, cp := range proofs {
		if !verifyProof(cp, root, 3) {
			t.Errorf("proof %d (3-chunk) failed verification", i)
		}
	}
}

func TestComputeChunksAndProofs_FiveChunks(t *testing.T) {
	data := make([]byte, ChunkSize*5)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 5 {
		t.Fatalf("expected 5 proofs, got %d", len(proofs))
	}

	for i, cp := range proofs {
		if !verifyProof(cp, root, 5) {
			t.Errorf("proof %d (5-chunk) failed verification", i)
		}
	}
}

func TestComputeChunksAndProofs_PartialLastChunk(t *testing.T) {
	// 2.5 chunks worth of data
	data := make([]byte, ChunkSize*2+ChunkSize/2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 3 {
		t.Fatalf("expected 3 proofs, got %d", len(proofs))
	}

	// Last chunk should be partial
	if len(proofs[2].Chunk) != ChunkSize/2 {
		t.Errorf("last chunk size mismatch: got %d, expected %d", len(proofs[2].Chunk), ChunkSize/2)
	}

	for i, cp := range proofs {
		if !verifyProof(cp, root, 3) {
			t.Errorf("proof %d (partial) failed verification", i)
		}
	}
}

func TestComputeChunksDeterminism(t *testing.T) {
	data := make([]byte, ChunkSize*4)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root1, _ := computeChunksAndProofs(data)
	root2, _ := computeChunksAndProofs(data)

	if string(root1) != string(root2) {
		t.Fatal("Merkle root not deterministic")
	}
}

func TestComputeChunksDifferentDataDifferentRoot(t *testing.T) {
	data1 := make([]byte, ChunkSize*2)
	data2 := make([]byte, ChunkSize*2)
	for i := range data2 {
		data2[i] = byte(i % 256)
	}
	// data1 is all zeros, data2 has varied content

	root1, _ := computeChunksAndProofs(data1)
	root2, _ := computeChunksAndProofs(data2)

	if string(root1) == string(root2) {
		t.Fatal("different data should produce different roots")
	}
}

// =============================================================================
// Proof verification helper
// =============================================================================

// verifyProof checks that a chunk + proof reconstruct to the expected root.
// totalChunks is the total number of chunks the data was split into.
func verifyProof(cp chunkProof, root []byte, totalChunks int) bool {
	leafHash := sha256.Sum256(cp.Chunk)

	current := leafHash[:]
	proof := cp.Proof

	idx := cp.Offset / ChunkSize
	levelCount := totalChunks

	for levelCount > 1 {
		siblingIdx := idx ^ 1
		if siblingIdx < levelCount {
			// Sibling exists — consume 32 bytes from proof
			if len(proof) < 32 {
				return false
			}
			sibling := proof[:32]
			proof = proof[32:]

			var combined [64]byte
			if idx%2 == 0 {
				// current is left child
				copy(combined[:32], current)
				copy(combined[32:], sibling)
			} else {
				// current is right child
				copy(combined[:32], sibling)
				copy(combined[32:], current)
			}
			h := sha256.Sum256(combined[:])
			current = h[:]
		}
		// else: no sibling, node is promoted — current stays the same

		idx = idx / 2
		levelCount = (levelCount + 1) / 2
	}

	return string(current) == string(root)
}

// =============================================================================
// Mock server tests for chunked upload
// =============================================================================

func newMockChunkedServer() *httptest.Server {
	// Track uploaded chunks
	chunks := make(map[int][]byte)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/chunk" && r.Method == "POST":
			var req chunkUploadRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			offset, _ := strconv.Atoi(req.Offset)
			chunkData, _ := base64.RawURLEncoding.DecodeString(req.Chunk)
			chunks[offset] = chunkData
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))

		case r.URL.Path == "/tx" && r.Method == "POST":
			// Should be a chunked tx (no data field, has data_root)
			var tx map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Verify no data field is present
			if _, hasData := tx["data"]; hasData && tx["data"] != "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"chunked tx should not have data field"}`))
				return
			}
			if _, hasRoot := tx["data_root"]; !hasRoot {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"chunked tx missing data_root"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"chunked-tx-id"}`))

		case r.URL.Path == "/price/0":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1000"))

		case r.URL.Path == "/tx_anchor":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor"`))

		case strings.HasPrefix(r.URL.Path, "/raw/") && r.Method == "GET":
			// Serve the first chunk for verification
			txID := strings.TrimPrefix(r.URL.Path, "/raw/")
			w.Header().Set("Content-Type", "application/octet-stream")
			// Reconstruct the expected first chunk
			// The test data is ChunkSize+100 bytes of i%256
			chunkLen := ChunkSize
			firstChunk := make([]byte, chunkLen)
			for i := 0; i < chunkLen; i++ {
				firstChunk[i] = byte(i % 256)
			}
			// Handle range request
			if rng := r.Header.Get("Range"); rng != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			w.Write(firstChunk)
			_ = txID

		case strings.HasPrefix(r.URL.Path, "/tx/") && r.Method == "GET":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":2000000,"block_indep_hash":"mock-hash"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestUploadDataChunked_FullFlow(t *testing.T) {
	server := newMockChunkedServer()
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	// Create data just over ChunkSize to ensure chunked path
	data := make([]byte, ChunkSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	tags := []Tag{{Name: "Test", Value: "Chunked"}}

	tx, status, err := client.UploadDataChunked(wallet, data, tags)
	if err != nil {
		t.Fatalf("UploadDataChunked failed: %v", err)
	}

	if tx.ID == "" {
		t.Error("tx ID should be set")
	}
	if tx.DataRoot == "" {
		t.Error("data_root should be set")
	}
	if tx.DataSize != strconv.Itoa(len(data)) {
		t.Errorf("data_size mismatch: got %s, expected %d", tx.DataSize, len(data))
	}
	if tx.Data != "" {
		t.Error("data field should be empty for chunked tx")
	}
	if status.BlockHeight != 2000000 {
		t.Errorf("expected block height 2000000, got %d", status.BlockHeight)
	}

	t.Logf("Chunked upload complete: tx=%s, root=%s, size=%s, height=%d",
		tx.ID, tx.DataRoot, tx.DataSize, status.BlockHeight)
}

func TestUploadData_AutoChunkedRouting(t *testing.T) {
	// Test that UploadData routes to chunked path for large data
	server := newMockChunkedServer()
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	// Data >= 256KB → should use chunked
	largeData := make([]byte, ChunkSize+1)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	tx, _, err := client.UploadData(wallet, largeData, nil)
	if err != nil {
		t.Fatalf("UploadData with large data failed: %v", err)
	}
	if tx.Data != "" {
		t.Error("large data tx should have empty data field (chunked path)")
	}
	if tx.DataRoot == "" {
		t.Error("large data tx should have data_root")
	}
	t.Logf("Large data → chunked path: tx=%s", tx.ID)
}

func TestUploadData_SmallDataOldPath(t *testing.T) {
	// Test that small data still uses old /tx path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx" && r.Method == "POST" {
			var tx map[string]interface{}
			json.NewDecoder(r.Body).Decode(&tx)
			if _, hasData := tx["data"]; !hasData || tx["data"] == "" {
				// For small data, must have data field
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"small data tx should have data field"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"small-tx-id"}`))
			return
		}
		if r.URL.Path == "/price/0" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1000"))
			return
		}
		if r.URL.Path == "/tx_anchor" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor"`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/tx/") && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":100}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	smallData := []byte("hello arweave")
	tx, _, err := client.UploadData(wallet, smallData, nil)
	if err != nil {
		t.Fatalf("UploadData with small data failed: %v", err)
	}
	if tx.Data == "" {
		t.Error("small data tx should have data field (old path)")
	}
	t.Logf("Small data → old path: tx=%s", tx.ID)
}

func TestUploadDataChunked_SignatureValid(t *testing.T) {
	// Verify the transaction signature is valid for chunked txs
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	nBytes := privKey.N.Bytes()
	owner := base64.RawURLEncoding.EncodeToString(nBytes)

	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Compute root
	root, _ := computeChunksAndProofs(data)
	dataRoot := base64.RawURLEncoding.EncodeToString(root)

	tx := buildChunkedTransaction(owner, len(data), dataRoot, []Tag{{Name: "T", Value: "V"}}, "1000", "anchor-xxx")
	if err := tx.Sign(privKey); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if tx.Signature == "" {
		t.Fatal("empty signature")
	}
	if tx.ID == "" {
		t.Fatal("empty ID")
	}

	// Verify signature against the same deep hash
	sigData := tx.deepHash()
	hashed := sha256.Sum256(sigData)

	sigBytes, err := base64.RawURLEncoding.DecodeString(tx.Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	err = rsa.VerifyPSS(&privKey.PublicKey, crypto.SHA256, hashed[:], sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	t.Logf("Chunked tx signature valid: id=%s", tx.ID)
}

// =============================================================================
// Streaming Merkle tree tests
// =============================================================================

func TestComputeMerkleTreeFromReader_MatchesInMemory(t *testing.T) {
	// Verify that the streaming Merkle tree produces the same root as the
	// in-memory version for various data sizes.
	sizes := []int{
		0,
		100,
		ChunkSize,
		ChunkSize + 1,
		ChunkSize * 2,
		ChunkSize*2 + ChunkSize/2,
		ChunkSize * 5,
	}

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		// In-memory
		rootMem, _ := computeChunksAndProofs(data)

		// Streaming via bytes.NewReader
		reader := bytes.NewReader(data)
		rootStream, nodesStream, nChunks, leafHashes, err := computeMerkleTreeFromReader(reader, int64(size))
		if err != nil {
			t.Fatalf("size=%d: streaming tree failed: %v", size, err)
		}

		if !bytes.Equal(rootMem, rootStream) {
			t.Errorf("size=%d: root mismatch; in-memory=%x streaming=%x", size, rootMem, rootStream)
		}

		// Verify leaf hashes match chunk hashes
		if nChunks > 0 {
			if len(leafHashes) != nChunks {
				t.Errorf("size=%d: expected %d leaf hashes, got %d", size, nChunks, len(leafHashes))
			}

			// Spot-check: verify each leaf hash against directly computed hash
			for i := 0; i < nChunks; i++ {
				start := i * ChunkSize
				end := start + ChunkSize
				if end > size {
					end = size
				}
				expectedHash := sha256.Sum256(data[start:end])
				if !bytes.Equal(leafHashes[i], expectedHash[:]) {
					t.Errorf("size=%d chunk %d: leaf hash mismatch", size, i)
				}
			}

			// Verify proof for each chunk
			_ = nodesStream
			for i := 0; i < nChunks; i++ {
				proof := collectProof(nodesStream, i, nChunks)
				start := i * ChunkSize
				end := start + ChunkSize
				if end > size {
					end = size
				}
				// Verify using the in-memory verification helper
				cp := chunkProof{
					Offset: start,
					Chunk:  data[start:end],
					Proof:  proof,
				}
				if !verifyProof(cp, rootStream, nChunks) {
					t.Errorf("size=%d chunk %d: proof verification failed", size, i)
				}
			}
		}
	}
}

// =============================================================================
// Reader error handling tests
// =============================================================================

type brokenReaderAt struct {
	data       []byte
	failAtByte int64 // return an error after reading this many bytes
}

func (b *brokenReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	if b.failAtByte >= 0 && off >= b.failAtByte {
		return 0, fmt.Errorf("simulated read error at offset %d", off)
	}
	end := off + int64(len(p))
	if end > int64(len(b.data)) {
		end = int64(len(b.data))
	}
	n := copy(p, b.data[off:end])
	if off+int64(n) >= int64(len(b.data)) {
		return n, io.EOF
	}
	return n, nil
}

func TestComputeMerkleTreeFromReader_ReadError(t *testing.T) {
	data := make([]byte, ChunkSize*3)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Fail at the second chunk (offset ChunkSize)
	broken := &brokenReaderAt{data: data, failAtByte: ChunkSize}
	_, _, _, _, err := computeMerkleTreeFromReader(broken, int64(len(data)))
	if err == nil {
		t.Fatal("expected error from broken reader, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestUploadChunksStreaming_ReadError(t *testing.T) {
	// Test that second-pass read errors are propagated
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// First pass succeeds (use a good reader)
	goodReader := bytes.NewReader(data)
	_, nodes, nChunks, _, err := computeMerkleTreeFromReader(goodReader, int64(len(data)))
	if err != nil {
		t.Fatalf("first pass failed: %v", err)
	}

	// Second pass: break at offset zero (first chunk read fails)
	broken := &brokenReaderAt{data: data, failAtByte: 0}

	server := newMockChunkedServer()
	defer server.Close()
	client := NewGatewayClient(server.URL)

	err = client.uploadChunksStreaming("mock-root", len(data), broken, nodes, nChunks)
	if err == nil {
		t.Fatal("expected error from broken reader in second pass, got nil")
	}
	t.Logf("Got expected second-pass error: %v", err)
}

// =============================================================================
// Data corruption detection tests
// =============================================================================

func TestVerifyFirstChunk_Success(t *testing.T) {
	// Create test data and a mock server that returns the correct first chunk
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	expectedHash := sha256.Sum256(data[:ChunkSize])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			w.Header().Set("Content-Type", "application/octet-stream")
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			w.Write(data[:ChunkSize])
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyFirstChunk("test-tx-id", expectedHash[:], int64(len(data)))
	if err != nil {
		t.Fatalf("verifyFirstChunk should succeed: %v", err)
	}
}

func TestVerifyFirstChunk_Corruption(t *testing.T) {
	// Return corrupted data → verification must fail
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	expectedHash := sha256.Sum256(data[:ChunkSize])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			// Return CORRUPTED data (all zeros instead of pattern)
			corrupted := make([]byte, ChunkSize)
			w.Header().Set("Content-Type", "application/octet-stream")
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			w.Write(corrupted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyFirstChunk("test-tx-id", expectedHash[:], int64(len(data)))
	if err == nil {
		t.Fatal("verifyFirstChunk MUST return an error for corrupted data")
	}
	t.Logf("Corruption correctly detected: %v", err)
}

func TestVerifyFirstChunk_EmptyResponse(t *testing.T) {
	// Empty response body → verification must fail
	data := make([]byte, ChunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	expectedHash := sha256.Sum256(data)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			// Return empty body (data not available yet)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			// No body written
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyFirstChunk("test-tx-id", expectedHash[:], int64(len(data)))
	if err == nil {
		t.Fatal("verifyFirstChunk MUST return an error for empty response")
	}
	t.Logf("Empty response correctly detected: %v", err)
}

// =============================================================================
// Test helpers
// =============================================================================

// verifyProof belongs to the Merkle tree section above.
