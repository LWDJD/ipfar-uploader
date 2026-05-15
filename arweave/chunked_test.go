package arweave

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// =============================================================================
// Merkle tree tests (annotated ar_merkle.erl format)
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

	// Root should be chunkLeafHash(SHA-256(data), 100)
	chunkHash := sha256.Sum256(data)
	expectedRoot := chunkLeafHash(chunkHash[:], 100)
	if string(root) != string(expectedRoot) {
		t.Errorf("single chunk root mismatch: got %x, expected %x", root, expectedRoot)
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
	// Single chunk: proof should be [dataHash(32)] [endOffset(32)] = 64 bytes
	if len(proofs[0].Proof) != 64 {
		t.Errorf("single chunk proof should be 64 bytes, got %d", len(proofs[0].Proof))
	}

	// Verify the proof reconstructs the root
	if !verifyProofArweave(proofs[0], root, 1) {
		t.Errorf("single chunk proof failed verification")
	}
}

func TestComputeChunksAndProofs_TwoChunks(t *testing.T) {
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %d", len(proofs))
	}

	// Verify all proofs
	for i, cp := range proofs {
		if !verifyProofArweave(cp, root, 2) {
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

	for i, cp := range proofs {
		if !verifyProofArweave(cp, root, 3) {
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
		if !verifyProofArweave(cp, root, 5) {
			t.Errorf("proof %d (5-chunk) failed verification", i)
		}
	}
}

func TestComputeChunksAndProofs_PartialLastChunk(t *testing.T) {
	data := make([]byte, ChunkSize*2+ChunkSize/2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	root, proofs := computeChunksAndProofs(data)

	if len(proofs) != 3 {
		t.Fatalf("expected 3 proofs, got %d", len(proofs))
	}

	if len(proofs[2].Chunk) != ChunkSize/2 {
		t.Errorf("last chunk size mismatch: got %d, expected %d", len(proofs[2].Chunk), ChunkSize/2)
	}

	for i, cp := range proofs {
		if !verifyProofArweave(cp, root, 3) {
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

	root1, _ := computeChunksAndProofs(data1)
	root2, _ := computeChunksAndProofs(data2)

	if string(root1) == string(root2) {
		t.Fatal("different data should produce different roots")
	}
}

// =============================================================================
// Proof verification helper (annotated ar_merkle.erl format)
// =============================================================================

// verifyProofArweave checks that an Arweave data_path proof reconstructs
// to the expected Merkle root.  totalChunks is the total number of chunks.
//
// The proof format (matching ar_merkle.erl:validate_path and arweave-js
// merkle.js:validatePath) is walked FORWARD from root to leaf:
//
//	root segment → [leftID(32)][rightID(32)][note(32)]
//	  → compute branchHash, verify it matches expected parent ID
//	  → recurse into left or right child based on the chunk offset
//	... repeat ...
//	leaf segment → [dataHash(32)][endOffset(32)]
//	  → compute leafHash, verify it matches the last expected child ID
func verifyProofArweave(cp chunkProof, root []byte, totalChunks int) bool {
	proof := cp.Proof
	if len(proof) < 64 {
		return false
	}

	// Determine the chunk's end offset and the "dest" byte (offset - 1,
	// matching what gets sent to the /chunk endpoint).
	endOffset := cp.Offset + len(cp.Chunk)
	dest := endOffset - 1 // the byte we're proving inclusion for

	// Walk the proof FORWARD (root → leaf)
	remaining := proof
	expectedID := root

	for {
		if len(remaining) == 64 {
			// ---- Leaf: [dataHash(32)] [endOffset(32)] ----
			leafData := remaining[:32]
			leafNote := remaining[32:64]

			// Verify leaf data hash matches the actual chunk
			actualChunkHash := sha256.Sum256(cp.Chunk)
			if !bytes.Equal(leafData, actualChunkHash[:]) {
				return false
			}

			leafEndOffset := binary.BigEndian.Uint64(leafNote[noteSize-8:])
			computedLeafID := chunkLeafHash(leafData, leafEndOffset)

			return bytes.Equal(computedLeafID, expectedID)
		}

		if len(remaining) < 96 {
			return false // malformed proof
		}

		// ---- Branch: [leftID(32)] [rightID(32)] [note(32)] ----
		leftID := remaining[:32]
		rightID := remaining[32:64]
		note := remaining[64:96]
		remaining = remaining[96:]

		leftMax := binary.BigEndian.Uint64(note[noteSize-8:])

		// Compute branch hash and verify it matches the expected ID
		computedBranchID := chunkBranchHash(leftID, rightID, leftMax)
		if !bytes.Equal(computedBranchID, expectedID) {
			return false
		}

		// Decide which child to follow based on dest byte
		if uint64(dest) < leftMax {
			expectedID = leftID
		} else {
			expectedID = rightID
		}
	}
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
			dataSize := ChunkSize + 100
			w.Header().Set("Content-Type", "application/octet-stream")

			start := int64(0)
			end := int64(dataSize) - 1

			if rng := r.Header.Get("Range"); rng != "" {
				if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if end >= int64(dataSize) {
					end = int64(dataSize) - 1
				}
				w.WriteHeader(http.StatusPartialContent)
			}

			chunk := make([]byte, end-start+1)
			for i := int64(0); i < int64(len(chunk)); i++ {
				chunk[i] = byte((start + i) % 256)
			}
			w.Write(chunk)

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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx" && r.Method == "POST" {
			var tx map[string]interface{}
			json.NewDecoder(r.Body).Decode(&tx)
			if _, hasData := tx["data"]; !hasData || tx["data"] == "" {
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

		// In-memory (annotated Merkle)
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

		// Verify proof for each chunk
		if nChunks > 0 {
			for i := 0; i < nChunks; i++ {
				start := i * ChunkSize
				end := start + ChunkSize
				if end > size {
					end = size
				}
				proof := collectProof(nodesStream, i, nChunks, leafHashes[i])
				cp := chunkProof{
					Offset: start,
					Chunk:  data[start:end],
					Proof:  proof,
				}
				if !verifyProofArweave(cp, rootStream, nChunks) {
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
	failAtByte int64
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

	broken := &brokenReaderAt{data: data, failAtByte: ChunkSize}
	_, _, _, _, err := computeMerkleTreeFromReader(broken, int64(len(data)))
	if err == nil {
		t.Fatal("expected error from broken reader, got nil")
	}
	t.Logf("Got expected error: %v", err)
}

func TestUploadChunksStreaming_ReadError(t *testing.T) {
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	goodReader := bytes.NewReader(data)
	_, nodes, nChunks, leafHashes, err := computeMerkleTreeFromReader(goodReader, int64(len(data)))
	if err != nil {
		t.Fatalf("first pass failed: %v", err)
	}

	broken := &brokenReaderAt{data: data, failAtByte: 0}

	server := newMockChunkedServer()
	defer server.Close()
	client := NewGatewayClient(server.URL)

	err = client.uploadChunksStreaming("mock-root", len(data), broken, nodes, nChunks, leafHashes)
	if err == nil {
		t.Fatal("expected error from broken reader in second pass, got nil")
	}
	t.Logf("Got expected second-pass error: %v", err)
}

// =============================================================================
// Data corruption detection tests
// =============================================================================

func TestVerifyAllChunks_Success(t *testing.T) {
	data := make([]byte, ChunkSize*3+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	leafHashes := make([][]byte, nChunks)
	for i := 0; i < nChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		h := sha256.Sum256(data[start:end])
		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], h[:])
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			w.Header().Set("Content-Type", "application/octet-stream")

			start := int64(0)
			end := int64(len(data)) - 1

			if rng := r.Header.Get("Range"); rng != "" {
				fmt.Sscanf(rng, "bytes=%d-%d", &start, &end)
				if end >= int64(len(data)) {
					end = int64(len(data)) - 1
				}
				w.WriteHeader(http.StatusPartialContent)
			}

			chunk := make([]byte, end-start+1)
			for i := int64(0); i < int64(len(chunk)); i++ {
				chunk[i] = byte((start + i) % 256)
			}
			w.Write(chunk)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyAllChunks("test-tx-id", leafHashes, int64(len(data)))
	if err != nil {
		t.Fatalf("verifyAllChunks should succeed: %v", err)
	}
}

func TestVerifyAllChunks_Corruption(t *testing.T) {
	data := make([]byte, ChunkSize*3+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	leafHashes := make([][]byte, nChunks)
	for i := 0; i < nChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		h := sha256.Sum256(data[start:end])
		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], h[:])
	}

	corruptIdx := 1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			w.Header().Set("Content-Type", "application/octet-stream")

			start := int64(0)
			end := int64(len(data)) - 1

			if rng := r.Header.Get("Range"); rng != "" {
				fmt.Sscanf(rng, "bytes=%d-%d", &start, &end)
				if end >= int64(len(data)) {
					end = int64(len(data)) - 1
				}
				w.WriteHeader(http.StatusPartialContent)
			}

			chunk := make([]byte, end-start+1)
			for i := int64(0); i < int64(len(chunk)); i++ {
				chunk[i] = byte((start + i) % 256)
			}

			corruptStart := int64(corruptIdx * ChunkSize)
			corruptEnd := corruptStart + int64(ChunkSize) - 1
			if start <= corruptEnd && end >= corruptStart {
				for i := int64(0); i < int64(len(chunk)); i++ {
					absIdx := start + i
					if absIdx >= corruptStart && absIdx <= corruptEnd {
						chunk[i] ^= 0xFF
					}
				}
			}

			w.Write(chunk)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyAllChunks("test-tx-id", leafHashes, int64(len(data)))
	if err == nil {
		t.Fatal("verifyAllChunks MUST return an error for corrupted data")
	}
	t.Logf("Corruption correctly detected: %v", err)
}

func TestVerifyAllChunks_EmptyResponse(t *testing.T) {
	data := make([]byte, ChunkSize*2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	leafHashes := make([][]byte, nChunks)
	for i := 0; i < nChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		h := sha256.Sum256(data[start:end])
		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], h[:])
	}

	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raw/") {
			w.Header().Set("Content-Type", "application/octet-stream")

			if atomic.AddInt32(&requestCount, 1) == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}

			start := int64(0)
			end := int64(len(data)) - 1
			if rng := r.Header.Get("Range"); rng != "" {
				fmt.Sscanf(rng, "bytes=%d-%d", &start, &end)
				if end >= int64(len(data)) {
					end = int64(len(data)) - 1
				}
				w.WriteHeader(http.StatusPartialContent)
			}

			chunk := make([]byte, end-start+1)
			for i := int64(0); i < int64(len(chunk)); i++ {
				chunk[i] = byte((start + i) % 256)
			}
			w.Write(chunk)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	err := client.verifyAllChunks("test-tx-id", leafHashes, int64(len(data)))
	if err == nil {
		t.Fatal("verifyAllChunks MUST return an error for empty response")
	}
	t.Logf("Empty response correctly detected: %v", err)
}
