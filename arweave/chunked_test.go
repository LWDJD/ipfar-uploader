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
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	goartypes "github.com/LWDJD/ipfar-uploader/arweave/goar/types"
	goarutils "github.com/LWDJD/ipfar-uploader/arweave/goar/utils"
)

// =============================================================================
// Merkle tree tests (now using goar)
// =============================================================================

func TestComputeChunksAndProofs_Empty(t *testing.T) {
	root, proofs := computeChunksAndProofs([]byte{})
	// Empty data: root = SHA256(nil) or empty
	if len(proofs) != 0 {
		t.Errorf("expected 0 proofs for empty data, got %d", len(proofs))
	}
	t.Logf("Empty data root: %x", root)
}

func TestComputeChunksAndProofs_SingleChunk(t *testing.T) {
	data := make([]byte, 100) // less than ChunkSize
	for i := range data {
		data[i] = byte(i)
	}

	root, proofs := computeChunksAndProofs(data)

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
	if !verifyProofGoar(proofs[0], root, 1) {
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

	for i, cp := range proofs {
		if !verifyProofGoar(cp, root, 2) {
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
		if !verifyProofGoar(cp, root, 3) {
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
		if !verifyProofGoar(cp, root, 5) {
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
		if !verifyProofGoar(cp, root, 3) {
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
// Proof verification helper (using goar's validatePath)
// =============================================================================

// verifyProofGoar checks that a chunk proof validates using goar's ValidatePath.
// totalSize is the total data size in bytes.
func verifyProofGoar(cp chunkProof, root []byte, totalSize int) bool {
	if len(cp.Proof) < 64 {
		return false
	}

	endOffset := cp.Offset + len(cp.Chunk)
	dest := endOffset - 1

	result, ok := goarutils.ValidatePath(root, dest, 0, totalSize, cp.Proof)
	if !ok || result == nil {
		return false
	}

	// Also verify chunk data hash matches
	actualHash := sha256.Sum256(cp.Chunk)
	if !bytes.Equal(actualHash[:], cp.Proof[:32]) {
		return false
	}

	return true
}

// =============================================================================
// Mock server tests for chunked upload
// =============================================================================

func newMockChunkedServer() *httptest.Server {
	chunks := make(map[int][]byte)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/chunk" && r.Method == "POST":
			var req goartypes.GetChunk
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
			var tx map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Verify no data field is present for chunked tx
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

	goarTags := []goartypes.Tag{{Name: "T", Value: "V"}}
	tx := &goartypes.Transaction{
		Format:   2,
		Owner:    owner,
		Target:   "",
		Quantity: "0",
		DataSize: strconv.Itoa(len(data)),
		Reward:   "1000",
		LastTx:   "anchor-xxx",
		Tags:     goarTags,
	}

	// Prepare chunks first
	if err := goarutils.PrepareChunks(tx, data, len(data)); err != nil {
		t.Fatalf("PrepareChunks failed: %v", err)
	}

	// Sign using goar's SHA-384 deep hash
	if err := goarutils.SignTransaction(tx, privKey); err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}

	if tx.Signature == "" {
		t.Fatal("empty signature")
	}
	if tx.ID == "" {
		t.Fatal("empty ID")
	}

	// Verify signature
	sigData, err := goarutils.GetSignatureData(tx)
	if err != nil {
		t.Fatalf("GetSignatureData failed: %v", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(tx.Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	hashed := sha256.Sum256(sigData)
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
// Streaming upload tests
// =============================================================================

func TestUploadDataChunkedStreamingFile(t *testing.T) {
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

	// Create a temp file with test data
	data := make([]byte, ChunkSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	tmpFile, err := os.CreateTemp("", "ipfar-test-*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatalf("failed to seek: %v", err)
	}

	tags := []Tag{{Name: "Test", Value: "Streaming"}}
	tx, status, err := client.UploadDataChunkedStreamingFile(wallet, tmpFile, int64(len(data)), tags)
	if err != nil {
		t.Fatalf("UploadDataChunkedStreamingFile failed: %v", err)
	}

	if tx.ID == "" {
		t.Error("tx ID should be set")
	}
	if status.BlockHeight != 2000000 {
		t.Errorf("expected block height 2000000, got %d", status.BlockHeight)
	}

	t.Logf("Streaming chunked upload complete: tx=%s", tx.ID)
}

func TestUploadDataChunkedStreaming_WithReaderAt(t *testing.T) {
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

	data := make([]byte, ChunkSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	tags := []Tag{{Name: "Test", Value: "ReaderAt"}}
	tx, status, err := client.UploadDataChunkedStreaming(wallet, reader, int64(len(data)), tags)
	if err != nil {
		t.Fatalf("UploadDataChunkedStreaming failed: %v", err)
	}

	if tx.ID == "" {
		t.Error("tx ID should be set")
	}
	if status.BlockHeight != 2000000 {
		t.Errorf("expected block height 2000000, got %d", status.BlockHeight)
	}

	t.Logf("ReaderAt chunked upload complete: tx=%s", tx.ID)
}

// =============================================================================
// Data corruption detection tests
// =============================================================================

func TestVerifyAllChunks_Success(t *testing.T) {
	data := make([]byte, ChunkSize*3+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Build a goar tx with chunks
	tx := &goartypes.Transaction{
		Format:   2,
		DataSize: strconv.Itoa(len(data)),
	}
	if err := goarutils.PrepareChunks(tx, data, len(data)); err != nil {
		t.Fatalf("PrepareChunks failed: %v", err)
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
	err := client.verifyAllChunks("test-tx-id", tx, int64(len(data)))
	if err != nil {
		t.Fatalf("verifyAllChunks should succeed: %v", err)
	}
}

func TestVerifyAllChunks_Corruption(t *testing.T) {
	data := make([]byte, ChunkSize*3+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	tx := &goartypes.Transaction{
		Format:   2,
		DataSize: strconv.Itoa(len(data)),
	}
	if err := goarutils.PrepareChunks(tx, data, len(data)); err != nil {
		t.Fatalf("PrepareChunks failed: %v", err)
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
	err := client.verifyAllChunks("test-tx-id", tx, int64(len(data)))
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

	tx := &goartypes.Transaction{
		Format:   2,
		DataSize: strconv.Itoa(len(data)),
	}
	if err := goarutils.PrepareChunks(tx, data, len(data)); err != nil {
		t.Fatalf("PrepareChunks failed: %v", err)
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
	err := client.verifyAllChunks("test-tx-id", tx, int64(len(data)))
	if err == nil {
		t.Fatal("verifyAllChunks MUST return an error for empty response")
	}
	t.Logf("Empty response correctly detected: %v", err)
}

// =============================================================================
// Broken reader tests
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

func TestReadFullAt_Error(t *testing.T) {
	data := make([]byte, ChunkSize*3)
	for i := range data {
		data[i] = byte(i % 256)
	}

	broken := &brokenReaderAt{data: data, failAtByte: ChunkSize}
	_, err := readFullAt(broken, make([]byte, ChunkSize*2), 0)
	if err == nil {
		t.Fatal("expected error from broken reader, got nil")
	}
	t.Logf("Got expected error: %v", err)
}
