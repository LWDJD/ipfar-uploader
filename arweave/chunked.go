// Package arweave — chunked upload support for large data.
//
// This file uses the goar library's Merkle tree and chunk management
// (vendored from github.com/everFinance/goar, Apache 2.0 licensed).
//
// Upload flow:
//   Pass 1:  Prepare chunks (compute Merkle tree) via goar's GenerateChunks
//   Pass 2:  Build, sign (with SHA-384 deep hash), and submit the transaction.
//            The data_root is registered at the gateway when the TX is posted.
//   Pass 3:  Upload each chunk + Merkle proof to /chunk
//   Pass 4:  Wait for confirmation & verify chunks
//
// Reference:
//   - goar/types/merkle.go   — annotated Merkle tree types
//   - goar/utils/merkle.go   — Merkle tree construction & proofs
//   - goar/utils/transaction.go — signing (DeepHash/SHA-384)
package arweave

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	goartypes "github.com/LWDJD/ipfar-uploader/arweave/goar/types"
	goarutils "github.com/LWDJD/ipfar-uploader/arweave/goar/utils"
)

// =============================================================================
// Constants
// =============================================================================

// ChunkSize is the default Arweave data chunk size (256 KiB).
const ChunkSize = goartypes.MAX_CHUNK_SIZE

// noteSize is the size of offset notes in the annotated Merkle tree (32 bytes).
const noteSize = goartypes.NOTE_SIZE

// =============================================================================
// Chunk submission (goar-powered)
// =============================================================================

// submitChunkGoar uploads a single chunk to the gateway using goar's format.
func (gc *GatewayClient) submitChunkGoar(ctx context.Context, gcGoar *goartypes.GetChunk) error {
	body, err := gcGoar.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal chunk request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/chunk", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create chunk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := debugHTTPStart(req.Method, req.URL.String())
	resp, err := gc.client.Do(req)
	if err != nil {
		debugHTTPDone(start, 0, nil, err)
		return fmt.Errorf("failed to upload chunk at offset %s: %w", gcGoar.Offset, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		debugHTTPDone(start, resp.StatusCode, respBody, nil)
		return fmt.Errorf("gateway returned %d for chunk at offset %s: %s",
			resp.StatusCode, gcGoar.Offset, string(respBody))
	}
	debugHTTPDone(start, resp.StatusCode, nil, nil)

	return nil
}

// =============================================================================
// Chunked transaction submission (goar-powered)
// =============================================================================

// signTxGoar signs a goar Transaction using the correct Arweave v2 deep hash
// (SHA-384, matching the Arweave spec). This is critical because our previous
// deepHash used SHA-256 which produced wrong transaction IDs on real gateways.
func signTxGoar(tx *goartypes.Transaction, wallet *Wallet) error {
	err := goarutils.SignTransaction(tx, wallet.PrivateKey)
	if err == nil {
		debugLog("signTxGoar: txID=%s, dataRoot=%s", tx.ID, tx.DataRoot)
	}
	return err
}

// submitChunkedTransactionGoar posts a transaction without data to /tx.
func (gc *GatewayClient) submitChunkedTransactionGoar(ctx context.Context, tx *goartypes.Transaction) (string, error) {
	body, err := marshalTxWithoutData(tx)
	if err != nil {
		return "", fmt.Errorf("failed to marshal chunked tx: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/tx", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := debugHTTPStart(req.Method, req.URL.String())
	resp, err := gc.client.Do(req)
	if err != nil {
		debugHTTPDone(start, 0, nil, err)
		return "", fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	debugHTTPDone(start, resp.StatusCode, respBody, nil)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	return tx.ID, nil
}

// marshalTxWithoutData serializes a chunked-data Transaction.
//
// The "data" field MUST be present (the gateway's json_struct_to_tx expects it)
// but set to "" for chunked transactions where the data is uploaded separately
// via /chunk.  Omitting the key entirely causes "Invalid JSON".
func marshalTxWithoutData(tx *goartypes.Transaction) ([]byte, error) {
	m := map[string]interface{}{
		"format":    tx.Format,
		"id":        tx.ID,
		"last_tx":   tx.LastTx,
		"owner":     tx.Owner,
		"target":    tx.Target,
		"quantity":  tx.Quantity,
		"data":      "", // REQUIRED by gateway — empty string for chunked uploads
		"data_size": tx.DataSize,
		"data_root": tx.DataRoot,
		"reward":    tx.Reward,
		"signature": tx.Signature,
		"tags":      tx.Tags,
	}
	return json.Marshal(m)
}

// =============================================================================
// Chunk upload helpers (goar-powered)
// =============================================================================

// uploadChunksGoar uploads all chunks using goar's GetChunk / GetChunkStream.
// The loop respects context cancellation.
func (gc *GatewayClient) uploadChunksGoar(ctx context.Context, tx *goartypes.Transaction, data []byte, dataReader *os.File) error {
	nChunks := len(tx.Chunks.Chunks)
	for i := 0; i < nChunks; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var gcChunk *goartypes.GetChunk
		var err error

		if dataReader != nil {
			gcChunk, err = goarutils.GetChunkStream(*tx, i, dataReader)
		} else {
			gcChunk, err = goarutils.GetChunk(*tx, i, data)
		}

		if err != nil {
			return fmt.Errorf("failed to get chunk %d: %w", i, err)
		}

		if err := gc.submitChunkGoar(ctx, gcChunk); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// Data verification (same algorithm, goar-powered validation)
// =============================================================================

// verifyAllChunks downloads every chunk and verifies SHA-256 against expected hashes.
// The loop respects context cancellation.
func (gc *GatewayClient) verifyAllChunks(ctx context.Context, txID string, tx *goartypes.Transaction, dataSize int64) error {
	nChunks := len(tx.Chunks.Chunks)
	if nChunks == 0 {
		return nil
	}

	// Reconstruct expected hashes from tx
	expectedHashes := make([][]byte, nChunks)
	for i, ch := range tx.Chunks.Chunks {
		expectedHashes[i] = ch.DataHash
	}

	for i := 0; i < nChunks; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk := tx.Chunks.Chunks[i]
		offset := int64(chunk.MinByteRange)
		fetchLen := chunk.MaxByteRange - chunk.MinByteRange

		req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/raw/"+txID, nil)
		if err != nil {
			return fmt.Errorf("verify chunk %d/%d: failed to create request: %w", i, nChunks, err)
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(fetchLen)-1))

		vStart := debugHTTPStart(req.Method, req.URL.String())
		resp, err := gc.client.Do(req)
		if err != nil {
			debugHTTPDone(vStart, 0, nil, err)
			return fmt.Errorf("verify chunk %d/%d: failed to download: %w", i, nChunks, err)
		}

		downloaded, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(fetchLen)))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("verify chunk %d/%d: failed to read response: %w", i, nChunks, readErr)
		}

		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("verify chunk %d/%d: gateway returned %d", i, nChunks, resp.StatusCode)
		}

		if len(downloaded) == 0 {
			return fmt.Errorf("verify chunk %d/%d: downloaded chunk is empty — data may not be available yet", i, nChunks)
		}

		actualHash := sha256.Sum256(downloaded)
		expectedHash := expectedHashes[i]

		if !bytes.Equal(actualHash[:], expectedHash) {
			return fmt.Errorf(
				"DATA VERIFICATION FAILED: chunk %d/%d hash mismatch.\n"+
					"  Offset: %d\n"+
					"  Expected: %x\n"+
					"  Got:      %x\n"+
					"  The uploaded data may be corrupted. Do not trust this transaction.",
				i, nChunks, offset, expectedHash, actualHash[:],
			)
		}
	}

	fmt.Printf("All %d chunks verified OK\n", nChunks)
	return nil
}

// =============================================================================
// Public API — goar-powered chunked upload
// =============================================================================

// buildGoarTransaction creates a goar Transaction from wallet + data info.
//
// Tag names and values are base64url-encoded here because the goar
// signing path (GetSignatureData → DeepHash → deepHashStr) expects
// base64-encoded strings (it decodes them internally).  Raw strings
// would fail base64 decoding and produce wrong signatures.
//
// IMPORTANT: Because tags are stored base64-encoded on-chain, GraphQL
// dedup queries must search for the base64-encoded form of tag values.
func buildGoarTransaction(owner string, dataSize int64, tags []Tag, reward string, lastTx string) *goartypes.Transaction {
	goarTags := make([]goartypes.Tag, len(tags))
	for i, t := range tags {
		goarTags[i] = goartypes.Tag{
			Name:  base64.RawURLEncoding.EncodeToString([]byte(t.Name)),
			Value: base64.RawURLEncoding.EncodeToString([]byte(t.Value)),
		}
	}

	ownerPrefix := owner
	if len(ownerPrefix) > 20 {
		ownerPrefix = ownerPrefix[:20] + "..."
	}
	debugLog("buildGoarTransaction: owner=%s, dataSize=%d, tags=%d", ownerPrefix, dataSize, len(goarTags))
	return &goartypes.Transaction{
		Format:   2,
		Owner:    owner,
		Target:   "",
		Quantity: "0",
		Data:     "", // no inline data for chunked
		DataSize: strconv.FormatInt(dataSize, 10),
		Reward:   reward,
		LastTx:   lastTx,
		Tags:     goarTags,
	}
}

// UploadDataChunked uploads data to Arweave using the chunked /chunk endpoint.
// It uses goar's Merkle tree, deep hash signing, and chunk management.
func (gc *GatewayClient) UploadDataChunked(ctx context.Context, wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	return gc.uploadDataChunkedInternal(ctx, wallet, data, nil, int64(len(data)), tags)
}

// UploadDataChunkedStreamingFile uploads data from an os.File (streaming).
// Prefer this for large files to avoid loading the entire file into memory.
func (gc *GatewayClient) UploadDataChunkedStreamingFile(ctx context.Context, wallet *Wallet, file *os.File, dataSize int64, tags []Tag) (*Transaction, *TransactionStatus, error) {
	return gc.uploadDataChunkedInternal(ctx, wallet, nil, file, dataSize, tags)
}

// uploadDataChunkedInternal is the common implementation for chunked upload.
// Either data ([]byte) or dataReader (*os.File) must be set.
//
// Transient gateway errors (502, 503, 504) are automatically retried up to
// 3 times with exponential backoff (1s → 2s → 4s).
func (gc *GatewayClient) uploadDataChunkedInternal(
	ctx context.Context,
	wallet *Wallet,
	data []byte,
	dataReader *os.File,
	dataSize int64,
	tags []Tag,
) (*Transaction, *TransactionStatus, error) {
	debugLog("uploadDataChunkedInternal: dataSize=%d, hasStream=%v", dataSize, dataReader != nil)
	var dataInterface interface{}
	if dataReader != nil {
		dataInterface = dataReader
	} else {
		dataInterface = data
	}

	// Step 1 (prepare chunks) and step 2 (sign) are local — do them once.
	goarTags := make([]goartypes.Tag, len(tags))
	for i, t := range tags {
		goarTags[i] = goartypes.Tag{Name: t.Name, Value: t.Value}
	}

	// Fetch anchor & reward
	anchor, err := gc.GetAnchor(ctx)
	if err != nil {
		anchor = ""
	}

	reward, err := gc.GetReward(ctx, dataSize)
	if err != nil {
		reward = "0"
	}

	// Build goar transaction
	tx := buildGoarTransaction(wallet.Owner, dataSize, tags, reward, anchor)

	// Prepare chunks (fills tx.Chunks, tx.DataRoot)
	if err := goarutils.PrepareChunks(tx, dataInterface, int(dataSize)); err != nil {
		return nil, nil, fmt.Errorf("failed to prepare chunks: %w", err)
	}
	nChunks := 0
	if tx.Chunks != nil {
		nChunks = len(tx.Chunks.Chunks)
	}
	debugLog("PrepareChunks: chunks=%d, dataRoot=%s", nChunks, tx.DataRoot)

	// Sign with correct deep hash (SHA-384)
	if err := signTxGoar(tx, wallet); err != nil {
		return nil, nil, fmt.Errorf("failed to sign chunked tx: %w", err)
	}

	// Steps 3–6 are network operations — wrap with retry.
	const maxRetries = 3
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	var txID string
	var status *TransactionStatus

	err = retryWithBackoff(ctx, func() error {
		// ---- 3. submit transaction (registers data_root on gateway) ----
		var sErr error
		txID, sErr = gc.submitChunkedTransactionGoar(ctx, tx)
		if sErr != nil {
			return fmt.Errorf("failed to submit chunked tx: %w", sErr)
		}
		tx.ID = txID

		// ---- 4. upload chunks ----
		if dataSize > 0 {
			if cErr := gc.uploadChunksGoar(ctx, tx, data, dataReader); cErr != nil {
				return fmt.Errorf("chunk upload: %w", cErr)
			}
		}

		// ---- 5. wait for confirmation ----
		var cErr error
		status, cErr = gc.WaitForConfirmation(ctx, txID, 120, 3*time.Second)
		if cErr != nil {
			return fmt.Errorf("submitted but unconfirmed: %w", cErr)
		}

		// ---- 6. verify chunk integrity ----
		if dataSize > 0 {
			if verr := gc.verifyAllChunks(ctx, txID, tx, dataSize); verr != nil {
				return fmt.Errorf("post-upload verification failed: %w", verr)
			}
		}
		return nil
	}, maxRetries, delays)

	if err != nil {
		return convTxGoarToLegacy(tx), status, err
	}

	return convTxGoarToLegacy(tx), status, nil
}

// =============================================================================
// Conversion helpers (goar types ↔ legacy types)
// =============================================================================

// convTxGoarToLegacy converts a goar Transaction to our legacy Transaction type.
func convTxGoarToLegacy(gtx *goartypes.Transaction) *Transaction {
	tags := make([]Tag, len(gtx.Tags))
	for i, t := range gtx.Tags {
		tags[i] = Tag{Name: t.Name, Value: t.Value}
	}

	return &Transaction{
		Format:    gtx.Format,
		ID:        gtx.ID,
		LastTx:    gtx.LastTx,
		Owner:     gtx.Owner,
		Target:    gtx.Target,
		Quantity:  gtx.Quantity,
		Data:      gtx.Data,
		DataSize:  gtx.DataSize,
		DataRoot:  gtx.DataRoot,
		Reward:    gtx.Reward,
		Signature: gtx.Signature,
		Tags:      tags,
	}
}

// =============================================================================
// Legacy compatibility: UploadDataChunkedStreaming with io.ReaderAt
// =============================================================================

// UploadDataChunkedStreaming uploads data via io.ReaderAt (legacy API).
// For new code, prefer UploadDataChunkedStreamingFile with *os.File.
//
// This implementation copies data to a temp file to bridge between io.ReaderAt
// and goar's *os.File API. For very large data, use UploadDataChunkedStreamingFile
// directly with an *os.File to avoid the copy.
func (gc *GatewayClient) UploadDataChunkedStreaming(
	ctx context.Context,
	wallet *Wallet,
	reader io.ReaderAt,
	dataSize int64,
	tags []Tag,
) (*Transaction, *TransactionStatus, error) {
	// For small-to-medium data, just read into memory and use UploadDataChunked
	if dataSize <= 256*1024*1024 { // 256 MiB threshold
		data := make([]byte, dataSize)
		n, err := readFullAt(reader, data, 0)
		if err != nil && err != io.EOF {
			return nil, nil, fmt.Errorf("failed to read data: %w", err)
		}
		if int64(n) < dataSize {
			return nil, nil, fmt.Errorf("short read: got %d bytes, expected %d", n, dataSize)
		}
		return gc.UploadDataChunked(ctx, wallet, data, tags)
	}

	// For very large data, create a temp file and use the streaming API
	tmpFile, err := os.CreateTemp("", "ipfar-upload-*.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copy from reader to temp file in chunks
	buf := make([]byte, goartypes.MAX_CHUNK_SIZE)
	var totalRead int64
	for totalRead < dataSize {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		toRead := int64(len(buf))
		if remaining := dataSize - totalRead; remaining < toRead {
			toRead = remaining
		}
		n, err := readFullAt(reader, buf[:toRead], totalRead)
		if n > 0 {
			if _, werr := tmpFile.Write(buf[:n]); werr != nil {
				return nil, nil, fmt.Errorf("failed to write temp file: %w", werr)
			}
			totalRead += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("failed to read at offset %d: %w", totalRead, err)
		}
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		return nil, nil, fmt.Errorf("failed to seek temp file: %w", err)
	}

	return gc.UploadDataChunkedStreamingFile(ctx, wallet, tmpFile, dataSize, tags)
}

// readFullAt reads exactly len(buf) bytes from r starting at offset.
// Returns the number of bytes read and any error.
func readFullAt(r io.ReaderAt, buf []byte, offset int64) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.ReadAt(buf[total:], offset+int64(total))
		total += n
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

// =============================================================================
// Legacy Merkle tree functions (deprecated, kept for test compatibility)
// =============================================================================

// chunkProof is the legacy proof type, kept for test backward compatibility.
type chunkProof struct {
	Offset int
	Chunk  []byte
	Proof  []byte
}

// computeChunksAndProofs is the legacy Merkle tree function using goar.
// Kept for backward compatibility with existing tests.
func computeChunksAndProofs(data []byte) (dataRoot []byte, results []chunkProof) {
	tx := &goartypes.Transaction{
		Format:   2,
		DataSize: strconv.Itoa(len(data)),
	}

	if err := goarutils.PrepareChunks(tx, data, len(data)); err != nil {
		// Fallback: empty root
		return nil, nil
	}

	dataRoot = tx.Chunks.DataRoot

	if tx.Chunks == nil || len(tx.Chunks.Proofs) == 0 {
		return dataRoot, nil
	}

	results = make([]chunkProof, len(tx.Chunks.Proofs))
	for i, proof := range tx.Chunks.Proofs {
		ch := tx.Chunks.Chunks[i]
		results[i] = chunkProof{
			Offset: ch.MinByteRange,
			Chunk:  data[ch.MinByteRange:ch.MaxByteRange],
			Proof:  proof.Proof,
		}
	}

	return dataRoot, results
}

// chunkLeafHash is the legacy leaf hash function (kept for test helpers).
func chunkLeafHash(dataHash []byte, endOffset uint64) []byte {
	return goarutils.Hash([][]byte{
		goarutils.Hash([][]byte{dataHash}),
		goarutils.Hash([][]byte{intToBuffer(int(endOffset))}),
	})
}

// chunkBranchHash is the legacy branch hash function (kept for test helpers).
func chunkBranchHash(leftID, rightID []byte, leftMax uint64) []byte {
	return goarutils.Hash([][]byte{
		goarutils.Hash([][]byte{leftID}),
		goarutils.Hash([][]byte{rightID}),
		goarutils.Hash([][]byte{intToBuffer(int(leftMax))}),
	})
}

// intToBuffer converts int to 32-byte big-endian buffer.
func intToBuffer(note int) []byte {
	buffer := make([]byte, goartypes.NOTE_SIZE)
	for i := len(buffer) - 1; i >= 0; i-- {
		byt := note % 256
		buffer[i] = byte(byt)
		note = (note - byt) / 256
	}
	return buffer
}

// base64URLEncode is a local helper to avoid import conflicts.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode is a local helper to avoid import conflicts.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
