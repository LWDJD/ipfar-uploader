// Package arweave — chunked upload support for large data.
//
// Arweave v2 nodes expose POST /chunk for uploading data in 256 KiB chunks,
// bypassing nginx 413 body size limits on POST /tx (typically ~1–2 MiB).
//
// Flow (two-pass streaming):
//  1. First pass:  stream data via io.ReaderAt, compute SHA-256 leaf hashes
//     and build a Merkle tree → data_root.  Only tree nodes (32 B each) stay
//     in memory.
//  2. Second pass: re-read data via io.ReaderAt, upload each chunk + Merkle
//     proof to /chunk.  Memory: 256 KiB buffer.
//  3. Build & sign tx, POST /tx, confirm.
//  4. Verify all chunks via GET /raw/{txID} (Range requests).
//
// Legacy inline-data path (UploadData) is auto-selected for data < 256 KiB.
package arweave

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// =============================================================================
// Constants
// =============================================================================

// ChunkSize is the default Arweave chunk size (256 KiB).
const ChunkSize = 256 * 1024

// =============================================================================
// Merkle tree types
// =============================================================================

// chunkProof holds the Merkle proof for a single chunk (includes chunk data
// for the legacy all-in-memory path).
type chunkProof struct {
	Offset int    // byte offset of this chunk in the original data
	Chunk  []byte // raw chunk bytes (subslice of data in legacy path)
	Proof  []byte // concatenated sibling hashes from leaf to root
}

// merkleNode is an internal node in the chunk Merkle tree.
type merkleNode struct {
	hash   []byte // 32 bytes
	left   int    // index of left child (-1 if leaf)
	right  int    // index of right child (-1 if leaf or promoted)
}

// =============================================================================
// Legacy in-memory Merkle tree (kept for backward compat and tests)
// =============================================================================

// computeChunksAndProofs splits data into fixed-size chunks, builds a Merkle
// tree, and returns every chunk together with its inclusion proof.
//
// Memory: chunk slices are subslices of data (no copy); the Merkle tree
// temporarily allocates ~2× the number of leaf hashes (32 B each).
func computeChunksAndProofs(data []byte) (dataRoot []byte, results []chunkProof) {
	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	if nChunks == 0 {
		h := sha256.Sum256(nil)
		return h[:], nil
	}

	// ---- 1. leaf hashes ----
	nodes := make([]merkleNode, 0, nChunks*2)

	for i := 0; i < nChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		h := sha256.Sum256(data[start:end])
		nodes = append(nodes, merkleNode{hash: h[:], left: -1, right: -1})
	}

	// ---- 2. build tree bottom-up ----
	levelStart := 0
	levelCount := nChunks
	for levelCount > 1 {
		nextLevelStart := len(nodes)
		for i := 0; i < levelCount; i += 2 {
			leftIdx := levelStart + i
			if i+1 < levelCount {
				rightIdx := levelStart + i + 1
				combined := make([]byte, 64)
				copy(combined[:32], nodes[leftIdx].hash)
				copy(combined[32:], nodes[rightIdx].hash)
				h := sha256.Sum256(combined)
				nodes = append(nodes, merkleNode{
					hash:  h[:],
					left:  leftIdx,
					right: rightIdx,
				})
			} else {
				nodes = append(nodes, merkleNode{
					hash:  nodes[leftIdx].hash,
					left:  leftIdx,
					right: -1,
				})
			}
		}
		levelStart = nextLevelStart
		levelCount = (levelCount + 1) / 2
	}

	rootIdx := len(nodes) - 1
	dataRoot = nodes[rootIdx].hash

	// ---- 3. compute proof for each chunk ----
	results = make([]chunkProof, nChunks)
	for chunkIdx := 0; chunkIdx < nChunks; chunkIdx++ {
		start := chunkIdx * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}

		proof := collectProof(nodes, chunkIdx, nChunks)
		results[chunkIdx] = chunkProof{
			Offset: start,
			Chunk:  data[start:end],
			Proof:  proof,
		}
	}

	return dataRoot, results
}

// =============================================================================
// Streaming Merkle tree (two-pass friendly)
// =============================================================================

// computeMerkleTreeFromReader computes the Merkle tree by streaming data
// from an io.ReaderAt.  Only tree node hashes (32 B per node) are kept in
// memory; chunk data is discarded after hashing.
//
// Returns:
//   - dataRoot:      Merkle root (32 bytes)
//   - nodes:         full Merkle tree node slice (needed to generate proofs)
//   - nChunks:       total number of leaf chunks
//   - leafHashes:    SHA-256 hashes of every leaf (32 B each; used for
//                    post-upload verification)
func computeMerkleTreeFromReader(r io.ReaderAt, dataSize int64) (
	dataRoot []byte,
	nodes []merkleNode,
	nChunks int,
	leafHashes [][]byte,
	err error,
) {
	if dataSize == 0 {
		h := sha256.Sum256(nil)
		return h[:], nil, 0, nil, nil
	}

	nChunks = int((dataSize + ChunkSize - 1) / ChunkSize)

	// ---- 1. read each chunk and compute leaf hashes ----
	buf := make([]byte, ChunkSize)
	leafHashes = make([][]byte, nChunks)
	// Pre-allocate enough capacity for the full Merkle tree.
	// Maximum node count: leaves + sum_{k>=1} ceil(leaves/2^k) ≤ 2*leaves + 1.
	nodes = make([]merkleNode, 0, nChunks*2+1)

	for i := 0; i < nChunks; i++ {
		offset := int64(i) * ChunkSize
		end := offset + ChunkSize
		if end > dataSize {
			end = dataSize
		}
		chunkLen := int(end - offset)

		n, readErr := readFullAt(r, buf[:chunkLen], offset)
		if readErr != nil {
			err = fmt.Errorf("read chunk %d at offset %d: %w", i, offset, readErr)
			return
		}
		if n < chunkLen {
			err = fmt.Errorf("short read at chunk %d: got %d bytes, want %d", i, n, chunkLen)
			return
		}

		h := sha256.Sum256(buf[:chunkLen])
		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], h[:])
		nodes = append(nodes, merkleNode{hash: leafHashes[i], left: -1, right: -1})
	}

	// ---- 2. build tree bottom-up ----
	dataRoot, nodes = buildMerkleTree(nodes, nChunks)

	return dataRoot, nodes, nChunks, leafHashes, nil
}

// buildMerkleTree builds the internal Merkle tree levels on top of existing
// leaf nodes.  `nodes` must already contain the nChunks leaf nodes at the
// front.  Returns the Merkle root hash and the (possibly reallocated) node
// slice.
func buildMerkleTree(nodes []merkleNode, nChunks int) ([]byte, []merkleNode) {
	levelStart := 0
	levelCount := nChunks
	for levelCount > 1 {
		nextLevelStart := len(nodes)
		for i := 0; i < levelCount; i += 2 {
			leftIdx := levelStart + i
			if i+1 < levelCount {
				rightIdx := levelStart + i + 1
				combined := make([]byte, 64)
				copy(combined[:32], nodes[leftIdx].hash)
				copy(combined[32:], nodes[rightIdx].hash)
				h := sha256.Sum256(combined)
				nodes = append(nodes, merkleNode{
					hash:  h[:],
					left:  leftIdx,
					right: rightIdx,
				})
			} else {
				// Odd node → promote
				nodes = append(nodes, merkleNode{
					hash:  nodes[leftIdx].hash,
					left:  leftIdx,
					right: -1,
				})
			}
		}
		levelStart = nextLevelStart
		levelCount = (levelCount + 1) / 2
	}

	return nodes[len(nodes)-1].hash, nodes
}

// readFullAt reads exactly len(buf) bytes from r starting at offset.
// For the last partial chunk where ReadAt returns io.EOF, the bytes
// successfully read are returned with a nil error.
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

// collectProof walks up the Merkle tree from leafIdx and collects sibling
// hashes at each level.  nodes is the full node slice; leafCount is the
// original number of leaves (nChunks).
func collectProof(nodes []merkleNode, leafIdx int, leafCount int) []byte {
	var proof bytes.Buffer

	idx := leafIdx
	levelStart := 0
	levelCount := leafCount
	for levelCount > 1 {
		siblingIdx := idx ^ 1 // flip LSB to get sibling index
		if siblingIdx < levelCount {
			proof.Write(nodes[levelStart+siblingIdx].hash)
		}
		idx = idx / 2
		levelStart = levelStart + levelCount
		levelCount = (levelCount + 1) / 2
	}

	return proof.Bytes()
}

// =============================================================================
// Chunk submission
// =============================================================================

// chunkUploadRequest is the JSON body for POST /chunk.
type chunkUploadRequest struct {
	DataRoot string `json:"data_root"`
	DataSize string `json:"data_size"`
	DataPath string `json:"data_path"`
	Offset   string `json:"offset"`
	Chunk    string `json:"chunk"`
}

// submitChunk uploads a single chunk to the gateway.
func (gc *GatewayClient) submitChunk(dataRoot string, dataSize int, dataPath string, offset int, chunkData []byte) error {
	req := chunkUploadRequest{
		DataRoot: dataRoot,
		DataSize: strconv.Itoa(dataSize),
		DataPath: dataPath,
		Offset:   strconv.Itoa(offset),
		Chunk:    base64.RawURLEncoding.EncodeToString(chunkData),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal chunk request: %w", err)
	}

	resp, err := gc.client.Post(
		gc.GatewayURL+"/chunk",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to upload chunk at offset %d: %w", offset, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway returned %d for chunk at offset %d: %s", resp.StatusCode, offset, string(respBody))
	}

	return nil
}

// =============================================================================
// Chunked transaction submission
// =============================================================================

// TransactionWithoutData is a transaction that omits the data field (used
// for chunked uploads where data was already uploaded via /chunk).
type TransactionWithoutData struct {
	Format    int    `json:"format"`
	ID        string `json:"id"`
	LastTx    string `json:"last_tx"`
	Owner     string `json:"owner"`
	Target    string `json:"target"`
	Quantity  string `json:"quantity"`
	DataSize  string `json:"data_size"`
	DataRoot  string `json:"data_root"`
	Reward    string `json:"reward"`
	Signature string `json:"signature"`
	Tags      []Tag  `json:"tags"`
}

// buildChunkedTransaction constructs an unsigned transaction for chunked data.
func buildChunkedTransaction(owner string, dataSize int, dataRoot string, tags []Tag, reward string, lastTx string) *Transaction {
	tx := &Transaction{
		Format:   2,
		Owner:    owner,
		Target:   "",
		Quantity: "0",
		Data:     "", // no inline data
		DataSize: strconv.Itoa(dataSize),
		DataRoot: dataRoot,
		Reward:   reward,
		LastTx:   lastTx,
		Tags:     tags,
	}
	return tx
}

// submitChunkedTransaction posts a transaction without data to /tx.
func (gc *GatewayClient) submitChunkedTransaction(tx *Transaction) (string, error) {
	txNoData := TransactionWithoutData{
		Format:    tx.Format,
		ID:        tx.ID,
		LastTx:    tx.LastTx,
		Owner:     tx.Owner,
		Target:    tx.Target,
		Quantity:  tx.Quantity,
		DataSize:  tx.DataSize,
		DataRoot:  tx.DataRoot,
		Reward:    tx.Reward,
		Signature: tx.Signature,
		Tags:      tx.Tags,
	}

	body, err := json.Marshal(txNoData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal chunked tx: %w", err)
	}

	resp, err := gc.client.Post(
		gc.GatewayURL+"/tx",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	return tx.ID, nil
}

// =============================================================================
// Streaming chunk upload (second pass)
// =============================================================================

// uploadChunksStreaming re-reads data from reader, collects Merkle proofs
// from the pre-computed tree nodes, and uploads each chunk to /chunk.
func (gc *GatewayClient) uploadChunksStreaming(
	dataRoot string,
	dataSize int,
	reader io.ReaderAt,
	nodes []merkleNode,
	nChunks int,
) error {
	buf := make([]byte, ChunkSize)

	for i := 0; i < nChunks; i++ {
		offset := i * ChunkSize
		end := offset + ChunkSize
		if end > dataSize {
			end = dataSize
		}
		chunkLen := end - offset

		n, readErr := readFullAt(reader, buf[:chunkLen], int64(offset))
		if readErr != nil {
			return fmt.Errorf("second pass: read chunk %d at offset %d: %w", i, offset, readErr)
		}
		if n < chunkLen {
			return fmt.Errorf("second pass: short read at chunk %d: got %d, want %d", i, n, chunkLen)
		}

		proof := collectProof(nodes, i, nChunks)
		dataPath := base64.RawURLEncoding.EncodeToString(proof)

		if err := gc.submitChunk(dataRoot, dataSize, dataPath, offset, buf[:chunkLen]); err != nil {
			return err
		}
	}

	return nil
}

// =============================================================================
// Data verification
// =============================================================================

// verifyAllChunks downloads every chunk from the gateway via Range requests
// and verifies each chunk's SHA-256 against the pre-computed Merkle leaf
// hashes.  This detects corruption in any chunk without downloading the
// entire file — only 256 KiB × N chunks are transferred.
func (gc *GatewayClient) verifyAllChunks(txID string, merkleLeaves [][]byte, dataSize int64) error {
	nChunks := len(merkleLeaves)
	if nChunks == 0 {
		return nil
	}

	for i := 0; i < nChunks; i++ {
		offset := int64(i) * ChunkSize
		fetchLen := ChunkSize
		if offset+int64(ChunkSize) > dataSize {
			fetchLen = int(dataSize - offset)
		}

		req, err := http.NewRequest("GET", gc.GatewayURL+"/raw/"+txID, nil)
		if err != nil {
			return fmt.Errorf("verify chunk %d/%d: failed to create request: %w", i, nChunks, err)
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(fetchLen)-1))

		resp, err := gc.client.Do(req)
		if err != nil {
			return fmt.Errorf("verify chunk %d/%d: failed to download: %w", i, nChunks, err)
		}

		downloaded, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(fetchLen)))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("verify chunk %d/%d: failed to read response: %w", i, nChunks, readErr)
		}

		// Accept 206 Partial Content and 200 OK (some gateways ignore Range)
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("verify chunk %d/%d: gateway returned %d", i, nChunks, resp.StatusCode)
		}

		if len(downloaded) == 0 {
			return fmt.Errorf("verify chunk %d/%d: downloaded chunk is empty — data may not be available yet", i, nChunks)
		}

		actualHash := sha256.Sum256(downloaded)
		expectedHash := merkleLeaves[i]

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

	// All chunks verified successfully.
	fmt.Printf("All %d chunks verified OK\n", nChunks)
	return nil
}

// =============================================================================
// Public API — streaming (primary)
// =============================================================================

// UploadDataChunkedStreaming uploads data to Arweave using the chunked
// /chunk endpoint with two-pass streaming.
//
// Pass 1:  compute Merkle tree via io.ReaderAt (only hashes in memory).
// Pass 2:  re-read and upload each chunk + Merkle proof (256 KiB buffer).
// Pass 3:  build, sign, submit the transaction and wait for confirmation.
// Pass 4:  verify all chunks against the gateway.
//
// The reader must support io.ReaderAt (e.g. *os.File, *bytes.Reader).
func (gc *GatewayClient) UploadDataChunkedStreaming(
	wallet *Wallet,
	reader io.ReaderAt,
	dataSize int64,
	tags []Tag,
) (*Transaction, *TransactionStatus, error) {
	// ---- 1. first pass: compute Merkle tree ----
	dataRootHash, nodes, nChunks, leafHashes, err := computeMerkleTreeFromReader(reader, dataSize)
	if err != nil {
		return nil, nil, fmt.Errorf("first pass (Merkle tree): %w", err)
	}
	dataRoot := base64.RawURLEncoding.EncodeToString(dataRootHash)

	// ---- 2. second pass: upload chunks ----
	if err := gc.uploadChunksStreaming(dataRoot, int(dataSize), reader, nodes, nChunks); err != nil {
		return nil, nil, fmt.Errorf("second pass (chunk upload): %w", err)
	}

	// ---- 3. fetch anchor & reward ----
	anchor, err := gc.GetAnchor()
	if err != nil {
		anchor = ""
	}

	reward, err := gc.GetReward(dataSize)
	if err != nil {
		reward = "0"
	}

	// ---- 4. build & sign transaction ----
	tx := buildChunkedTransaction(wallet.Owner, int(dataSize), dataRoot, tags, reward, anchor)
	if err := tx.Sign(wallet.PrivateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to sign chunked tx: %w", err)
	}

	// ---- 5. submit transaction ----
	txID, err := gc.submitChunkedTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	tx.ID = txID

	// ---- 6. wait for confirmation ----
	status, err := gc.WaitForConfirmation(txID, 120, 3*time.Second)
	if err != nil {
		return tx, nil, fmt.Errorf("submitted but unconfirmed: %w", err)
	}

	// ---- 7. verify first chunk integrity ----
	if nChunks > 0 && len(leafHashes) > 0 {
		if verr := gc.verifyAllChunks(txID, leafHashes, dataSize); verr != nil {
			// Do NOT silently fail — verification errors must be surfaced.
			return tx, status, fmt.Errorf("post-upload verification failed: %w", verr)
		}
	}

	return tx, status, nil
}

// =============================================================================
// Public API — backward compatible (all-in-memory)
// =============================================================================

// UploadDataChunked uploads data to Arweave using the chunked /chunk endpoint.
// It always uses the chunked flow regardless of data size.  For datasets
// smaller than 256 KiB, UploadData (which auto-detects size) is more efficient.
//
// This is a convenience wrapper around UploadDataChunkedStreaming that accepts
// a []byte.  For large data, prefer UploadDataChunkedStreaming with an
// io.ReaderAt to avoid keeping the full payload in memory.
func (gc *GatewayClient) UploadDataChunked(wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	return gc.UploadDataChunkedStreaming(wallet, bytes.NewReader(data), int64(len(data)), tags)
}
