// Package arweave — chunked upload support for large data.
//
// Arweave v2 nodes expose POST /chunk for uploading data in 256 KiB chunks,
// bypassing nginx 413 body size limits on POST /tx (typically ~1–2 MiB).
//
// Merkle tree algorithm
// =====================
// This file implements the exact annotated Merkle tree from Erlang's
// ar_merkle.erl (generate_tree / generate_path / validate_path).  The key
// difference from a standard Merkle tree is that every node carries an
// offset "note" that records the cumulative byte range covered by its
// subtree.  This allows the gateway to verify not only that a chunk hash is
// included in the tree but also that the chunk's size and position agree
// with the transaction's data_size.
//
// Leaf:
//   leaf_id = SHA-256( SHA-256(chunk_data) || SHA-256(end_offset_32be) )
//
// Branch (internal node):
//   branch_id = SHA-256( SHA-256(left_id) || SHA-256(right_id) ||
//                        SHA-256(left_max_offset_32be) )
//
// Data path (Merkle proof) binary format, bottom-up:
//   leaf    → [dataHash (32 B)] [endOffset (32 B)]                          = 64 B
//   branch  → [leftChild.id (32 B)] [rightChild.id (32 B)] [note (32 B)] | rest
//                                                                            = 96 B per level
//   total   = 64 + 96 × (tree_height - 1)
//
// Upload order
// ============
// The Arweave gateway requires that the data_root be registered BEFORE any
// chunks are uploaded.  A data_root is registered when:
//   1. A transaction carrying data_root is submitted via POST /tx, OR
//   2. A data_root is synchronised from a mined block via POST /data_roots.
//
// Therefore the two-pass streaming flow is:
//   Pass 1:  compute Merkle tree → data_root
//   Pass 2:  build, sign, submit transaction (registers data_root)
//   Pass 3:  upload chunks with Merkle proofs to /chunk
//   Pass 4:  wait for confirmation & verify chunks
//
// Reference
// =========
//   - apps/arweave/src/ar_merkle.erl   — Merkle tree construction & validation
//   - apps/arweave/src/ar_tx.erl       — chunk splitting & chunk ID generation
//   - apps/arweave/src/ar_poa.erl      — validate_data_path/5
//   - arweave-js lib/merkle.js         — JavaScript reference implementation
package arweave

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// ChunkSize is the default Arweave data chunk size (256 KiB).
const ChunkSize = 256 * 1024

// noteSize is the size of offset notes in the annotated Merkle tree (32 bytes,
// big-endian 256-bit integer as per ar.hrl NOTE_SIZE).
const noteSize = 32

// =============================================================================
// Annotated Merkle tree hash functions (matches ar_merkle.erl)
// =============================================================================

// chunkLeafHash computes the ID of a Merkle leaf node.
//
//	leaf = SHA-256( SHA-256(dataHash) || SHA-256(offsetBigEndian32) )
//
// dataHash is SHA-256 of the raw chunk bytes.  endOffset is the cumulative
// byte count covered by this chunk (i.e. the chunk's end position).
func chunkLeafHash(dataHash []byte, endOffset uint64) []byte {
	hData := sha256.Sum256(dataHash) // double-SHA of chunk

	noteBuf := make([]byte, noteSize)
	binary.BigEndian.PutUint64(noteBuf[noteSize-8:], endOffset)
	hNote := sha256.Sum256(noteBuf)

	h := sha256.New()
	h.Write(hData[:])
	h.Write(hNote[:])
	return h.Sum(nil)
}

// chunkBranchHash computes the ID of a Merkle branch (internal) node.
//
//	branch = SHA-256( SHA-256(leftID) || SHA-256(rightID) ||
//	                  SHA-256(leftMaxBigEndian32) )
//
// leftMax is the maximum end offset covered by the left child's subtree.
func chunkBranchHash(leftID, rightID []byte, leftMax uint64) []byte {
	hLeft := sha256.Sum256(leftID)
	hRight := sha256.Sum256(rightID)

	noteBuf := make([]byte, noteSize)
	binary.BigEndian.PutUint64(noteBuf[noteSize-8:], leftMax)
	hNote := sha256.Sum256(noteBuf)

	h := sha256.New()
	h.Write(hLeft[:])
	h.Write(hRight[:])
	h.Write(hNote[:])
	return h.Sum(nil)
}

// =============================================================================
// Merkle tree types
// =============================================================================

// merkleNode is an internal or leaf node in the chunk Merkle tree.  The
// "max" field stores the maximum end offset in this node's subtree — essential
// for computing branch hashes and building correct data_path proofs.
type merkleNode struct {
	hash []byte // 32-byte node ID
	max  uint64 // maximum cumulative end offset in subtree
}

// =============================================================================
// Streaming Merkle tree (two-pass friendly)
// =============================================================================

// computeMerkleTreeFromReader computes the annotated Merkle tree by streaming
// data from an io.ReaderAt.  Only tree node data (~32 B per node) is kept in
// memory; chunk contents are discarded after hashing.
//
// Returns:
//   - dataRoot:    Merkle root (32 bytes)
//   - nodes:       full Merkle tree node slice (needed to generate proofs)
//   - nChunks:     total number of leaf chunks
//   - leafHashes:  SHA-256 of every leaf chunk (used for post-upload
//                  verification)
func computeMerkleTreeFromReader(r io.ReaderAt, dataSize int64) (
	dataRoot []byte,
	nodes []merkleNode,
	nChunks int,
	leafHashes [][]byte,
	err error,
) {
	if dataSize == 0 {
		// Empty data: root = SHA-256(nil) (same as arweave convention)
		h := sha256.Sum256(nil)
		return h[:], nil, 0, nil, nil
	}

	nChunks = int((dataSize + ChunkSize - 1) / ChunkSize)

	// Pre-allocate enough capacity for the full Merkle tree.
	// Maximum node count: leaves + sum_{k>=1} ceil(leaves/2^k) ≤ 2×leaves + 1.
	nodes = make([]merkleNode, 0, nChunks*2+1)
	leafHashes = make([][]byte, nChunks)

	buf := make([]byte, ChunkSize)

	var cumulative uint64

	for i := 0; i < nChunks; i++ {
		start := int64(i) * ChunkSize
		end := start + ChunkSize
		if end > dataSize {
			end = dataSize
		}
		chunkLen := int(end - start)
		cumulative += uint64(chunkLen)

		n, readErr := readFullAt(r, buf[:chunkLen], start)
		if readErr != nil {
			err = fmt.Errorf("read chunk %d at offset %d: %w", i, start, readErr)
			return
		}
		if n < chunkLen {
			err = fmt.Errorf("short read at chunk %d: got %d bytes, want %d", i, n, chunkLen)
			return
		}

		// Leaf ID = SHA-256( SHA-256(chunk) || SHA-256(end_offset) )
		chunkHash := sha256.Sum256(buf[:chunkLen])
		leafID := chunkLeafHash(chunkHash[:], cumulative)

		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], chunkHash[:])

		nodes = append(nodes, merkleNode{hash: leafID, max: cumulative})
	}

	// ---- 2. build tree bottom-up ----
	dataRoot, nodes = buildMerkleTree(nodes, nChunks)

	return dataRoot, nodes, nChunks, leafHashes, nil
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

// buildMerkleTree builds the internal Merkle tree levels on top of existing
// leaf nodes.  `nodes` must already contain the nChunks leaf nodes at the
// front.  Returns the Merkle root hash and the (possibly reallocated) node
// slice.
//
// The algorithm: bottom-up, pairing adjacent nodes.  Odd nodes are promoted
// (not duplicated).  This matches ar_merkle.erl:generate_row.
func buildMerkleTree(nodes []merkleNode, nChunks int) ([]byte, []merkleNode) {
	if nChunks == 0 {
		h := sha256.Sum256(nil)
		return h[:], nodes
	}

	levelStart := 0
	levelCount := nChunks

	for levelCount > 1 {
		nextLevelStart := len(nodes)
		for i := 0; i < levelCount; i += 2 {
			leftIdx := levelStart + i
			left := nodes[leftIdx]

			if i+1 < levelCount {
				rightIdx := levelStart + i + 1
				right := nodes[rightIdx]

				branchID := chunkBranchHash(left.hash, right.hash, left.max)
				nodes = append(nodes, merkleNode{
					hash: branchID,
					max:  right.max, // right child's max becomes this subtree's max
				})
			} else {
				// Odd node: promote to next level unchanged
				nodes = append(nodes, merkleNode{
					hash: left.hash,
					max:  left.max,
				})
			}
		}
		levelStart = nextLevelStart
		levelCount = (levelCount + 1) / 2
	}

	return nodes[len(nodes)-1].hash, nodes
}

// collectProof builds the Arweave data_path for a single chunk at leafIdx.
//
// Format (from root to leaf):
//
//	branch → [leftChild.id (32 B)] [rightChild.id (32 B)] [note (32 B)] | rest
//	leaf   → [dataHash (32 B)] [endOffset note (32 B)]
//
// Important: when a node is PROMOTED (odd leaf at a level), no branch proof
// segment is emitted for that level — the promoted node's hash is identical
// to its child's, so the proof skips straight from the parent branch to the
// leaf.  This matches ar_merkle.erl:generate_path_parts and the JavaScript
// merkle.js:resolveBranchProofs.
func collectProof(nodes []merkleNode, leafIdx int, nChunks int, leafDataHash []byte) []byte {
	type branchLevel struct {
		leftID  []byte
		rightID []byte
		note    []byte
	}
	var branches []branchLevel

	idx := leafIdx
	levelStart := 0
	levelCount := nChunks

	for levelCount > 1 {
		parentIdx := idx / 2
		parentPos := levelStart + levelCount + parentIdx

		if parentPos >= len(nodes) {
			break
		}

		// Determine whether this parent is a real branch (two children) or
		// a promoted node (odd child promoted, same hash).
		leftChildIdx := levelStart + (parentIdx * 2)
		if leftChildIdx+1 < levelStart+levelCount {
			// Real branch: two children → emit a branch proof segment.
			leftChild := nodes[leftChildIdx]
			rightChild := nodes[leftChildIdx+1]

			noteBuf := make([]byte, noteSize)
			binary.BigEndian.PutUint64(noteBuf[noteSize-8:], leftChild.max)

			branches = append(branches, branchLevel{
				leftID:  leftChild.hash,
				rightID: rightChild.hash,
				note:    noteBuf,
			})
		}
		// else: promoted node → skip (no branch segment for this level)

		idx = parentIdx
		levelStart = levelStart + levelCount
		levelCount = (levelCount + 1) / 2
	}

	// Build the proof binary: branch segments (root-most first) + leaf
	var buf bytes.Buffer
	for i := len(branches) - 1; i >= 0; i-- {
		b := branches[i]
		buf.Write(b.leftID)
		buf.Write(b.rightID)
		buf.Write(b.note)
	}

	// Leaf: dataHash (32) + endOffset note (32)
	buf.Write(leafDataHash)
	noteBuf := make([]byte, noteSize)
	binary.BigEndian.PutUint64(noteBuf[noteSize-8:], nodes[leafIdx].max)
	buf.Write(noteBuf)

	return buf.Bytes()
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
//   - offset is the *last byte index* of the chunk (end_offset - 1), matching
//     the convention used by arweave-js's merkle.js.
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
		return fmt.Errorf("gateway returned %d for chunk at offset %d: %s",
			resp.StatusCode, offset, string(respBody))
	}

	return nil
}

// =============================================================================
// Chunked transaction submission
// =============================================================================

// TransactionWithoutData is a transaction that omits the data field (used
// for chunked uploads where data is uploaded separately via /chunk).
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
// Streaming chunk upload (third pass — tx must be submitted first)
// =============================================================================

// uploadChunksStreaming re-reads data from reader, collects Merkle proofs
// from the pre-computed tree nodes, and uploads each chunk to /chunk.
//
// IMPORTANT: The data_root must already be registered on the gateway
// (by submitting the transaction via POST /tx) before calling this function.
func (gc *GatewayClient) uploadChunksStreaming(
	dataRoot string,
	dataSize int,
	reader io.ReaderAt,
	nodes []merkleNode,
	nChunks int,
	leafHashes [][]byte,
) error {
	buf := make([]byte, ChunkSize)

	var cumulative uint64

	for i := 0; i < nChunks; i++ {
		start := int64(i) * ChunkSize
		end := start + ChunkSize
		if end > int64(dataSize) {
			end = int64(dataSize)
		}
		chunkLen := int(end - start)
		cumulative += uint64(chunkLen)

		n, readErr := readFullAt(reader, buf[:chunkLen], start)
		if readErr != nil {
			return fmt.Errorf("third pass: read chunk %d at offset %d: %w", i, start, readErr)
		}
		if n < chunkLen {
			return fmt.Errorf("third pass: short read at chunk %d: got %d, want %d", i, n, chunkLen)
		}

		proof := collectProof(nodes, i, nChunks, leafHashes[i])
		dataPath := base64.RawURLEncoding.EncodeToString(proof)

		// The offset sent to /chunk is end_offset - 1 (the last byte of the chunk)
		chunkOffset := int(cumulative) - 1

		if err := gc.submitChunk(dataRoot, dataSize, dataPath, chunkOffset, buf[:chunkLen]); err != nil {
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
// /chunk endpoint with multi-pass streaming.
//
// CORRECT ORDER (matches gateway expectations):
//   Pass 1:  compute Merkle tree via io.ReaderAt (only hashes in memory).
//   Pass 2:  fetch anchor & reward, build, sign, submit the transaction.
//            This REGISTERS the data_root on the gateway.
//   Pass 3:  re-read data and upload each chunk + Merkle proof to /chunk.
//            (256 KiB buffer, one chunk at a time).
//   Pass 4:  wait for confirmation & verify all chunks against the gateway.
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

	// ---- 2. fetch anchor & reward ----
	anchor, err := gc.GetAnchor()
	if err != nil {
		anchor = ""
	}

	reward, err := gc.GetReward(dataSize)
	if err != nil {
		reward = "0"
	}

	// ---- 3. build, sign & submit transaction FIRST ----
	// The transaction MUST be submitted before uploading chunks because the
	// gateway's ar_disk_pool:check_admission requires data_root to be
	// registered (either in the disk pool via a submitted tx, or via synced
	// data_roots from a mined block).  Uploading chunks before the tx results
	// in "data_root_not_found".
	tx := buildChunkedTransaction(wallet.Owner, int(dataSize), dataRoot, tags, reward, anchor)
	if err := tx.Sign(wallet.PrivateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to sign chunked tx: %w", err)
	}

	txID, err := gc.submitChunkedTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	tx.ID = txID

	// ---- 4. upload chunks ----
	if err := gc.uploadChunksStreaming(dataRoot, int(dataSize), reader, nodes, nChunks, leafHashes); err != nil {
		return nil, nil, fmt.Errorf("chunk upload: %w", err)
	}

	// ---- 5. wait for confirmation ----
	status, err := gc.WaitForConfirmation(txID, 120, 3*time.Second)
	if err != nil {
		return tx, nil, fmt.Errorf("submitted but unconfirmed: %w", err)
	}

	// ---- 6. verify chunk integrity ----
	if nChunks > 0 && len(leafHashes) > 0 {
		if verr := gc.verifyAllChunks(txID, leafHashes, dataSize); verr != nil {
			// Do NOT silently fail — verification errors must be surfaced.
			return tx, status, fmt.Errorf("post-upload verification failed: %w", verr)
		}
	}

	return tx, status, nil
}

// =============================================================================
// Legacy in-memory Merkle tree (kept for backward compat and tests)
// =============================================================================

// chunkProof holds the Merkle proof for a single chunk.
type chunkProof struct {
	Offset int    // byte offset of this chunk in the original data
	Chunk  []byte // raw chunk bytes (subslice of data)
	Proof  []byte // Arweave data_path (Merkle proof)
}

// computeChunksAndProofs splits data into fixed-size chunks, builds an
// annotated Merkle tree (matching ar_merkle.erl), and returns every chunk
// together with its inclusion proof.
//
// Memory: chunk slices are subslices of data (no copy); the Merkle tree
// temporarily allocates ~2× the number of leaf hashes × 40 bytes each.
func computeChunksAndProofs(data []byte) (dataRoot []byte, results []chunkProof) {
	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	if nChunks == 0 {
		h := sha256.Sum256(nil)
		return h[:], nil
	}

	// ---- 1. leaf hashes ----
	nodes := make([]merkleNode, 0, nChunks*2)
	leafHashes := make([][]byte, nChunks)

	var cumulative uint64
	for i := 0; i < nChunks; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		cumulative += uint64(end - start)

		chunkHash := sha256.Sum256(data[start:end])
		leafID := chunkLeafHash(chunkHash[:], cumulative)

		leafHashes[i] = make([]byte, 32)
		copy(leafHashes[i], chunkHash[:])

		nodes = append(nodes, merkleNode{hash: leafID, max: cumulative})
	}

	// ---- 2. build tree bottom-up ----
	dataRoot, nodes = buildMerkleTree(nodes, nChunks)

	// ---- 3. compute proof for each chunk ----
	results = make([]chunkProof, nChunks)
	cumulative = 0
	for chunkIdx := 0; chunkIdx < nChunks; chunkIdx++ {
		start := chunkIdx * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		cumulative += uint64(end - start)

		proof := collectProof(nodes, chunkIdx, nChunks, leafHashes[chunkIdx])
		results[chunkIdx] = chunkProof{
			Offset: start,
			Chunk:  data[start:end],
			Proof:  proof,
		}
	}

	return dataRoot, results
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
