// Package arweave — chunked upload support for large data.
//
// Arweave v2 nodes expose POST /chunk for uploading data in 256 KiB chunks,
// bypassing nginx 413 body size limits on POST /tx (typically ~1–2 MiB).
//
// Flow:
//  1. Split data into chunks and compute a Merkle tree → data_root.
//  2. POST each chunk to /chunk with its Merkle proof.
//  3. POST the transaction to /tx with data_root / data_size but no data field.
//  4. Confirm as usual.
//
// For data < 256 KiB the classic single-POST /tx path is used transparently.
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
// Merkle tree utilities
// =============================================================================

// chunkProof holds the Merkle proof for a single chunk.
type chunkProof struct {
	Offset int    // byte offset of this chunk in the original data
	Chunk  []byte // raw chunk bytes
	Proof  []byte // concatenated sibling hashes from leaf to root
}

// merkleNode is an internal node in the chunk Merkle tree.
type merkleNode struct {
	hash   []byte // 32 bytes
	left   int    // index of left child (-1 if leaf)
	right  int    // index of right child (-1 if leaf or promoted)
}

// computeChunksAndProofs splits data into fixed-size chunks, builds a Merkle
// tree, and returns every chunk together with its inclusion proof.
//
// Memory: chunk slices are subslices of data (no copy); the Merkle tree
// temporarily allocates ~2× the number of leaf hashes (32 B each).
func computeChunksAndProofs(data []byte) (dataRoot []byte, results []chunkProof) {
	nChunks := (len(data) + ChunkSize - 1) / ChunkSize
	if nChunks == 0 {
		// Empty data → SHA-256 of empty byte slice as root.
		h := sha256.Sum256(nil)
		return h[:], nil
	}

	// ---- 1. leaf hashes ----
	nodes := make([]merkleNode, 0, nChunks*2) // pre-allocate for the whole tree

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
				// Two children → hash(left || right)
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
					right: -1, // promoted, no right sibling
				})
			}
		}
		levelStart = nextLevelStart
		levelCount = (levelCount + 1) / 2
	}

	// Root is the last node
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
			// Sibling exists → append its hash
			proof.Write(nodes[levelStart+siblingIdx].hash)
		}
		// Move to parent level
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
	// Serialise *without* the data field.
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
// Public API
// =============================================================================

// UploadDataChunked uploads data to Arweave using the chunked /chunk endpoint.
// It always uses the chunked flow regardless of data size.  For datasets
// smaller than 256 KiB, UploadData (which auto-detects size) is more efficient.
func (gc *GatewayClient) UploadDataChunked(wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	dataSize := len(data)

	// ---- 1. compute Merkle tree ----
	dataRootHash, chunkProofs := computeChunksAndProofs(data)
	dataRoot := base64.RawURLEncoding.EncodeToString(dataRootHash)

	// ---- 2. upload every chunk ----
	for _, cp := range chunkProofs {
		dataPath := base64.RawURLEncoding.EncodeToString(cp.Proof)
		if err := gc.submitChunk(dataRoot, dataSize, dataPath, cp.Offset, cp.Chunk); err != nil {
			return nil, nil, err
		}
	}

	// ---- 3. fetch anchor & reward ----
	anchor, err := gc.GetAnchor()
	if err != nil {
		anchor = ""
	}

	reward, err := gc.GetReward(int64(dataSize))
	if err != nil {
		reward = "0"
	}

	// ---- 4. build & sign transaction ----
	tx := buildChunkedTransaction(wallet.Owner, dataSize, dataRoot, tags, reward, anchor)
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

	return tx, status, nil
}
