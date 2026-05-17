// Package arweave 提供 Arweave 钱包管理、交易创建、签名和上传功能。
// 支持标准 Arweave 交易和 ANS-104 Bundle 上传。
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
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Retry helpers
// =============================================================================

// isRetryableHTTPError checks whether an error is a transient gateway error
// (HTTP 502, 503, or 504) that should be retried.
func isRetryableHTTPError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "gateway returned 502") ||
		strings.Contains(s, "gateway returned 503") ||
		strings.Contains(s, "gateway returned 504")
}

// retryWithBackoff executes fn up to maxRetries+1 times if the error is
// retryable. Between retries it sleeps for delays[attempt] and prints a
// message to stderr.
func retryWithBackoff(fn func() error, maxRetries int, delays []time.Duration) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableHTTPError(err) {
			return err
		}
		if attempt < maxRetries {
			delay := delays[attempt]
			fmt.Fprintf(os.Stderr, "Retry %d/%d in %ds...\n", attempt+1, maxRetries, int(delay.Seconds()))
			time.Sleep(delay)
		}
	}
	return lastErr
}

// =============================================================================
// Wallet
// =============================================================================

// JWK represents an Arweave JWK (JSON Web Key) RSA key.
type JWK struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d"`
	P string `json:"p"`
	Q string `json:"q"`
	Dp string `json:"dp"`
	Dq string `json:"dq"`
	Qi string `json:"qi"`
}

// Wallet holds the parsed RSA private key and derived fields.
type Wallet struct {
	PrivateKey *rsa.PrivateKey
	Owner      string // Base64URL of modulus bytes
	Address    string // Base64URL of SHA-256 of modulus bytes
}

// LoadWalletFromFile loads a JWK wallet from a JSON file.
func LoadWalletFromFile(path string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %w", err)
	}
	return LoadWalletFromJSON(data)
}

// LoadWalletFromJSON parses a JWK JSON and returns a Wallet.
func LoadWalletFromJSON(data []byte) (*Wallet, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	return NewWalletFromJWK(&jwk)
}

// NewWalletFromJWK creates a Wallet from JWK fields.
func NewWalletFromJWK(jwk *JWK) (*Wallet, error) {
	n, err := decodeBase64BigInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}
	e, err := decodeBase64BigInt(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}
	d, err := decodeBase64BigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("invalid private exponent: %w", err)
	}

	nBytes := n.Bytes()
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D: d,
	}

	// Parse optional primes
	if jwk.P != "" {
		p, err := decodeBase64BigInt(jwk.P)
		if err == nil {
			privKey.Primes = append(privKey.Primes, p)
		}
	}
	if jwk.Q != "" {
		q, err := decodeBase64BigInt(jwk.Q)
		if err == nil {
			privKey.Primes = append(privKey.Primes, q)
		}
	}

	// Precompute for performance
	privKey.Precompute()

	owner := base64.RawURLEncoding.EncodeToString(nBytes)
	h := sha256.Sum256(nBytes)
	address := base64.RawURLEncoding.EncodeToString(h[:])

	return &Wallet{
		PrivateKey: privKey,
		Owner:      owner,
		Address:    address,
	}, nil
}

func decodeBase64BigInt(s string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

// =============================================================================
// Transaction
// =============================================================================

// Tag represents an Arweave transaction tag.
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Transaction represents an Arweave v2 transaction.
type Transaction struct {
	Format    int    `json:"format"`
	ID        string `json:"id"`
	LastTx    string `json:"last_tx"`
	Owner     string `json:"owner"`
	Target    string `json:"target"`
	Quantity  string `json:"quantity"`
	Data      string `json:"data"`
	DataSize  string `json:"data_size"`
	DataRoot  string `json:"data_root"`
	Reward    string `json:"reward"`
	Signature string `json:"signature"`
	Tags      []Tag  `json:"tags"`
}

// TransactionBuilder constructs transactions incrementally.
type TransactionBuilder struct {
	owner    string
	data     []byte
	tags     []Tag
	target   string
	quantity string
	reward   string
	lastTx   string
}

// NewTransactionBuilder creates a new builder.
func NewTransactionBuilder(owner string) *TransactionBuilder {
	return &TransactionBuilder{
		owner:    owner,
		quantity: "0",
		reward:   "0",
	}
}

func (tb *TransactionBuilder) SetData(data []byte)         { tb.data = data }
func (tb *TransactionBuilder) SetTags(tags []Tag)           { tb.tags = tags }
func (tb *TransactionBuilder) AddTag(name, value string)    { tb.tags = append(tb.tags, Tag{Name: name, Value: value}) }
func (tb *TransactionBuilder) SetTarget(target string)      { tb.target = target }
func (tb *TransactionBuilder) SetReward(reward string)      { tb.reward = reward }
func (tb *TransactionBuilder) SetLastTx(lastTx string)      { tb.lastTx = lastTx }

// Build creates an unsigned Transaction.
func (tb *TransactionBuilder) Build() *Transaction {
	dataRoot := ""
	if len(tb.data) > 0 {
		h := sha256.Sum256(tb.data)
		dataRoot = base64.RawURLEncoding.EncodeToString(h[:])
	}

	tx := &Transaction{
		Format:   2,
		Owner:    tb.owner,
		Target:   tb.target,
		Quantity: tb.quantity,
		Data:     base64.RawURLEncoding.EncodeToString(tb.data),
		DataSize: strconv.Itoa(len(tb.data)),
		DataRoot: dataRoot,
		Reward:   tb.reward,
		LastTx:   tb.lastTx,
		Tags:     tb.tags,
	}
	return tx
}

// Sign signs the transaction using RSA-PSS SHA-256.
func (tx *Transaction) Sign(privKey *rsa.PrivateKey) error {
	sigData := tx.deepHash()
	hashed := sha256.Sum256(sigData)
	sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}
	tx.Signature = base64.RawURLEncoding.EncodeToString(sig)
	tx.ID = base64.RawURLEncoding.EncodeToString(sha256Hash(sig))
	return nil
}

// deepHash computes the Arweave deep hash for transaction signing.
// Spec: https://docs.arweave.org/developers/server/http-api#transaction-signing
func (tx *Transaction) deepHash() []byte {
	// Deep hash list for a v2 transaction:
	// format(2) -> owner -> target -> quantity -> reward -> last_tx -> tags -> data_size -> data_root
	tagsBytes := tx.serializeTags()

	chunks := [][]byte{
		[]byte(fmt.Sprintf("%d", tx.Format)),
		[]byte(tx.Owner),
		[]byte(tx.Target),
		[]byte(tx.Quantity),
		[]byte(tx.Reward),
		[]byte(tx.LastTx),
		tagsBytes,
		[]byte(tx.DataSize),
		[]byte(tx.DataRoot),
	}

	return deepHashChunks(chunks)
}

func (tx *Transaction) serializeTags() []byte {
	var buf bytes.Buffer
	nTags := int64(len(tx.Tags))
	buf.Write(encodeAVROLong(nTags))
	for _, tag := range tx.Tags {
		nameB := []byte(tag.Name)
		valueB := []byte(tag.Value)
		buf.Write(encodeAVROLong(int64(len(nameB))))
		buf.Write(nameB)
		buf.Write(encodeAVROLong(int64(len(valueB))))
		buf.Write(valueB)
	}
	return buf.Bytes()
}

// ToJSON serializes the transaction.
func (tx *Transaction) ToJSON() ([]byte, error) {
	return json.Marshal(tx)
}

// =============================================================================
// Deep Hash
// =============================================================================

// deepHashChunks computes the Arweave deep hash over byte chunks.
// Each chunk is appended to the cumulative SHA-256 hash.
func deepHashChunks(chunks [][]byte) []byte {
	h := sha256.New()
	for _, chunk := range chunks {
		// hash = SHA-256(prev_hash ++ chunk)
		prevHash := h.Sum(nil)
		h.Reset()
		h.Write(prevHash)
		h.Write(chunk)
	}
	return h.Sum(nil)
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// encodeAVROLong encodes an int64 in AVRO zigzag varint format.
func encodeAVROLong(value int64) []byte {
	var zigzag uint64
	if value < 0 {
		zigzag = uint64(^value<<1) | 1
	} else {
		zigzag = uint64(value << 1)
	}
	var result []byte
	for zigzag > 0x7f {
		result = append(result, byte(zigzag&0x7f)|0x80)
		zigzag >>= 7
	}
	result = append(result, byte(zigzag))
	return result
}

// =============================================================================
// Gateway Client
// =============================================================================

// GatewayClient interacts with an Arweave gateway.
type GatewayClient struct {
	GatewayURL string
	client     *http.Client
}

// NewGatewayClient creates a new client.
func NewGatewayClient(gatewayURL string) *GatewayClient {
	return &GatewayClient{
		GatewayURL: strings.TrimRight(gatewayURL, "/"),
		client: &http.Client{
			Timeout: 300 * time.Second,
		},
	}
}

// SetProxy configures an HTTP/SOCKS5 proxy.
func (gc *GatewayClient) SetProxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}
	gc.client.Transport = &http.Transport{
		Proxy: http.ProxyURL(u),
	}
	return nil
}

// SubmitTransaction sends a signed transaction to the gateway.
func (gc *GatewayClient) SubmitTransaction(tx *Transaction) (string, error) {
	body, err := tx.ToJSON()
	if err != nil {
		return "", err
	}

	resp, err := gc.client.Post(
		gc.GatewayURL+"/tx",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("failed to submit tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	return tx.ID, nil
}

// TransactionStatus represents confirmation status.
type TransactionStatus struct {
	Confirmed   bool
	BlockHeight int
	BlockHash   string
}

// GetTransactionStatus checks whether a transaction is confirmed.
func (gc *GatewayClient) GetTransactionStatus(txID string) (*TransactionStatus, error) {
	resp, err := gc.client.Get(gc.GatewayURL + "/tx/" + txID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return &TransactionStatus{Confirmed: false}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return &TransactionStatus{Confirmed: false}, nil
	}

	var result struct {
		BlockHeight           int    `json:"block_height"`
		BlockIndepHash        string `json:"block_indep_hash"`
		NumberOfConfirmations int    `json:"number_of_confirmations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &TransactionStatus{
		Confirmed:   result.BlockHeight > 0,
		BlockHeight: result.BlockHeight,
		BlockHash:   result.BlockIndepHash,
	}, nil
}

// WaitForConfirmation polls until the transaction is confirmed.
func (gc *GatewayClient) WaitForConfirmation(txID string, maxRetries int, interval time.Duration) (*TransactionStatus, error) {
	for i := 0; i < maxRetries; i++ {
		status, err := gc.GetTransactionStatus(txID)
		if err != nil {
			time.Sleep(interval)
			continue
		}
		if status.Confirmed && status.BlockHeight > 0 {
			return status, nil
		}
		time.Sleep(interval)
	}
	return nil, fmt.Errorf("transaction %s not confirmed after %d retries", txID, maxRetries)
}

// GetReward fetches the recommended mining reward for a given data size.
func (gc *GatewayClient) GetReward(dataSize int64) (string, error) {
	u := fmt.Sprintf("%s/price/%d", gc.GatewayURL, dataSize)
	resp, err := gc.client.Get(u)
	if err != nil {
		return "", fmt.Errorf("failed to get price: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// GetAnchor gets a recent transaction anchor.
func (gc *GatewayClient) GetAnchor() (string, error) {
	resp, err := gc.client.Get(gc.GatewayURL + "/tx_anchor")
	if err != nil {
		return "", fmt.Errorf("failed to get anchor: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.Trim(string(body), "\""), nil
}

// UploadData creates, signs, submits and waits for confirmation of a data transaction.
//
// For data >= 256 KiB the function transparently switches to chunked upload
// (POST /chunk) to avoid nginx 413 body-size limits on the gateway.
//
// Transient gateway errors (502, 503, 504) are automatically retried up to
// 3 times with exponential backoff (1s → 2s → 4s).
func (gc *GatewayClient) UploadData(wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	if len(data) >= ChunkSize {
		return gc.UploadDataChunked(wallet, data, tags)
	}

	var tx *Transaction
	var status *TransactionStatus

	const maxRetries = 3
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

	err := retryWithBackoff(func() error {
		anchor, aErr := gc.GetAnchor()
		if aErr != nil {
			anchor = ""
		}

		reward, rErr := gc.GetReward(int64(len(data)))
		if rErr != nil {
			reward = "0"
		}

		tb := NewTransactionBuilder(wallet.Owner)
		tb.SetData(data)
		tb.SetTags(tags)
		tb.SetLastTx(anchor)
		tb.SetReward(reward)

		tx = tb.Build()
		if sErr := tx.Sign(wallet.PrivateKey); sErr != nil {
			return fmt.Errorf("failed to sign: %w", sErr)
		}

		txID, sErr := gc.SubmitTransaction(tx)
		if sErr != nil {
			return fmt.Errorf("failed to submit: %w", sErr)
		}
		tx.ID = txID

		var cErr error
		status, cErr = gc.WaitForConfirmation(txID, 120, 3*time.Second)
		if cErr != nil {
			return fmt.Errorf("submitted but unconfirmed: %w", cErr)
		}
		return nil
	}, maxRetries, delays)

	if err != nil {
		return tx, status, err
	}
	return tx, status, nil
}

// UploadDataRaw submits an already-signed raw transaction bytes (bundle).
func (gc *GatewayClient) UploadDataRaw(data []byte) (string, error) {
	resp, err := gc.client.Post(
		gc.GatewayURL+"/tx",
		"application/octet-stream",
		bytes.NewReader(data),
	)
	if err != nil {
		return "", fmt.Errorf("failed to submit raw data: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse TX ID from response
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err == nil {
		if id, ok := result["id"].(string); ok {
			return id, nil
		}
	}

	return strings.TrimSpace(string(respBody)), nil
}

// =============================================================================
// ANS-104 Bundle Upload
// =============================================================================

// Bundle signature types
const (
	ArweaveSignType = 1
)

// BundleItem represents a single item in an ANS-104 bundle.
type BundleItem struct {
	SignatureType int
	Signature     []byte
	Owner         []byte // 512 bytes for Arweave RSA
	Target        []byte // 32 bytes, optional
	Anchor        []byte // 32 bytes, optional
	Tags          []Tag
	Data          []byte
	ID            []byte // SHA-256 of signature
	HasTarget     bool
	HasAnchor     bool
}

// BundleBuilder builds ANS-104 bundles.
type BundleBuilder struct {
	items []BundleItem
}

// NewBundleBuilder creates a new bundle builder.
func NewBundleBuilder() *BundleBuilder {
	return &BundleBuilder{}
}

// AddItem adds a signed item to the bundle.
func (bb *BundleBuilder) AddItem(item BundleItem) {
	bb.items = append(bb.items, item)
}

// ItemCount returns the number of items.
func (bb *BundleBuilder) ItemCount() int {
	return len(bb.items)
}

// SignItem signs a bundle item with an Arweave RSA key.
func SignBundleItem(data []byte, tags []Tag, wallet *Wallet, anchor []byte) (*BundleItem, error) {
	item := &BundleItem{
		SignatureType: ArweaveSignType,
		Tags:          tags,
		Data:          data,
	}

	if anchor != nil {
		item.Anchor = anchor
		item.HasAnchor = true
	}

	nBytes := wallet.PrivateKey.N.Bytes()
	owner := make([]byte, 512)
	copy(owner[512-len(nBytes):], nBytes)
	item.Owner = owner

	// Compute signature data
	sigData := bundleItemSignData(item)
	hashed := sha256.Sum256(sigData)
	sig, err := rsa.SignPSS(rand.Reader, wallet.PrivateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign bundle item: %w", err)
	}

	sigPadded := make([]byte, 512)
	copy(sigPadded[512-len(sig):], sig)
	item.Signature = sigPadded
	item.ID = sha256Hash(sigPadded)

	return item, nil
}

// Build serializes the bundle to ANS-104 binary format.
func (bb *BundleBuilder) Build() ([]byte, error) {
	if len(bb.items) == 0 {
		return nil, fmt.Errorf("bundle must contain at least one item")
	}

	var header bytes.Buffer
	itemsNum := int64(len(bb.items))

	// Header: 32 bytes for item count
	header.Write(longTo32Bytes(itemsNum))

	// For each item: 32 bytes length + 32 bytes ID
	var itemBinaries [][]byte
	for _, item := range bb.items {
		encoded, err := encodeBundleItem(&item)
		if err != nil {
			return nil, err
		}
		itemBinaries = append(itemBinaries, encoded)
		header.Write(longTo32Bytes(int64(len(encoded))))
		header.Write(item.ID)
	}

	var result bytes.Buffer
	result.Write(header.Bytes())
	for _, ib := range itemBinaries {
		result.Write(ib)
	}

	return result.Bytes(), nil
}

func longTo32Bytes(value int64) []byte {
	buf := make([]byte, 32)
	for i := 0; i < 8; i++ {
		buf[i] = byte(value >> (8 * i))
	}
	return buf
}

func encodeBundleItem(item *BundleItem) ([]byte, error) {
	var buf bytes.Buffer

	// Signature type (2 bytes, LE)
	buf.WriteByte(byte(item.SignatureType))
	buf.WriteByte(byte(item.SignatureType >> 8))

	// Signature (512 bytes for Arweave)
	buf.Write(item.Signature)

	// Owner (512 bytes for Arweave)
	buf.Write(item.Owner)

	// Target present + target
	if item.HasTarget && len(item.Target) > 0 {
		buf.WriteByte(1)
		buf.Write(item.Target)
	} else {
		buf.WriteByte(0)
	}

	// Anchor present + anchor
	if item.HasAnchor && len(item.Anchor) > 0 {
		buf.WriteByte(1)
		buf.Write(item.Anchor)
	} else {
		buf.WriteByte(0)
	}

	// Tags
	tagsBin := serializeTagsAVRO(item.Tags)
	numTags := int64(len(item.Tags))
	buf.Write(longTo32Bytes(numTags))
	buf.Write(longTo32Bytes(int64(len(tagsBin))))
	buf.Write(tagsBin)

	// Data
	buf.Write(item.Data)

	return buf.Bytes(), nil
}

func serializeTagsAVRO(tags []Tag) []byte {
	var buf bytes.Buffer
	for _, tag := range tags {
		nameB := []byte(tag.Name)
		valueB := []byte(tag.Value)
		buf.Write(encodeAVROLong(int64(len(nameB))))
		buf.Write(nameB)
		buf.Write(encodeAVROLong(int64(len(valueB))))
		buf.Write(valueB)
	}
	return buf.Bytes()
}

// bundleItemSignData computes the deep hash for a bundle item signature.
func bundleItemSignData(item *BundleItem) []byte {
	tagsBin := serializeTagsAVRO(item.Tags)

	chunks := [][]byte{
		[]byte("dataitem"),
		[]byte("1"),
		[]byte(strconv.Itoa(item.SignatureType)),
		item.Owner,
		item.Target,
		item.Anchor,
		tagsBin,
		item.Data,
	}

	return deepHashChunks(chunks)
}

// =============================================================================
// GraphQL helpers
// =============================================================================

// QueryExistingCAR queries the Arweave GraphQL endpoint for an existing CAR
// transaction tagged with the given rootCID. Returns the tx ID if found, or
// empty string if none exists.
func (gc *GatewayClient) QueryExistingCAR(rootCID string) (string, error) {
	query := fmt.Sprintf(`{
		transactions(
			tags: [
				{ name: "Root-CID", values: ["%s"] },
				{ name: "Content-Type", values: ["application/vnd.ipld.car"] }
			],
			first: 1
		) {
			edges {
				node { id }
			}
		}
	}`, rootCID)

	graphqlURL := gc.GatewayURL + "/graphql"
	payload := map[string]string{"query": query}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal GraphQL query: %w", err)
	}

	resp, err := gc.client.Post(graphqlURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("GraphQL query failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GraphQL returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gqlResp struct {
		Data struct {
			Transactions struct {
				Edges []struct {
					Node struct {
						ID string `json:"id"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"transactions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return "", fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	if len(gqlResp.Data.Transactions.Edges) > 0 {
		return gqlResp.Data.Transactions.Edges[0].Node.ID, nil
	}
	return "", nil
}

// UploadBundle creates and uploads an ANS-104 bundle transaction.
func (gc *GatewayClient) UploadBundle(wallet *Wallet, items []*BundleItem, tags []Tag) (*Transaction, *TransactionStatus, error) {
	bb := NewBundleBuilder()
	for _, item := range items {
		bb.AddItem(*item)
	}

	bundleBytes, err := bb.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build bundle: %w", err)
	}

	// The bundle itself is uploaded as a data transaction
	return gc.UploadData(wallet, bundleBytes, tags)
}
