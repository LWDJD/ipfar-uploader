package arweave

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadWalletFromJSON(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

	jwk := JWK{N: n, E: e, D: d}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}

	wallet, err := LoadWalletFromJSON(jwkJSON)
	if err != nil {
		t.Fatalf("LoadWalletFromJSON failed: %v", err)
	}

	if wallet.Owner == "" {
		t.Fatal("empty owner")
	}
	if wallet.Address == "" {
		t.Fatal("empty address")
	}

	t.Logf("Wallet address: %s", wallet.Address)
}

func TestTransactionSignAndVerify(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("hello world"))
	tb.AddTag("Test", "Value")
	tb.SetReward("100")

	tx := tb.Build()
	if err := tx.Sign(privKey); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if tx.Signature == "" {
		t.Fatal("empty signature")
	}
	if tx.ID == "" {
		t.Fatal("empty ID")
	}

	// Verify round-trip JSON
	jsonBytes, err := tx.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var tx2 Transaction
	if err := json.Unmarshal(jsonBytes, &tx2); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if tx2.ID != tx.ID {
		t.Errorf("ID mismatch: %s vs %s", tx2.ID, tx.ID)
	}

	t.Logf("TX ID: %s", tx.ID)
}

func TestDeepHash(t *testing.T) {
	tb := NewTransactionBuilder("owner123")
	tb.SetData([]byte("test data"))
	tb.AddTag("Name", "Value")

	tx := tb.Build()
	dh1 := tx.deepHash()
	dh2 := tx.deepHash()

	if len(dh1) == 0 {
		t.Fatal("empty deep hash")
	}
	if string(dh1) != string(dh2) {
		t.Fatal("deepHash not deterministic")
	}

	t.Logf("DeepHash: %x", dh1)
}

func TestBundleBuilder_Build(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	item, err := SignBundleItem([]byte("bundle test data"), []Tag{}, wallet, nil)
	if err != nil {
		t.Fatalf("SignBundleItem failed: %v", err)
	}

	if item.SignatureType != ArweaveSignType {
		t.Errorf("expected ArweaveSignType, got %d", item.SignatureType)
	}
	if len(item.Signature) != 512 {
		t.Errorf("expected 512-byte signature, got %d", len(item.Signature))
	}
	if len(item.ID) != 32 {
		t.Errorf("expected 32-byte ID, got %d", len(item.ID))
	}

	t.Logf("Bundle item ID: %x", item.ID)
}

func TestBundleBuilder_MultipleItems(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	bb := NewBundleBuilder()
	item1, err := SignBundleItem([]byte("item 1"), []Tag{{Name: "T1", Value: "V1"}}, wallet, nil)
	if err != nil {
		t.Fatalf("SignBundleItem 1 failed: %v", err)
	}
	bb.AddItem(*item1)

	item2, err := SignBundleItem([]byte("item 2"), []Tag{{Name: "T2", Value: "V2"}}, wallet, nil)
	if err != nil {
		t.Fatalf("SignBundleItem 2 failed: %v", err)
	}
	bb.AddItem(*item2)

	if bb.ItemCount() != 2 {
		t.Errorf("expected 2 items, got %d", bb.ItemCount())
	}

	bundleBytes, err := bb.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if len(bundleBytes) < 200 {
		t.Errorf("bundle too small: %d bytes", len(bundleBytes))
	}

	t.Logf("Bundle size: %d bytes for 2 items", len(bundleBytes))
}

func TestGatewayClient_Mock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For any /tx/<id> request (except POST), return a confirmed status
		if r.URL.Path == "/tx" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"mock-tx-id-12345"}`))
			return
		}
		if r.URL.Path == "/price/0" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1000"))
			return
		}
		if r.URL.Path == "/tx_anchor" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor-tx-id"`))
			return
		}
		// Generic /tx/<id> - return confirmed
		if len(r.URL.Path) > 4 && r.URL.Path[:4] == "/tx/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":1913000,"block_indep_hash":"mock-hash"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	reward, err := client.GetReward(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetReward failed: %v", err)
	}
	t.Logf("Reward: %s", reward)

	anchor, err := client.GetAnchor(context.Background())
	if err != nil {
		t.Fatalf("GetAnchor failed: %v", err)
	}
	t.Logf("Anchor: %s", anchor)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("test"))
	tx := tb.Build()
	tx.Sign(privKey)

	txID, err := client.SubmitTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SubmitTransaction failed: %v", err)
	}
	t.Logf("Submitted TX ID: %s", txID)

	status, err := client.GetTransactionStatus(context.Background(), txID)
	if err != nil {
		t.Fatalf("GetTransactionStatus failed: %v", err)
	}
	if !status.Confirmed {
		t.Error("transaction should be confirmed")
	}
	if status.BlockHeight != 1913000 {
		t.Errorf("unexpected block height: %d", status.BlockHeight)
	}
}

func TestWaitForConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx/test-tx" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":100}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	status, err := client.WaitForConfirmation(context.Background(), "test-tx", 5, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForConfirmation failed: %v", err)
	}
	if status.BlockHeight != 100 {
		t.Errorf("expected block 100, got %d", status.BlockHeight)
	}
}

func TestEncodeAVROLong(t *testing.T) {
	tests := []struct {
		value  int64
		length int
	}{
		{0, 1},
		{1, 1},
		{-1, 1},
		{64, 2},
		{16384, 3},
	}

	for _, tt := range tests {
		result := encodeAVROLong(tt.value)
		if len(result) != tt.length {
			t.Errorf("encodeAVROLong(%d): expected length %d, got %d (bytes: %v)", tt.value, tt.length, len(result), result)
		}
	}
}

func TestDeepHashChunks(t *testing.T) {
	c1 := deepHashChunks([][]byte{[]byte("a"), []byte("b")})
	c2 := deepHashChunks([][]byte{[]byte("a"), []byte("b")})

	if string(c1) != string(c2) {
		t.Fatal("deepHashChunks not deterministic")
	}

	c3 := deepHashChunks([][]byte{[]byte("b"), []byte("a")})
	if string(c1) == string(c3) {
		t.Fatal("different order should produce different hash")
	}

	t.Logf("deepHash: %x", c1)
}
