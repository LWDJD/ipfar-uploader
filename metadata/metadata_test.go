package metadata

import (
	"testing"
)

func TestMetadata_ToJSONAndBack(t *testing.T) {
	meta := &Metadata{
		Version:      Version1,
		Method:       MethodRaw,
		RootCID:      "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID:     "test-tx-id-1234567890123456789012345678901234567890123",
		DataHeight:   1913000,
		DataSize:     12345678,
		ContentType:  "image/png",
		OriginalName: "myfile.png",
		PoW:          "12345",
		PoWAlg:       "argon2id-light-v1",
	}

	jsonBytes, err := meta.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	parsed, err := ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if parsed.RootCID != meta.RootCID {
		t.Errorf("RootCID mismatch: %s vs %s", parsed.RootCID, meta.RootCID)
	}
	if parsed.DataTXID != meta.DataTXID {
		t.Errorf("DataTXID mismatch")
	}
	if parsed.DataSize != meta.DataSize {
		t.Errorf("DataSize mismatch: %d vs %d", parsed.DataSize, meta.DataSize)
	}
	if parsed.ContentType != meta.ContentType {
		t.Errorf("ContentType mismatch")
	}
	if parsed.PoW != meta.PoW {
		t.Errorf("PoW mismatch: %s vs %s", parsed.PoW, meta.PoW)
	}
}

func TestMetadata_Base64URL(t *testing.T) {
	meta := &Metadata{
		Version:     Version1,
		Method:      MethodRaw,
		RootCID:     "bafytest123",
		DataTXID:    "txid123",
		DataHeight:  100,
		DataSize:    500,
	}

	b64, err := meta.ToBase64URL()
	if err != nil {
		t.Fatalf("ToBase64URL failed: %v", err)
	}

	if b64 == "" {
		t.Fatal("empty base64")
	}

	parsed, err := ParseFromBase64URL(b64)
	if err != nil {
		t.Fatalf("ParseFromBase64URL failed: %v", err)
	}

	if parsed.RootCID != meta.RootCID {
		t.Errorf("RootCID mismatch after base64 roundtrip")
	}
}

func TestMetadata_Validate(t *testing.T) {
	tests := []struct {
		name    string
		meta    *Metadata
		wantErr bool
	}{
		{
			name: "valid with PoW",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodRaw,
				RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
				DataTXID:   "test-tx-id-1234567890123456789012345678901234567890123",
				DataHeight: 100,
				DataSize:   1024,
				PoW:        "12345",
				PoWAlg:     "argon2id-light-v1",
			},
			wantErr: false,
		},
		{
			name: "valid large file no PoW",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodRaw,
				RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
				DataTXID:   "test-tx-id-1234567890123456789012345678901234567890123",
				DataHeight: 100,
				DataSize:   200 * 1024 * 1024, // 200 MiB
			},
			wantErr: false,
		},
		{
			name: "missing version",
			meta: &Metadata{
				Method:   MethodRaw,
				RootCID:  "bafytest",
				DataTXID: "txid",
				DataSize: 1024,
				PoW:      "0",
				PoWAlg:   "argon2id-light-v1",
			},
			wantErr: true,
		},
		{
			name: "small file missing PoW",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodRaw,
				RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
				DataTXID:   "test-tx-id-1234567890123456789012345678901234567890123",
				DataHeight: 100,
				DataSize:   1024,
			},
			wantErr: true,
		},
		{
			name: "invalid method",
			meta: &Metadata{
				Version:    Version1,
				Method:     "invalid",
				RootCID:    "bafytest",
				DataTXID:   "txid123",
				DataHeight: 100,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: true,
		},
		{
			name: "bundle method valid (height >= 0)",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodBundle,
				RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
				DataTXID:   "test-tx-id-1234567890123456789012345678901234567890123",
				BundleTXID: "actual-bundle-tx-id",
				DataHeight: 100,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: false,
		},
		{
			name: "bundle method valid (height = -1, same bundle)",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodBundle,
				RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
				DataTXID:   "test-tx-id-1234567890123456789012345678901234567890123",
				BundleTXID: "none",
				DataHeight: -1,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: false,
		},
		{
			name: "bundle method invalid: data_height=-1 but bundle_txid not none",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodBundle,
				RootCID:    "bafytest",
				DataTXID:   "txid123",
				BundleTXID: "some-other-txid",
				DataHeight: -1,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: true,
		},
		{
			name: "bundle method invalid: missing bundle_txid",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodBundle,
				RootCID:    "bafytest",
				DataTXID:   "txid123",
				DataHeight: 100,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: true,
		},
		{
			name: "raw method invalid: data_height = -1",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodRaw,
				RootCID:    "bafytest",
				DataTXID:   "txid123",
				DataHeight: -1,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: true,
		},
		{
			name: "raw method invalid: bundle_txid set",
			meta: &Metadata{
				Version:    Version1,
				Method:     MethodRaw,
				RootCID:    "bafytest",
				DataTXID:   "txid123",
				BundleTXID: "something",
				DataHeight: 100,
				DataSize:   200 * 1024 * 1024,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.meta.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNeedsPoW(t *testing.T) {
	meta := &Metadata{DataSize: 1024}
	if !meta.NeedsPoW() {
		t.Error("small file should need PoW")
	}

	meta.DataSize = 200 * 1024 * 1024
	if meta.NeedsPoW() {
		t.Error("large file should not need PoW")
	}
}

func TestBuildCARTags(t *testing.T) {
	tags := BuildCARTags("bafytest123", 12345)

	if len(tags) == 0 {
		t.Fatal("no tags generated")
	}

	tagMap := TagSlice(tags).ToMap()

	if tagMap["Protocol"] != "IPFS-Arweave-Bridge" {
		t.Errorf("wrong Protocol: %s", tagMap["Protocol"])
	}
	if tagMap["Protocol-Version"] != "1" {
		t.Errorf("wrong Protocol-Version")
	}
	if tagMap["Root-CID"] != "bafytest123" {
		t.Errorf("wrong Root-CID")
	}
	if tagMap["Content-Type"] != "application/vnd.ipld.car" {
		t.Errorf("wrong Content-Type: %s", tagMap["Content-Type"])
	}
	if tagMap["Data-Size"] != "12345" {
		t.Errorf("wrong Data-Size: %s", tagMap["Data-Size"])
	}
}

func TestBuildMetaTags(t *testing.T) {
	tags := BuildMetaTags("bafytest123", "txid123")

	tagMap := TagSlice(tags).ToMap()

	if tagMap["Protocol"] != "IPFS-Arweave-Bridge" {
		t.Errorf("wrong Protocol")
	}
	if tagMap["IPFAR-Type"] != "meta" {
		t.Errorf("wrong IPFAR-Type: %s", tagMap["IPFAR-Type"])
	}
	if tagMap["Content-Type"] != "application/json" {
		t.Errorf("wrong Content-Type")
	}
	if tagMap["Root-CID"] != "bafytest123" {
		t.Errorf("wrong Root-CID")
	}
	if tagMap["Data-TXID"] != "txid123" {
		t.Errorf("wrong Data-TXID: %s", tagMap["Data-TXID"])
	}
}

func TestValidateTags(t *testing.T) {
	tags := BuildMetaTags("bafytest", "txid123")
	if err := ValidateTags(tags); err != nil {
		t.Errorf("valid tags should pass: %v", err)
	}

	// Missing Protocol
	badTags := []Tag{
		{Name: "Protocol-Version", Value: "1"},
	}
	if err := ValidateTags(badTags); err == nil {
		t.Error("missing Protocol should fail")
	}
}

func TestReference(t *testing.T) {
	ref := &ReferenceMap{
		"txid-1": {Height: 100, CIDs: []string{"bafy1", "bafy2"}},
		"txid-2": {Height: 200, CIDs: []string{"bafy3"}},
	}

	err := validateReference(ref)
	if err != nil {
		t.Errorf("valid reference should pass: %v", err)
	}

	// Height = -1 (same bundle reference) should be valid
	refNeg := &ReferenceMap{
		"txid-1": {Height: -1, CIDs: []string{"bafy1"}},
	}
	err = validateReference(refNeg)
	if err != nil {
		t.Errorf("reference with height=-1 should pass: %v", err)
	}

	// Empty CID list
	badRef := &ReferenceMap{
		"txid-1": {Height: 100, CIDs: []string{}},
	}
	err = validateReference(badRef)
	if err == nil {
		t.Error("empty CID list should fail")
	}
}
