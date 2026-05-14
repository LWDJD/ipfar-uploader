// Package metadata 提供 IPFAR 元数据 JSON 的解析、验证与构建功能
// 规范参考: ipfar-specs/V1/数据结构规范.md §2
package metadata

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	Version1 = 1

	MethodRaw    = "raw"
	MethodBundle = "bundle"

	PoWThreshold = 100 * 1024 * 1024
)

var (
	ErrInvalidJSON        = errors.New("invalid metadata JSON")
	ErrMissingField       = errors.New("missing required field")
	ErrInvalidVersion     = errors.New("invalid version: must be 1")
	ErrInvalidMethod      = errors.New("invalid method: must be 'raw' or 'bundle'")
	ErrInvalidRootCID     = errors.New("invalid root_cid: must be a non-empty Base32 CID string")
	ErrInvalidDataTXID    = errors.New("invalid data_txid: must be a non-empty Arweave transaction ID")
	ErrInvalidDataHeight  = errors.New("invalid data_height: must be a non-negative integer")
	ErrInvalidDataSize    = errors.New("invalid data_size: must be a positive integer")
	ErrMissingPoW         = errors.New("missing pow: required for files smaller than 100 MiB")
	ErrMissingPowAlg      = errors.New("missing pow_alg: required for files smaller than 100 MiB")
	ErrInvalidReference   = errors.New("invalid reference format")
)

type ReferenceEntry struct {
	Height int      `json:"height"`
	CIDs   []string `json:"cids"`
}

type ReferenceMap map[string]ReferenceEntry

type Metadata struct {
	Version      int           `json:"version"`
	Method       string        `json:"method"`
	RootCID      string        `json:"root_cid"`
	DataTXID     string        `json:"data_txid"`
	DataHeight   int           `json:"data_height"`
	DataSize     int           `json:"data_size"`
	Reference    *ReferenceMap `json:"reference,omitempty"`
	ContentType  string        `json:"content_type,omitempty"`
	OriginalName string        `json:"original_name,omitempty"`
	PoW          string        `json:"pow,omitempty"`
	PoWAlg       string        `json:"pow_alg,omitempty"`
}

func ParseJSON(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrInvalidJSON)
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	return &meta, nil
}

func ParseFromBase64URL(encoded string) (*Metadata, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty Base64URL string", ErrInvalidJSON)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode Base64URL: %v", ErrInvalidJSON, err)
		}
	}
	return ParseJSON(decoded)
}

func (m *Metadata) Validate() error {
	if m.Version == 0 {
		return fmt.Errorf("%w: version", ErrMissingField)
	}
	if m.Version != Version1 {
		return fmt.Errorf("%w: got %d", ErrInvalidVersion, m.Version)
	}
	if m.Method == "" {
		return fmt.Errorf("%w: method", ErrMissingField)
	}
	if m.Method != MethodRaw && m.Method != MethodBundle {
		return fmt.Errorf("%w: got %q", ErrInvalidMethod, m.Method)
	}
	if m.RootCID == "" {
		return fmt.Errorf("%w: root_cid", ErrMissingField)
	}
	if m.DataTXID == "" {
		return fmt.Errorf("%w: data_txid", ErrMissingField)
	}
	if m.DataHeight < 0 {
		return fmt.Errorf("%w: got %d", ErrInvalidDataHeight, m.DataHeight)
	}
	if m.DataSize <= 0 {
		return fmt.Errorf("%w: got %d", ErrInvalidDataSize, m.DataSize)
	}
	if m.Reference != nil {
		if err := validateReference(m.Reference); err != nil {
			return err
		}
	}
	if int64(m.DataSize) < PoWThreshold {
		if m.PoW == "" {
			return ErrMissingPoW
		}
		if m.PoWAlg == "" {
			return ErrMissingPowAlg
		}
	}
	return nil
}

func (m *Metadata) NeedsPoW() bool {
	return int64(m.DataSize) < PoWThreshold
}

func (m *Metadata) HasReference() bool {
	return m.Reference != nil && len(*m.Reference) > 0
}

func (m *Metadata) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

func (m *Metadata) ToBase64URL() (string, error) {
	jsonBytes, err := m.ToJSON()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(jsonBytes), nil
}

func validateReference(ref *ReferenceMap) error {
	if ref == nil || len(*ref) == 0 {
		return nil
	}
	for txid, entry := range *ref {
		if txid == "" {
			return fmt.Errorf("%w: empty transaction ID key", ErrInvalidReference)
		}
		if entry.Height < 0 {
			return fmt.Errorf("%w: negative height %d for txid %q", ErrInvalidReference, entry.Height, txid)
		}
		if len(entry.CIDs) == 0 {
			return fmt.Errorf("%w: empty cids list for txid %q", ErrInvalidReference, txid)
		}
		for i, cid := range entry.CIDs {
			if cid == "" {
				return fmt.Errorf("%w: empty cid at index %d for txid %q", ErrInvalidReference, i, txid)
			}
		}
	}
	return nil
}

// Tag 表示 Arweave Transaction Tag 键值对
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TagSlice []Tag

func (ts TagSlice) ToMap() map[string]string {
	m := make(map[string]string)
	for _, t := range ts {
		m[t.Name] = t.Value
	}
	return m
}

func BuildMetaTags(rootCID, dataTXID string) []Tag {
	return []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "IPFAR-Type", Value: "meta"},
		{Name: "Root-CID", Value: rootCID},
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Data-TXID", Value: dataTXID},
	}
}

func BuildCARTags(rootCID string, dataSize int64) []Tag {
	return []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Root-CID", Value: rootCID},
		{Name: "Data-Size", Value: fmt.Sprintf("%d", dataSize)},
		{Name: "Content-Type", Value: "application/vnd.ipld.car"},
	}
}

func CleanCID(cid string) string {
	return strings.Trim(strings.TrimSpace(cid), "\"")
}

// ValidateTags 验证 Arweave Transaction Tags 是否符合 IPFAR 规范
func ValidateTags(tags []Tag) error {
	if len(tags) == 0 {
		return errors.New("tags must not be empty")
	}
	tagMap := make(map[string]string)
	for _, tag := range tags {
		tagMap[tag.Name] = tag.Value
	}
	protocol, ok := tagMap["Protocol"]
	if !ok || protocol == "" {
		return fmt.Errorf("%w: Protocol", ErrMissingField)
	}
	if protocol != "IPFS-Arweave-Bridge" {
		return fmt.Errorf("invalid Protocol tag: expected 'IPFS-Arweave-Bridge', got %q", protocol)
	}
	protocolVersion, ok := tagMap["Protocol-Version"]
	if !ok || protocolVersion == "" {
		return fmt.Errorf("%w: Protocol-Version", ErrMissingField)
	}
	if protocolVersion != "1" {
		return fmt.Errorf("invalid Protocol-Version tag: expected '1', got %q", protocolVersion)
	}
	return nil
}
