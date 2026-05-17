// Package uploader — remote CAR verification for dedup safety.
package uploader

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/LWDJD/ipfar-uploader/arweave"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-varint"
)

var carV2Pragma = []byte{0x63, 0x61, 0x72, 0x02} // "car\x02"

// VerifyRemoteCAR downloads key portions of a remote CAR file from Arweave
// and performs a multi-stage validation:
//
//  1. Pragma check (car\x02)
//  2. V2 header sanity (offsets / sizes)
//  3. V1 header parse → extract root CID(s)
//  4. Root-CID match against expectedRootCID
//  5. Index well-formedness (ValidateIndex)
//  6. Index cross-check: spot-verify that index entries point to valid blocks
//
// Only the header, index, and small block headers are downloaded (range
// requests), avoiding a full download of potentially large data.
//
// Returns (true, nil) when the CAR passes every check.
func VerifyRemoteCAR(gateway *arweave.GatewayClient, txID string, expectedRootCID string) (bool, error) {
	// ── 1. Download CAR header (4 B pragma + 48 B v2 header = 52 B) ───────
	headerBytes, err := gateway.DownloadTransactionDataRange(txID, 0, 51)
	if err != nil {
		return false, fmt.Errorf("failed to download CAR header: %w", err)
	}

	// ── 2. Pragma check ────────────────────────────────────────────────────
	if len(headerBytes) < 4 || !bytes.Equal(headerBytes[:4], carV2Pragma) {
		return false, fmt.Errorf("invalid CAR v2 pragma")
	}
	if len(headerBytes) < 52 {
		return false, fmt.Errorf("CAR too short for v2 header: got %d bytes", len(headerBytes))
	}

	// ── 3. Parse v2 header ─────────────────────────────────────────────────
	v2Header := headerBytes[4:52]
	dataOffset := binary.LittleEndian.Uint64(v2Header[16:24])
	dataSize := binary.LittleEndian.Uint64(v2Header[24:32])
	indexOffset := binary.LittleEndian.Uint64(v2Header[32:40])
	indexSize := binary.LittleEndian.Uint64(v2Header[40:48])

	if dataOffset != 52 {
		return false, fmt.Errorf("unexpected data offset: %d (expected 52)", dataOffset)
	}
	if dataSize == 0 {
		return false, fmt.Errorf("data section is empty")
	}
	if indexOffset < dataOffset+dataSize {
		return false, fmt.Errorf("index offset %d overlaps data section (ends at %d)", indexOffset, dataOffset+dataSize)
	}
	if indexSize == 0 {
		return false, fmt.Errorf("index section is empty")
	}

	// ── 4. Download and parse v1 header to extract root CIDs ──────────────
	// v1 header is tiny; 4 KiB is more than enough for any realistic root list.
	v1End := dataOffset + min(dataSize, 4096) - 1
	dataHead, err := gateway.DownloadTransactionDataRange(txID, int64(dataOffset), int64(v1End))
	if err != nil {
		return false, fmt.Errorf("failed to download v1 header region: %w", err)
	}

	rootCIDs, v1HeaderLen, err := parseV1Header(dataHead)
	if err != nil {
		return false, fmt.Errorf("failed to parse v1 header: %w", err)
	}

	// ── 5. Root-CID match ─────────────────────────────────────────────────
	expectedCID, err := cid.Decode(expectedRootCID)
	if err != nil {
		return false, fmt.Errorf("invalid expected root CID %q: %w", expectedRootCID, err)
	}

	found := false
	for _, c := range rootCIDs {
		if c.Equals(expectedCID) {
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("root CID mismatch: expected %s, roots in CAR: %v", expectedRootCID, rootCIDs)
	}

	// ── 6. Download and validate the index ────────────────────────────────
	indexEnd := indexOffset + indexSize - 1
	indexBytes, err := gateway.DownloadTransactionDataRange(txID, int64(indexOffset), int64(indexEnd))
	if err != nil {
		return false, fmt.Errorf("failed to download index: %w", err)
	}

	if err := validateIndex(indexBytes, dataSize); err != nil {
		return false, fmt.Errorf("index validation failed: %w", err)
	}

	// ── 7. Index cross-check (spot-verify block headers) ──────────────────
	if err := validateIndexCrossCheck(indexBytes, gateway, txID, int64(dataOffset), int(v1HeaderLen)); err != nil {
		return false, fmt.Errorf("index cross-check failed: %w", err)
	}

	return true, nil
}

// =============================================================================
// V1 header parser
// =============================================================================

// parseV1Header reads a CAR v1 header from data and returns the root CIDs,
// the number of bytes consumed, and any error.
//
// CAR v1 header layout:
//
//	varint(version)            — must be 1
//	varint(rootCount)
//	for each root:
//	    varint(cidLen) + CID bytes
func parseV1Header(data []byte) ([]cid.Cid, int, error) {
	pos := 0

	version, n, err := varint.FromUvarint(data[pos:])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read v1 version: %w", err)
	}
	pos += n
	if version != 1 {
		return nil, 0, fmt.Errorf("unsupported CAR v1 version: %d", version)
	}

	rootCount, n, err := varint.FromUvarint(data[pos:])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read root count: %w", err)
	}
	pos += n

	roots := make([]cid.Cid, 0, rootCount)
	for i := uint64(0); i < rootCount; i++ {
		cidLen, n, err := varint.FromUvarint(data[pos:])
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read CID length for root %d: %w", i, err)
		}
		pos += n

		if pos+int(cidLen) > len(data) {
			return nil, 0, fmt.Errorf("root CID %d exceeds available data", i)
		}

		c, err := cid.Cast(data[pos : pos+int(cidLen)])
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse root CID %d: %w", i, err)
		}
		pos += int(cidLen)
		roots = append(roots, c)
	}

	return roots, pos, nil
}

// =============================================================================
// Index validators
// =============================================================================

// validateIndex checks that every index entry is well-formed and its offset
// lies within the data section.
//
// Index entry layout:
//
//	varint(entryLen)
//	  varint(cidLen) + CID bytes + varint(offset)
func validateIndex(indexBytes []byte, dataSize uint64) error {
	pos := 0
	entryCount := 0
	for pos < len(indexBytes) {
		entryLen, n, err := varint.FromUvarint(indexBytes[pos:])
		if err != nil {
			return fmt.Errorf("failed to read index entry %d length: %w", entryCount, err)
		}
		pos += n

		entryEnd := pos + int(entryLen)
		if entryEnd > len(indexBytes) {
			return fmt.Errorf("index entry %d exceeds index boundary", entryCount)
		}

		// CID length
		cidLen, n, err := varint.FromUvarint(indexBytes[pos:])
		if err != nil {
			return fmt.Errorf("failed to read CID length in entry %d: %w", entryCount, err)
		}
		pos += n

		if pos+int(cidLen) > entryEnd {
			return fmt.Errorf("CID in entry %d exceeds entry boundary", entryCount)
		}

		if _, err := cid.Cast(indexBytes[pos : pos+int(cidLen)]); err != nil {
			return fmt.Errorf("invalid CID in entry %d: %w", entryCount, err)
		}
		pos += int(cidLen)

		// Offset
		offset, n, err := varint.FromUvarint(indexBytes[pos:])
		if err != nil {
			return fmt.Errorf("failed to read offset in entry %d: %w", entryCount, err)
		}
		pos += n

		if offset >= dataSize {
			return fmt.Errorf("offset %d in entry %d exceeds data size %d", offset, entryCount, dataSize)
		}

		if pos != entryEnd {
			return fmt.Errorf("trailing bytes in index entry %d", entryCount)
		}

		entryCount++
	}

	if entryCount == 0 {
		return fmt.Errorf("empty index")
	}

	return nil
}

// indexEntry holds a parsed index entry for cross-checking.
type indexEntry struct {
	cid    cid.Cid
	offset uint64
}

// parseIndexEntries extracts all entries from the index bytes.
func parseIndexEntries(indexBytes []byte) ([]indexEntry, error) {
	var entries []indexEntry
	pos := 0
	for pos < len(indexBytes) {
		entryLen, n, err := varint.FromUvarint(indexBytes[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		entryEnd := pos + int(entryLen)

		cidLen, n, _ := varint.FromUvarint(indexBytes[pos:])
		pos += n
		c, err := cid.Cast(indexBytes[pos : pos+int(cidLen)])
		if err != nil {
			return nil, err
		}
		pos += int(cidLen)

		offset, n, _ := varint.FromUvarint(indexBytes[pos:])
		pos += n

		entries = append(entries, indexEntry{cid: c, offset: offset})
		pos = entryEnd
	}
	return entries, nil
}

// validateIndexCrossCheck downloads block headers for a subset of index
// entries and verifies that the CID stored in the block matches the entry.
//
// Only the first entry, last entry and one middle entry are checked to avoid
// downloading every block.
func validateIndexCrossCheck(indexBytes []byte, gateway *arweave.GatewayClient, txID string, dataOffset int64, v1HeaderLen int) error {
	entries, err := parseIndexEntries(indexBytes)
	if err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}

	// Choose a representative set of entries
	indices := []int{0}
	if len(entries) > 1 {
		indices = append(indices, len(entries)-1)
	}
	if len(entries) > 2 {
		indices = append(indices, len(entries)/2)
	}

	for _, idx := range indices {
		entry := entries[idx]

		// The index offset is relative to the start of the *data section*
		// (i.e. after pragma + v2 header). The block starts at:
		//   dataOffset + entry.offset
		blockStart := dataOffset + int64(entry.offset)

		// Download a small window: ~256 B is enough for varint(sectionLen) +
		// CID bytes + some data.
		blockData, err := gateway.DownloadTransactionDataRange(txID, blockStart, blockStart+255)
		if err != nil {
			return fmt.Errorf("failed to fetch block at index entry %d (offset %d): %w", idx, entry.offset, err)
		}

		// Parse: varint(sectionLen) | CID bytes | data...
		sectionLen, n, err := varint.FromUvarint(blockData)
		if err != nil {
			return fmt.Errorf("failed to read section length at entry %d: %w", idx, err)
		}

		cidByteLen := entry.cid.ByteLen()
		if n+cidByteLen > len(blockData) {
			return fmt.Errorf("block header too short for CID at entry %d (need %d, have %d)", idx, n+cidByteLen, len(blockData))
		}

		blockCIDBytes := blockData[n : n+cidByteLen]
		if !bytes.Equal(blockCIDBytes, entry.cid.Bytes()) {
			return fmt.Errorf("CID mismatch at index entry %d: index=%s, block=%x", idx, entry.cid.String(), blockCIDBytes)
		}

		_ = sectionLen // silence unused warning — section length derived but not needed beyond bounds
	}

	return nil
}
