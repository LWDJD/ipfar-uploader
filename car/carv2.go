// Package car 提供 CAR v2 文件生成功能
// 将任意文件打包为符合 IPFAR 规范的 CAR v2 格式（带 Index）
package car

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

var carv2Pragma = []byte{0x63, 0x61, 0x72, 0x02} // "car\x02"

// CarV2Builder builds CAR v2 files from raw data blocks.
type CarV2Builder struct {
	blocks []blockEntry
	roots  []cid.Cid
}

type blockEntry struct {
	cid  cid.Cid
	data []byte
}

// NewCarV2Builder creates a new CAR v2 builder.
func NewCarV2Builder() *CarV2Builder {
	return &CarV2Builder{}
}

// AddRawBlock adds a raw data block to the CAR file.
// The data is wrapped in a CID with codec Raw and sha2-256 multihash.
func (b *CarV2Builder) AddRawBlock(data []byte) (cid.Cid, error) {
	c, err := createRawCID(data)
	if err != nil {
		return cid.Undef, err
	}
	b.blocks = append(b.blocks, blockEntry{cid: c, data: data})
	b.roots = append(b.roots, c)
	return c, nil
}

// AddBlock adds an arbitrary CID+data block.
func (b *CarV2Builder) AddBlock(c cid.Cid, data []byte) {
	b.blocks = append(b.blocks, blockEntry{cid: c, data: data})
}

// SetRoot sets the root CID(s) for the CAR file.
// If not set, all added blocks are treated as roots.
func (b *CarV2Builder) SetRoot(roots ...cid.Cid) {
	b.roots = roots
}

// Build writes a complete CAR v2 file (with index) to the writer.
func (b *CarV2Builder) Build(w io.Writer) (int64, error) {
	if len(b.blocks) == 0 {
		return 0, fmt.Errorf("no blocks to build")
	}

	// Pre-build all components
	v1Header, err := b.buildV1Header()
	if err != nil {
		return 0, err
	}

	indexBuilder := NewIndexBuilder()

	// Build data blocks and compute index
	var dataBuf bytes.Buffer
	for _, block := range b.blocks {
		indexBuilder.AddEntry(block.cid, uint64(dataBuf.Len()))
		blockBytes := b.encodeBlock(block.cid, block.data)
		dataBuf.Write(blockBytes)
	}

	indexBytes := indexBuilder.Build()
	// Pad index to 8-byte alignment
	padLen := (8 - (len(indexBytes) % 8)) % 8
	if padLen > 0 {
		indexBytes = append(indexBytes, make([]byte, padLen)...)
	}

	// Compute offsets
	pragmaSize := int64(4)
	v2HeaderSize := int64(48)
	v1HeaderSize := int64(len(v1Header))
	dataOffset := pragmaSize + v2HeaderSize
	dataSize := v1HeaderSize + int64(dataBuf.Len()) // includes v1 header + blocks
	indexOffset := dataOffset + dataSize
	indexSize := len(indexBytes)

	v2Header := b.buildV2Header(
		uint64(dataOffset),
		uint64(dataSize),
		uint64(indexOffset),
		uint64(indexSize),
	)

	// Write everything
	var totalWritten int64
	n, err := w.Write(carv2Pragma)
	totalWritten += int64(n)
	if err != nil {
		return totalWritten, err
	}

	n, err = w.Write(v2Header)
	totalWritten += int64(n)
	if err != nil {
		return totalWritten, err
	}

	n, err = w.Write(v1Header)
	totalWritten += int64(n)
	if err != nil {
		return totalWritten, err
	}

	n, err = w.Write(dataBuf.Bytes())
	totalWritten += int64(n)
	if err != nil {
		return totalWritten, err
	}

	n, err = w.Write(indexBytes)
	totalWritten += int64(n)
	if err != nil {
		return totalWritten, err
	}

	return totalWritten, nil
}

// BuildToFile writes the CAR v2 to a file.
func (b *CarV2Builder) BuildToFile(path string) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return b.Build(f)
}

// BuildToBuffer writes the CAR v2 to an in-memory buffer.
func (b *CarV2Builder) BuildToBuffer() ([]byte, error) {
	var buf bytes.Buffer
	_, err := b.Build(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *CarV2Builder) buildV1Header() ([]byte, error) {
	var buf bytes.Buffer

	// Version = 1
	buf.Write(varint.ToUvarint(1))

	// Root count
	roots := b.roots
	if len(roots) == 0 {
		roots = make([]cid.Cid, 0)
		for _, block := range b.blocks {
			roots = append(roots, block.cid)
		}
	}
	buf.Write(varint.ToUvarint(uint64(len(roots))))

	for _, root := range roots {
		rootBytes := root.Bytes()
		buf.Write(varint.ToUvarint(uint64(len(rootBytes))))
		buf.Write(rootBytes)
	}

	return buf.Bytes(), nil
}

func (b *CarV2Builder) buildV2Header(dataOffset, dataSize, indexOffset, indexSize uint64) []byte {
	hdr := make([]byte, 48)
	// Characteristics (16 bytes, all zeros for now)
	// DataOffset (8 bytes LE)
	binary.LittleEndian.PutUint64(hdr[16:24], dataOffset)
	// DataSize (8 bytes LE)
	binary.LittleEndian.PutUint64(hdr[24:32], dataSize)
	// IndexOffset (8 bytes LE)
	binary.LittleEndian.PutUint64(hdr[32:40], indexOffset)
	// IndexSize (8 bytes LE)
	binary.LittleEndian.PutUint64(hdr[40:48], indexSize)
	return hdr
}

func (b *CarV2Builder) encodeBlock(c cid.Cid, data []byte) []byte {
	var buf bytes.Buffer
	// section = varint(cidLen + dataLen) + CID bytes + data
	sectionLen := uint64(c.ByteLen() + len(data))
	buf.Write(varint.ToUvarint(sectionLen))
	buf.Write(c.Bytes())
	buf.Write(data)
	return buf.Bytes()
}

// createRawCID creates a CID v1 with raw codec (0x55) and sha2-256 multihash.
func createRawCID(data []byte) (cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}

// IndexBuilder builds the CAR v2 index section.
type IndexBuilder struct {
	entries []IndexEntry
}

// IndexEntry is a CID → offset mapping.
type IndexEntry struct {
	CID    cid.Cid
	Offset uint64
}

// NewIndexBuilder creates a new index builder.
func NewIndexBuilder() *IndexBuilder {
	return &IndexBuilder{}
}

// AddEntry adds an index entry.
func (ib *IndexBuilder) AddEntry(c cid.Cid, offset uint64) {
	ib.entries = append(ib.entries, IndexEntry{CID: c, Offset: offset})
}

// Build builds the index byte data.
// Format: each entry = varint(entryLen) + varint(cidLen) + CID bytes + varint(offset)
func (ib *IndexBuilder) Build() []byte {
	var buf bytes.Buffer
	for _, entry := range ib.entries {
		cidBytes := entry.CID.Bytes()
		entryContent := make([]byte, 0)
		entryContent = append(entryContent, varint.ToUvarint(uint64(len(cidBytes)))...)
		entryContent = append(entryContent, cidBytes...)
		entryContent = append(entryContent, varint.ToUvarint(entry.Offset)...)
		buf.Write(varint.ToUvarint(uint64(len(entryContent))))
		buf.Write(entryContent)
	}
	return buf.Bytes()
}

// BuildRaw builds raw index without outer length prefix.
func (ib *IndexBuilder) BuildRaw() []byte {
	var buf bytes.Buffer
	for _, entry := range ib.entries {
		cidBytes := entry.CID.Bytes()
		buf.Write(varint.ToUvarint(uint64(len(cidBytes))))
		buf.Write(cidBytes)
		buf.Write(varint.ToUvarint(entry.Offset))
	}
	return buf.Bytes()
}

// EntryCount returns the number of index entries.
func (ib *IndexBuilder) EntryCount() int {
	return len(ib.entries)
}

// CreateCarV2FromFile creates a CAR v2 file from a raw file.
// Returns the CAR data, root CID, and error.
func CreateCarV2FromFile(inputPath, outputPath string) (cid.Cid, int64, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return cid.Undef, 0, fmt.Errorf("failed to read input file: %w", err)
	}

	builder := NewCarV2Builder()
	rootCID, err := builder.AddRawBlock(data)
	if err != nil {
		return cid.Undef, 0, fmt.Errorf("failed to add block: %w", err)
	}

	written, err := builder.BuildToFile(outputPath)
	if err != nil {
		return cid.Undef, 0, fmt.Errorf("failed to build CAR v2: %w", err)
	}

	return rootCID, written, nil
}

// CreateCarV2FromBytes creates a CAR v2 from in-memory data.
func CreateCarV2FromBytes(data []byte) ([]byte, cid.Cid, error) {
	builder := NewCarV2Builder()
	rootCID, err := builder.AddRawBlock(data)
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("failed to add block: %w", err)
	}

	carBytes, err := builder.BuildToBuffer()
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("failed to build CAR v2: %w", err)
	}

	return carBytes, rootCID, nil
}
