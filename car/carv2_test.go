package car

import (
	"bytes"
	"os"
	"testing"

	"github.com/ipfs/go-cid"
)

func TestCreateCarV2FromBytes(t *testing.T) {
	data := []byte("Hello, IPFAR!")
	carBytes, rootCID, err := CreateCarV2FromBytes(data)
	if err != nil {
		t.Fatalf("CreateCarV2FromBytes failed: %v", err)
	}

	if len(carBytes) == 0 {
		t.Fatal("empty CAR bytes")
	}

	// Check CAR v2 pragma
	if !bytes.HasPrefix(carBytes, carv2Pragma) {
		t.Fatal("missing CAR v2 pragma")
	}

	// Check root CID is valid
	if rootCID == cid.Undef {
		t.Fatal("root CID is undefined")
	}

	if rootCID.Prefix().Codec != cid.Raw {
		t.Errorf("expected Raw codec, got %d", rootCID.Prefix().Codec)
	}

	t.Logf("Root CID: %s", rootCID.String())
	t.Logf("CAR size: %d bytes", len(carBytes))
}

func TestCarV2Builder_SingleBlock(t *testing.T) {
	data := []byte("test data for CAR v2")
	builder := NewCarV2Builder()

	rootCID, err := builder.AddRawBlock(data)
	if err != nil {
		t.Fatalf("AddRawBlock failed: %v", err)
	}

	if rootCID == cid.Undef {
		t.Fatal("root CID is undefined")
	}

	carBytes, err := builder.BuildToBuffer()
	if err != nil {
		t.Fatalf("BuildToBuffer failed: %v", err)
	}

	if len(carBytes) < 100 {
		t.Errorf("CAR too small: %d bytes", len(carBytes))
	}

	// Verify pragma
	if !bytes.HasPrefix(carBytes, carv2Pragma) {
		t.Fatal("missing pragma")
	}

	t.Logf("Root CID: %s, CAR size: %d", rootCID.String(), len(carBytes))
}

func TestCarV2Builder_MultipleBlocks(t *testing.T) {
	builder := NewCarV2Builder()

	data1 := []byte("block one data")
	data2 := []byte("block two data")

	cid1, err := builder.AddRawBlock(data1)
	if err != nil {
		t.Fatalf("AddRawBlock 1 failed: %v", err)
	}
	cid2, err := builder.AddRawBlock(data2)
	if err != nil {
		t.Fatalf("AddRawBlock 2 failed: %v", err)
	}

	builder.SetRoot(cid1) // only cid1 as root

	carBytes, err := builder.BuildToBuffer()
	if err != nil {
		t.Fatalf("BuildToBuffer failed: %v", err)
	}

	if cid1 == cid2 {
		t.Fatal("CIDs should differ for different data")
	}

	t.Logf("CID1: %s, CID2: %s, CAR size: %d", cid1.String(), cid2.String(), len(carBytes))
}

func TestCarV2Builder_FileOutput(t *testing.T) {
	data := []byte("file output test data")
	builder := NewCarV2Builder()
	rootCID, err := builder.AddRawBlock(data)
	if err != nil {
		t.Fatalf("AddRawBlock failed: %v", err)
	}

	tmpFile := t.TempDir() + "/test.car"
	written, err := builder.BuildToFile(tmpFile)
	if err != nil {
		t.Fatalf("BuildToFile failed: %v", err)
	}

	if written <= 0 {
		t.Fatal("zero bytes written")
	}

	// Check file exists and has content
	stat, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if stat.Size() != written {
		t.Errorf("size mismatch: written=%d, stat=%d", written, stat.Size())
	}

	// Read back and verify pragma
	fileData, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if !bytes.HasPrefix(fileData, carv2Pragma) {
		t.Fatal("file missing CAR v2 pragma")
	}

	t.Logf("Root CID: %s, CAR file size: %d", rootCID.String(), written)
}

func TestIndexBuilder(t *testing.T) {
	ib := NewIndexBuilder()

	// Create a test CID
	data := []byte("index test data")
	c, _ := createRawCID(data)

	ib.AddEntry(c, 128)
	ib.AddEntry(c, 256)

	if ib.EntryCount() != 2 {
		t.Errorf("expected 2 entries, got %d", ib.EntryCount())
	}

	indexBytes := ib.Build()
	if len(indexBytes) == 0 {
		t.Fatal("empty index")
	}

	rawBytes := ib.BuildRaw()
	if len(rawBytes) == 0 {
		t.Fatal("empty raw index")
	}

	t.Logf("Index (prefixed): %d bytes, Raw: %d bytes", len(indexBytes), len(rawBytes))
}

func TestCreateRawCID(t *testing.T) {
	data := []byte("deterministic CID test")
	c1, err := createRawCID(data)
	if err != nil {
		t.Fatalf("createRawCID failed: %v", err)
	}

	// Same data should produce same CID
	c2, err := createRawCID(data)
	if err != nil {
		t.Fatalf("createRawCID failed: %v", err)
	}

	if c1.String() != c2.String() {
		t.Errorf("CIDs differ for same data: %s vs %s", c1.String(), c2.String())
	}

	// Different data should produce different CID
	c3, err := createRawCID([]byte("different data"))
	if err != nil {
		t.Fatalf("createRawCID failed: %v", err)
	}

	if c1.String() == c3.String() {
		t.Error("CIDs should differ for different data")
	}

	t.Logf("CID: %s", c1.String())
}

func TestCreateCarV2FromFile(t *testing.T) {
	// Create a temporary input file
	tmpDir := t.TempDir()
	inputFile := tmpDir + "/input.txt"
	outputFile := tmpDir + "/output.car"

	testData := []byte("test file for CAR v2 creation")
	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		t.Fatalf("write input failed: %v", err)
	}

	rootCID, written, err := CreateCarV2FromFile(inputFile, outputFile)
	if err != nil {
		t.Fatalf("CreateCarV2FromFile failed: %v", err)
	}

	if written <= 0 {
		t.Fatal("zero bytes written")
	}

	if rootCID == cid.Undef {
		t.Fatal("root CID is undefined")
	}

	// Verify output
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read output failed: %v", err)
	}

	if !bytes.HasPrefix(outputData, carv2Pragma) {
		t.Fatal("output missing CAR v2 pragma")
	}

	t.Logf("Root CID: %s, Output size: %d", rootCID.String(), written)
}
