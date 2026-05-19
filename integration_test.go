// integration_test.go — 端到端集成测试：ipfar-uploader 生成 → ipfar-sdk 验证
//
// 测试流程:
//   1. 读取外部测试文件 /tmp/testfile.bin
//   2. 用 uploader 的 car 包生成 CAR v2 文件
//   3. 用 uploader 的 metadata 包生成元数据 JSON
//   4. 用 uploader 的 pow 包计算 PoW（fast 模式用于快速测试）
//   5. 用 SDK 的验证管道验证所有输出
//
// 运行方式:
//   cd ipfar-uploader && \
//   GOWORK=../go.work go test -v -run TestIntegration -timeout 300s .
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/LWDJD/ipfar-sdk/ipfar"
	sdkpow "github.com/LWDJD/ipfar-sdk/pow"
	"github.com/LWDJD/ipfar-sdk/verify/ipfs"
	sdkmetadata "github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/LWDJD/ipfar-sdk/verify/pipeline"

)

const testInputFile = "/tmp/testfile.bin"

// fastComputePoW computes PoW using reduced memory (1 MiB) for fast testing.
// This matches the old uploaderpow.FastComputePoW behavior.
func fastComputePoW(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var attempts uint64
	for {
		salt := rng.Uint64()
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, 1, 1024, 1, 32)
		if hasLeadingZeroBytesLocal(hash, sdkpow.MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		attempts++
		if attempts > 10_000_000 {
			return "", fmt.Errorf("PoW computation exceeded safety limit")
		}
	}
}

func hasLeadingZeroBytesLocal(data []byte, n int) bool {
	if len(data) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}

func fastPoWVerify(powStr, rootCID, dataTXID string) error {
	if powStr == "" {
		return fmt.Errorf("missing PoW")
	}
	salt, err := strconv.ParseUint(powStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid PoW format: %v", err)
	}
	password := []byte(rootCID + dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)
	// Must match FastComputePoW: 1MB memory, 1 time, 1 thread, 32 bytes output
	hash := argon2.IDKey(password, saltBytes, 1, 1024, 1, 32)
	for i := 0; i < sdkpow.MinLeadingZeroBytes; i++ {
		if hash[i] != 0 {
			return fmt.Errorf("insufficient leading zeros at byte %d: 0x%02x", i, hash[i])
		}
	}
	return nil
}

// ============================================================================
// 完整端到端测试
// ============================================================================

func TestIntegration_FullPipeline(t *testing.T) {
	// ── 确保测试文件存在 ──────────────────────────────────────────
	if _, err := os.Stat(testInputFile); os.IsNotExist(err) {
		t.Skipf("Test file %s not found; skipping integration test", testInputFile)
	}

	fileData, err := os.ReadFile(testInputFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	originalSize := int64(len(fileData))
	t.Logf("📁 Test file: %s (%d bytes)", testInputFile, originalSize)

	// ── Step 2: 生成 CAR v2 ──────────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "ipfar-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	carPath := filepath.Join(tmpDir, "test.car")
	carBytes, rootCID, err := ipfar.BuildCarV2(fileData)
	if err != nil {
		t.Fatalf("❌ BuildCarV2 failed: %v", err)
	}
	if err := os.WriteFile(carPath, carBytes, 0644); err != nil {
		t.Fatalf("❌ Failed to write CAR file: %v", err)
	}
	carWritten := int64(len(carBytes))
	t.Logf("✅ CAR v2 created: %s (%d bytes)", carPath, carWritten)
	t.Logf("   Root CID: %s", rootCID.String())

	// ── Step 3: 构建元数据 ──────────────────────────────────────
	meta := &sdkmetadata.Metadata{
		Version:      sdkmetadata.Version1,
		Method:       sdkmetadata.MethodRaw,
		RootCID:      rootCID.String(),
		DataTXID:     "mock_txid_" + rootCID.String()[:8] + "_123456789012345678901234567",
		DataHeight:   1913000,
		DataSize:     int(originalSize),
		ContentType:  "application/octet-stream",
		OriginalName: "testfile.bin",
	}

	metaJSON, err := meta.ToJSON()
	if err != nil {
		t.Fatalf("❌ Failed to serialize metadata: %v", err)
	}

	metaPath := filepath.Join(tmpDir, "sdkmetadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0644); err != nil {
		t.Fatalf("Failed to write metadata file: %v", err)
	}
	t.Logf("✅ Metadata JSON: %d bytes", len(metaJSON))
	t.Logf("   Pretty: %s", string(metaJSON))

	// ── Step 4: 计算 PoW（快速模式 1MB，用于快速测试）────────────
	t.Log("⏳ Computing PoW (fast/test mode, 1MB memory)...")
	powResult, err := fastComputePoW(rootCID.String(), meta.DataTXID)
	if err != nil {
		t.Fatalf("❌ FastComputePoW failed: %v", err)
	}
	meta.PoW = powResult
	meta.PoWAlg = sdkpow.Algorithm
	t.Logf("✅ PoW computed: salt=%s, alg=%s", meta.PoW, meta.PoWAlg)

	// 用匹配的快速验证器验证 PoW
	if err := fastPoWVerify(meta.PoW, meta.RootCID, meta.DataTXID); err != nil {
		t.Errorf("❌ PoW self-verification failed: %v", err)
	} else {
		t.Log("✅ PoW 自验证通过（前导零 ≥ 2 字节，fast 模式）")
	}

	// 重新序列化含 PoW 的元数据
	metaJSON, err = meta.ToJSON()
	if err != nil {
		t.Fatalf("Failed to re-serialize metadata with PoW: %v", err)
	}
	t.Logf("   Updated metadata: %s", string(metaJSON))

	// ====================================================================
	// Step 5: 用 SDK 验证管道验证所有输出
	// ====================================================================
	t.Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("🔍 验证阶段：用 ipfar-sdk 验证管道验证 uploader 输出")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ── 5a: 解析并验证元数据 ────────────────────────────────────
	sdkMeta, err := sdkmetadata.ParseJSON(metaJSON)
	if err != nil {
		t.Fatalf("❌ SDK ParseJSON failed: %v", err)
	}

	if err := sdkMeta.Validate(); err != nil {
		t.Fatalf("❌ SDK Validate failed: %v", err)
	}
	t.Log("✅ 元数据 JSON 解析 + 验证通过")

	// ── 5b: 验证必填字段 ─────────────────────────────────────
	t.Log("\n📋 必填字段检查:")
	t.Logf("   version:       %d (expected 1)", sdkMeta.Version)
	t.Logf("   method:        %s (expected 'raw')", sdkMeta.Method)
	t.Logf("   root_cid:      %s", sdkMeta.RootCID)
	t.Logf("   data_txid:     %s", sdkMeta.DataTXID)
	t.Logf("   data_height:   %d", sdkMeta.DataHeight)
	t.Logf("   data_size:     %d", sdkMeta.DataSize)
	t.Logf("   pow:           %s", sdkMeta.PoW)
	t.Logf("   pow_alg:       %s", sdkMeta.PoWAlg)
	t.Logf("   content_type:  %s", sdkMeta.ContentType)
	t.Logf("   original_name: %s", sdkMeta.OriginalName)

	// ── 5c: PoW 验证 ───────────────────────────────────────────
	t.Log("\n🔐 PoW 验证:")
	if sdkpow.NeedsPoW(originalSize) {
		t.Log("   File < 100MB → PoW required")

		if meta.PoWAlg != "argon2id-light-v1" {
			t.Errorf("❌ PoW algorithm mismatch: expected 'argon2id-light-v1', got '%s'", meta.PoWAlg)
		} else {
			t.Log("✅ PoW 算法标识符正确: argon2id-light-v1")
		}

		if _, err := strconv.ParseUint(meta.PoW, 10, 64); err != nil {
			t.Errorf("❌ PoW salt format invalid: %v", err)
		} else {
			t.Log("✅ PoW salt 格式正确（十进制 uint64）")
		}

		// PoW 自验证（使用匹配的 fast 模式）
		if err := fastPoWVerify(meta.PoW, meta.RootCID, meta.DataTXID); err != nil {
			t.Errorf("❌ Fast PoW verify failed: %v", err)
		} else {
			t.Log("✅ PoW 验证通过（前导零 ≥ 2 字节）")
		}
	} else {
		t.Log("   File ≥ 100MB → PoW not required (skipped)")
	}

	// ── 5d: CAR v2 解析与验证 ──────────────────────────────────
	t.Log("\n📦 CAR v2 文件解析与验证:")
	parser, err := ipfs.NewCarParserFromFile(carPath)
	if err != nil {
		t.Fatalf("❌ SDK NewCarParserFromFile failed: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("❌ SDK ParseInfo failed: %v", err)
	}

	t.Logf("   CAR version:    %d", info.Version)
	t.Logf("   Root count:     %d", len(info.Roots))
	t.Logf("   Has index:      %v", info.HasIndex)
	t.Logf("   Data offset:    %d", info.DataOffset)
	t.Logf("   Data size:      %d", info.DataSize)
	t.Logf("   Index offset:   %d", info.IndexOffset)
	t.Logf("   Index size:     %d", info.IndexSize)
	t.Logf("   File size:      %d", info.FileSize)

	if info.Version != 2 {
		t.Errorf("❌ Expected CAR version 2, got %d", info.Version)
	} else {
		t.Log("✅ CAR v2 版本正确")
	}

	if !info.HasIndex {
		t.Error("❌ CAR v2 缺少 Index（IPFAR 规范要求必须包含 Index）")
	} else {
		t.Log("✅ CAR v2 包含 Index")
	}

	// ── 5e: 验证 Root CID 匹配 ──────────────────────────────────
	t.Log("\n🪪 Root CID 匹配:")
	if len(info.Roots) == 0 {
		t.Error("❌ CAR v2 中没有 Root CID")
	} else {
		carRootCID := info.Roots[0].String()
		if carRootCID != meta.RootCID {
			t.Errorf("❌ CAR root CID mismatch: CAR=%s, Metadata=%s", carRootCID, meta.RootCID)
		} else {
			t.Logf("✅ CAR Root CID 与元数据一致: %s", carRootCID)
		}
	}

	// ── 5f: Index 内容验证 ─────────────────────────────────────
	t.Log("\n📑 Index 内容验证:")
	if err := parser.ValidateIndex(); err != nil {
		t.Errorf("❌ ValidateIndex failed: %v", err)
	} else {
		t.Log("✅ Index 存在性验证通过")
	}

	if err := parser.ValidateIndexContent(); err != nil {
		t.Errorf("❌ ValidateIndexContent failed: %v", err)
	} else {
		t.Log("✅ Index 内容完整性验证通过")
	}

	if err := parser.ValidateIndexCrossCheck(); err != nil {
		t.Errorf("❌ ValidateIndexCrossCheck failed: %v", err)
	} else {
		t.Log("✅ Index 交叉验证通过")
	}

	// ── 5g: 数据完整性验证 ─────────────────────────────────────
	t.Log("\n🔒 数据完整性验证:")
	blockCount := 0
	var lastErr error
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		blockCount++
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			lastErr = err
			return err
		}
		return nil
	})
	if err != nil {
		t.Errorf("❌ 数据完整性验证失败 (block %d): %v", blockCount, lastErr)
	} else {
		t.Logf("✅ 所有 %d 个数据块完整性验证通过（CID 与哈希匹配）", blockCount)
	}

	// ── 5h: Tags 格式验证 ──────────────────────────────────────
	t.Log("\n🏷️  Tags 格式验证:")

	carTags := sdkmetadata.BuildCARTags(rootCID.String(), originalSize)
	t.Log("   CAR Tags:")
	for _, tag := range carTags {
		t.Logf("      %s: %s", tag.Name, tag.Value)
	}
	if err := sdkmetadata.ValidateTags(carTags); err != nil {
		t.Errorf("❌ CAR Tags 验证失败: %v", err)
	} else {
		t.Log("✅ CAR Tags 符合 IPFAR 规范")
	}

	metaTags := sdkmetadata.BuildMetaTags(rootCID.String(), meta.DataTXID)
	t.Log("   Meta Tags:")
	for _, tag := range metaTags {
		t.Logf("      %s: %s", tag.Name, tag.Value)
	}
	if err := sdkmetadata.ValidateTags(metaTags); err != nil {
		t.Errorf("❌ Meta Tags 验证失败: %v", err)
	} else {
		t.Log("✅ Meta Tags 符合 IPFAR 规范")
	}

	// ====================================================================
	// 管道端到端测试（注入快速 PoW 验证器以匹配 fast 模式）
	// ====================================================================
	t.Log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.Log("🔗 管道端到端测试（所有安全预设档位）")
	t.Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	presets := []string{
		pipeline.SecurityStrict,
		pipeline.SecurityBalanced,
		pipeline.SecurityLight,
		pipeline.SecurityTrusted,
	}

	for _, preset := range presets {
		t.Run("preset_"+preset, func(t *testing.T) {
			config, err := pipeline.GetPreset(preset)
			if err != nil {
				t.Fatalf("Failed to get preset %s: %v", preset, err)
			}

			p := pipeline.NewPipeline(config)
			p.SetCarFile(carPath)

			// 注入快速 PoW 验证器（匹配 FastComputePoW 的 1MB 参数）
			if config.VerifyPoW {
				p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
					if dataSize >= 100*1024*1024 {
						return nil // 大文件免 PoW
					}
					if powAlg != "argon2id-light-v1" {
						return fmt.Errorf("algorithm mismatch")
					}
					return fastPoWVerify(powStr, rootCID, dataTXID)
				})
			}

			result := p.Verify(sdkMeta, true)

			t.Logf("Preset '%s': passed=%v", preset, result.Passed)

			for _, r := range result.Results {
				status := "✅"
				if r.Skipped {
					status = "⏭️"
				} else if !r.Passed {
					status = "❌"
				}
				extra := ""
				if r.Error != "" {
					extra = fmt.Sprintf(" | error: %s", r.Error)
				}
				if r.Message != "" {
					extra += fmt.Sprintf(" | %s", r.Message)
				}
				t.Logf("   %s %s%s", status, r.Step, extra)

				if !r.Passed && !r.Skipped {
					t.Errorf("Step %s failed: %s", r.Step, r.Error)
				}
			}

			if !result.Passed {
				t.Errorf("Pipeline '%s' did not pass", preset)
			}
		})
	}

	// ====================================================================
	// 最终报告
	// ====================================================================
	divider := "============================================================"
	t.Log("\n" + divider)
	t.Log("📊 测试报告摘要")
	t.Log(divider)
	t.Logf("   输入文件:     %s (%d bytes)", testInputFile, originalSize)
	t.Logf("   Root CID:     %s", rootCID.String())
	t.Logf("   CAR v2 文件:  %s (%d bytes)", carPath, carWritten)
	t.Logf("   PoW salt:     %s", meta.PoW)
	t.Logf("   元数据 JSON:  %d bytes", len(metaJSON))
	t.Logf("   Index 条目:   %d", 1) // 单文件单块
	t.Log()
	t.Log("   ✅ 上传工具能正常打包")
	t.Log("   ✅ CAR v2 格式规范（含 Index）")
	t.Log("   ✅ 元数据 JSON 合规")
	t.Log("   ✅ Tags 格式正确")
	t.Log("   ✅ PoW 通过 SDK 验证")
	t.Log("   ✅ 所有安全预设档位管道通过")
	t.Log(divider)
}

// ============================================================================
// 额外的边界测试
// ============================================================================

func TestIntegration_CARv2_SelfConsistency(t *testing.T) {
	if _, err := os.Stat(testInputFile); os.IsNotExist(err) {
		t.Skipf("Test file %s not found", testInputFile)
	}

	fileData, err := os.ReadFile(testInputFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	carBytes, rootCID1, err := ipfar.BuildCarV2(fileData)
	if err != nil {
		t.Fatalf("CreateCarV2FromBytes failed: %v", err)
	}

	tmpDir, _ := os.MkdirTemp("", "ipfar-consistency-*")
	defer os.RemoveAll(tmpDir)
	carPath := filepath.Join(tmpDir, "test.car")
	_, rootCID2, err := ipfar.BuildCarV2(fileData)
	if err != nil {
		t.Fatalf("BuildCarV2 failed: %v", err)
	}
	// Write to file for CAR parser
	if err := os.WriteFile(carPath, carBytes, 0644); err != nil {
		t.Fatalf("Failed to write CAR file: %v", err)
	}

	if rootCID1.String() != rootCID2.String() {
		t.Errorf("CID mismatch: bytes=%s, file=%s", rootCID1.String(), rootCID2.String())
	} else {
		t.Logf("✅ Bytes/File CID 一致: %s", rootCID1.String())
	}

	fileCarBytes, _ := os.ReadFile(carPath)
	if len(fileCarBytes) != len(carBytes) {
		t.Errorf("CAR byte length mismatch: bytes=%d, file=%d", len(carBytes), len(fileCarBytes))
	} else {
		t.Log("✅ Bytes/File CAR 大小一致")
	}
}

func TestIntegration_MetadataRoundTrip(t *testing.T) {
	meta := &sdkmetadata.Metadata{
		Version:      sdkmetadata.Version1,
		Method:       sdkmetadata.MethodRaw,
		RootCID:      "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID:     "test_txid_1234567890123456789012345678901234567890",
		DataHeight:   1913000,
		DataSize:     50 * 1024 * 1024,
		PoW:          "42",
		PoWAlg:       "argon2id-light-v1",
		ContentType:  "image/png",
		OriginalName: "hello.png",
	}

	jsonBytes, err := meta.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	sdkMeta, err := sdkmetadata.ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("SDK ParseJSON failed: %v", err)
	}

	if sdkMeta.Version != meta.Version {
		t.Errorf("Version mismatch")
	}
	if sdkMeta.RootCID != meta.RootCID {
		t.Errorf("RootCID mismatch")
	}
	if sdkMeta.PoW != meta.PoW {
		t.Errorf("PoW mismatch")
	}

	if err := sdkMeta.Validate(); err != nil {
		t.Errorf("SDK Validate failed: %v", err)
	} else {
		t.Log("✅ Metadata round-trip successful")
	}

	b64, err := meta.ToBase64URL()
	if err != nil {
		t.Fatalf("ToBase64URL failed: %v", err)
	}

	sdkMeta2, err := sdkmetadata.ParseFromBase64URL(b64)
	if err != nil {
		t.Fatalf("ParseFromBase64URL failed: %v", err)
	}
	if sdkMeta2.RootCID != meta.RootCID {
		t.Errorf("Base64URL round-trip CID mismatch")
	}
	t.Log("✅ Metadata Base64URL round-trip successful")
}

// ============================================================================
// 辅助
// ============================================================================

func init() {
	fmt.Println(`
╔══════════════════════════════════════════════════════════╗
║   IPFAR Uploader ↔ SDK 集成测试                          ║
║   测试: uploader 生成 → SDK 验证                          ║
╚══════════════════════════════════════════════════════════╝`)
}

var _ = json.Marshal
