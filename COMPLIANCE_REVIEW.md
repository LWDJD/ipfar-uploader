# IPFAR Uploader — 协议合规审查报告

> 审查日期：2025-07-17
> 规范版本：`ipfar-specs/V1/数据结构规范.md` + `ipfar-specs/V1/项目规划.md`
> 审查范围：`ipfar-uploader/` 全部 Go 源文件（除 vendored goar）

---

## 综述

| 类别 | 问题数 | 🔴 严重 | 🟡 中等/低 |
|------|--------|---------|------------|
| Tags | 2 | 1 | 1 |
| 元数据 JSON | 1 | 0 | 1 |
| CAR v2 | 1 | 0 | 1 |
| Reference | 0 | 0 | 0 |
| PoW | 3 | 1 | 2 |
| 去重/验证 | 2 | 1 | 1 |
| 状态机 | 0 | 0 | 0 |
| **合计** | **9** | **3** | **6** |

---

## 1. Tags（数据结构规范 §1）

### 1.1 🔴 Chunked 上传时 Tags 全部 Base64URL 编码，与规范冲突

- **规范要求**：Tags 值为明文，如 `Protocol: IPFS-Arweave-Bridge`、`Root-CID: bafy...`（Base32）、`Content-Type: application/vnd.ipld.car`。
- **代码行为**：`arweave/chunked.go:buildGoarTransaction()`（行 176–186）对所有 Tag name 和 value 做 `base64.RawURLEncoding.EncodeToString`。原因是 goar 的 deep hash 签名路径要求 Base64 输入。
- **影响**：
  - 链上 chunked 交易的 Tags 以 Base64 形式存储，如 `"Root-CID"` → `"Um9vdC1DSUQ="`，`"bafy..."` → `"YmFmeS..."`。
  - 桥节点若按规范读取明文 Tag 将无法识别这些交易。
  - **GraphQL 去重查询也因此存在盲区**（见 §6.1）。
- **建议修复**：chunked 路径改用标准 Arweave v2 交易签名（SHA-384 deep hash，直接对 UTF-8 Tag 字节做 deepHash），避免 goar 的 Base64 中间层。若短期无法绕过 goar，应在规范中明确允许 Base64 编码的 Tag 备选形式，并确保 GraphQL 查询同时匹配两种形式。
- **位置**：`arweave/chunked.go:176-186` (`buildGoarTransaction`)

### 1.2 🟡 CAR Tags 中 `Data-Size` 为原始文件大小而非 CAR 文件大小

- **规范要求**：`Data-Size: (整数) — 原始数据大小（字节）`
- **代码行为**：`metadata/metadata.go:183` — `BuildCARTags` 传入的 `dataSize` 是 `result.DataSize = int64(len(fileData))`（原始文件字节数）。✅ 实际符合规范。
- **说明**：此处规范与实现一致，`Data-Size` 标注的是原始内容大小，而非 CAR 封装后的体积。CAR 体积可由 `data_size`（Arweave 交易字段）获得。**无问题，仅为澄清**。

---

## 2. 元数据 JSON（数据结构规范 §2）

### 2.1 🟡 上传元数据时 `Content-Type` Tag 为 `application/json` 但 data 字段存储的是 Base64URL 字符串

- **规范要求**：`data` 字段为 JSON 的 **Base64URL 编码**，`Content-Type: application/json`。
- **代码行为**：`uploader/uploader.go` 中 `uploadMetaWithState()`（行 311）：
  ```go
  metaBase64 := base64.RawURLEncoding.EncodeToString(metaJSON)
  tb.SetData([]byte(metaBase64))
  ```
  交易 data 字段存储的是 Base64URL 字符串（如 `eyJ2ZXJzaW9uIjoxLC...`），而非原始 JSON。Tag 却标注 `Content-Type: application/json`。
- **影响**：若下游系统直接按 `Content-Type` 解析 data 为 JSON，会失败。规范明确要求此行为，但略显矛盾。建议桥节点始终按 Base64URL→JSON 两级解析。
- **合规判断**：**实现符合规范字面要求**，但语义不一致。建议规范未来版本考虑将 `Content-Type` 改为 `application/octet-stream` 或新增 `IPFAR-Encoding: base64url` Tag。
- **位置**：`uploader/uploader.go:305-311`

---

## 3. CAR v2（数据结构规范 §3）

### 3.1 🟡 CAR v2 生成仅使用 Legacy Pragma（`car\x02`），未使用标准 CBOR Pragma

- **规范要求**：CAR v2 格式（未强制 pragma 类型，但标准格式为 CBOR `{"version": 2}`）。
- **代码行为**：`car/carv2.go:15` — `var carv2Pragma = []byte{0x63, 0x61, 0x72, 0x02}`（legacy "car\x02"）。`buildV2Header()` 生成 48 字节 legacy header。
- **影响**：`go-car/v2` 等标准库生成 CBOR pragma。当前 uploader 生成的 CAR 文件使用非标准 pragma，可能不被严格遵守标准格式的解析器接受。验证端 (`verify.go:parseV2Header`) 已同时支持两种格式。
- **建议修复**：迁移至标准 CBOR pragma + 40 字节 header。`verify_test.go` 中的 `buildCBORFormatCAR()` 可作为参考实现。
- **位置**：`car/carv2.go:15, 86-93` (`Build` 函数中 pragma 和 header 构建)

---

## 4. Reference（数据结构规范 §4）

**无合规问题。** `metadata/metadata.go` 中 `ReferenceEntry` 和 `ReferenceMap` 结构与规范完全一致：
- 支持 `height: -1`（同 Bundle/同块引用）✅
- `bundle_txid` 为可选字段（`omitempty`）✅
- `cids` 为字符串数组 ✅
- `validateReference()` 正确校验各项约束 ✅

参考实现中 `reference` 从未在上传流程中被填充（分块/去重未实现），但这是功能缺失而非合规问题。

---

## 5. PoW（项目规划 §2.1）

### 5.1 🔴 Salt 搜索使用随机而非从 0 递增

- **规范要求**：
  > 计算方式：从 salt = 0 开始递增，计算 `Argon2id(password, salt, 20MB/1/1)`。当输出哈希的前导零满足难度要求时，将当前的 salt 值写入 `pow` 字段。
- **代码行为**：所有 PoW 搜索函数（`ComputePoW`, `ComputePoWParallel`, `ComputePoWWithProgress` 等）均使用 `rand.New(rand.NewSource(...))` 生成随机 salt：
  ```go
  // pow/pow.go:157
  salt := rng.Uint64()
  ```
- **影响**：
  - 规范要求的递增搜索是**确定性**的：给定相同输入，任何人重算都能得到相同的 salt。随机搜索破坏了这一特性。
  - 随机搜索可能"幸运"地在极少次数内命中，削弱 PoW 的抗攻击效果。
  - 并行递增搜索的正确方式：worker `k` 搜索 `k, k+N, k+2N, ...`（其中 N = 总 worker 数）。当前实现给每个 worker 不同随机种子，各搜各的。
- **建议修复**：
  将搜索逻辑改为确定性递增：
  ```go
  // 单线程：
  for salt := uint64(0); salt < maxAttempts; salt++ { ... }
  
  // 多线程：worker k 从 salt=k 开始，步长 numWorkers
  ```
- **位置**：`pow/pow.go:155-158`（`ComputePoW`）、`pow/pow.go:254-258`（`computePoWParallel`）

### 5.2 🟡 Raw 模式下存在浪费的"第一遍"PoW 计算

- **规范行为**：PoW 的 password = `root_cid + data_txid`。Raw 模式下 `data_txid` 在上传 CAR 后才确定，因此必须先上传 CAR 再算 PoW。
- **代码行为**：`uploader/uploader.go:uploadCarRaw()` 在 CAR 上传前先调用 `computePoWFirstPass()`（password = `root_cid + ""`），上传成功后调用 `recomputePoW()`（password = `root_cid + actual_data_txid`）。第一次计算结果被覆盖，纯属浪费。
- **影响**：无功能错误，但白白消耗 CPU 和 ~65,536 次 Argon2id 运算（约数秒到数十秒）。
- **建议修复**：移除 `computePoWFirstPass`，Raw 模式直接等 CAR 确认后算 PoW。第一遍计算无任何缓存或加速价值。
- **位置**：`uploader/uploader.go:166-172`（调用 `computePoWFirstPass`）、`uploader/uploader.go:403-426`（函数定义）

### 5.3 🟡 PoW 阈值判断使用原始文件大小而非 CAR 文件大小

- **规范描述**：
  > 难度根据 `data_txid` 对应文件在 Arweave 上占用的数据大小计算
  > 文件大小（Arweave data_size）| 前导零要求 | ...
- **代码行为**：`pow.NeedsPoW(result.DataSize)` 中 `result.DataSize = int64(len(fileData))`，即**原始文件**字节数。CAR 封装后会增大约 100–200 字节（header + index），对阈值判断影响极小。
- **影响**：一个原始文件 99.99 MiB 封装后可能略超 100 MiB，但仍被要求 PoW。严格按规范字面（Arweave data_size）应检查 CAR 字节数。但在 bridge 端验证时，SDK 读取的是 `metadata.data_size`（原始大小），两端一致。
- **合规判断**：**低风险**。建议统一采用原始文件大小（`data_size` 字段），与 metadata 一致，并更新规范措辞以消除歧义。
- **位置**：`pow/pow.go:123` (`NeedsPoW`)、`uploader/uploader.go:92` (`result.DataSize` 赋值)

---

## 6. 去重/验证逻辑

### 6.1 🔴 GraphQL 去重查询未搜索 Base64 编码的 `Root-CID`，导致漏检 Chunked 交易

- **规范行为**：去重查询应找到所有与当前 Root-CID 匹配的 CAR 交易。
- **代码行为**：`arweave/arweave.go:QueryExistingCARs()`（行 603–641）的 GraphQL 查询：
  ```graphql
  { name: "Root-CID", values: ["<plain_root_cid>"] }
  ```
  仅搜索明文 `Root-CID`。但 chunked 上传的 Tag 值是 Base64 编码的（见 §1.1），如 `"bafy..."` 被存储为 `"YmFmeS..."`。因此 **所有通过 chunked 路径上传的 CAR 文件都无法被去重查询匹配到**。
- **影响**：
  - 对同一文件重复上传时，去重逻辑不会发现已有的 chunked CAR 交易，导致用户重复支付 AR 费用。
  - 仅影响 ≥ 256 KiB 的文件（触发 chunked 阈值）。
- **建议修复**：在 GraphQL `values` 数组中同时加入 Base64 编码的 Root-CID：
  ```go
  rootCIDB64 := base64.RawURLEncoding.EncodeToString([]byte(rootCID))
  // values: ["<plain>", "<base64>"]
  ```
  参照 `Content-Type` 和 `Protocol` 已有的双值匹配模式。
- **位置**：`arweave/arweave.go:608` (`QueryExistingCARs` 中 GraphQL query 构造)

### 6.2 🟡 `dedupCheckCAR` 使用 height=0 标记已确认的复用 CAR

- **代码行为**：`uploader/uploader.go:dedupCheckCAR()`（行 536–554）找到远端匹配 CAR 后：
  ```go
  state.CarHeight = 0 // unknown, but confirmed
  ```
- **影响**：元数据的 `data_height` 须为有效块高或 -1。若复用 CAR 的实际块高不为 0，则元数据中记录的高度不准确。虽不影响数据完整性，但会降低 bridge 节点的数据定位效率。
- **建议修复**：在 `VerifyRemoteCAR` 验证通过后，从 `/tx/{txID}` 返回的 status 中提取实际 `block_height` 填入 state。
- **位置**：`uploader/uploader.go:543`

---

## 7. 状态机

**无合规问题。** `uploader/state.go` 的状态定义与转换规则设计合理：
- 状态常量清晰，覆盖完整上传生命周期 ✅
- 转换矩阵 `validTransitions` 正确约束跳转 ✅
- `ShouldAttemptDedup()` 逻辑合理 ✅
- 支持中断续传（resume）和重试 ✅
- Bundle 流程快捷路径 `StatusCarConfirmed → StatusDone` 符合 same-bundle 语义 ✅

---

## 附录 A：已确认合规项（抽样）

| 检查项 | 位置 | 状态 |
|--------|------|------|
| CAR Tags 5 项全在 | `metadata/metadata.go:179-188` | ✅ |
| 元数据 Tags 6 项全在 | `metadata/metadata.go:171-178` | ✅ |
| 元数据 JSON 结构全字段匹配 | `metadata/metadata.go:40-53` | ✅ |
| 元数据 Base64URL 编码 | `metadata/metadata.go:140-145` | ✅ |
| CAR v2 始终含 Index | `car/carv2.go:68-72` | ✅ |
| Index 8 字节对齐 | `car/carv2.go:69-72` | ✅ |
| `data_height = -1` 仅 bundle | `metadata/metadata.go:100-102` | ✅ |
| `data_height = -1` ⇒ `bundle_txid = "none"` | `metadata/metadata.go:107-109` | ✅ |
| Reference height 支持 -1 | `metadata/metadata.go:155` | ✅ |
| `argon2id-light-v1` 算法标识 | `pow/pow.go:100` | ✅ |
| 20MB/1/1 Argon2id 参数 | `pow/pow.go:102-105` | ✅ |
| Password = rootCID + dataTXID | `pow/pow.go:150,256` | ✅ |
| Salt 十进制字符串 | `pow/pow.go:164` | ✅ |
| 前导零 ≥ 2 字节 | `pow/pow.go:107` | ✅ |
| PoW 阈值 < 100 MiB | `pow/pow.go:109` | ✅ |
| Index 存在性强制验证 | `uploader/verify.go:170-172` | ✅ |
| CAR version == 2 检查 | `uploader/verify.go:166-168` | ✅ |
| Root CID 匹配检查 | `uploader/verify.go:174-187` | ✅ |
| `VerifyRemoteCAR` Index 完整性检查 | `uploader/verify.go:190-192` | ✅ |

---

## 附录 B：修复优先级建议

| 优先级 | 编号 | 问题 | 理由 |
|--------|------|------|------|
| **P0** | 5.1 | PoW 随机搜索→递增搜索 | 直接违反规范，破坏确定性 |
| **P0** | 6.1 | GraphQL 去重漏检 chunked 交易 | 导致用户重复支付 AR 费用 |
| **P1** | 1.1 | Chunked Tags Base64 编码 | 链上数据与规范不兼容 |
| **P2** | 5.2 | 浪费的第一遍 PoW | 性能浪费，用户体验差 |
| **P2** | 3.1 | Legacy CAR v2 pragma | 互操作性问题 |
| **P3** | 6.2 | 复用 CAR 的 height=0 | 数据定位精度 |
| **P3** | 5.3 | PoW 阈值用原始大小 vs CAR 大小 | 语义歧义 |
