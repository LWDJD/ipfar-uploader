// Package pow 提供 IPFAR 工作量证明（PoW）计算与验证功能
// 规范参考: ipfar-specs/V1/项目规划.md §2.1
package pow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// =============================================================================
// PoW Cache — avoid recomputing PoW for the same file
// =============================================================================

// PoWCache is stored alongside the file as {filename}.pow.json.
type PoWCache struct {
	RootCID  string `json:"root_cid"`
	DataTXID string `json:"data_txid"`
	Salt     string `json:"salt"`
}

// LoadPoWCache reads a cache file and returns the salt if rootCID and
// dataTXID match. Returns ("", false) on any miss or error.
func LoadPoWCache(cachePath string, rootCID, dataTXID string) (string, bool) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return "", false
	}
	var c PoWCache
	if err := json.Unmarshal(data, &c); err != nil {
		return "", false
	}
	if c.RootCID == rootCID && c.DataTXID == dataTXID {
		return c.Salt, true
	}
	return "", false
}

// SavePoWCache writes the cache to disk.
func SavePoWCache(cachePath string, rootCID, dataTXID, salt string) error {
	c := PoWCache{
		RootCID:  rootCID,
		DataTXID: dataTXID,
		Salt:     salt,
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// ProgressInfo 进度信息，用于进度回调
type ProgressInfo struct {
	Attempts uint64  // 已尝试次数
	Speed    float64 // 实时速度（h/s）
	BestSalt uint64  // 当前最佳 salt
}

// ProgressCallback 进度回调函数
type ProgressCallback func(info ProgressInfo)

// FormatSpeed 格式化速度，1000 进制
// < 1000 → "xxx h/s"
// ≥ 1000 → "x.x K/s"
// ≥ 1,000,000 → "x.x M/s"
func FormatSpeed(hps float64) string {
	switch {
	case hps >= 1_000_000:
		return fmt.Sprintf("%.1f M/s", hps/1_000_000)
	case hps >= 1000:
		return fmt.Sprintf("%.1f K/s", hps/1000)
	default:
		return fmt.Sprintf("%.0f h/s", hps)
	}
}

// FormatNumber 格式化数字加逗号
func FormatNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

const (
	Algorithm = "argon2id-light-v1"

	argon2Memory  = 20 * 1024 // 20 MB (KB)
	argon2Time    = 1
	argon2Threads = 1
	argon2KeyLen  = 32

	MinLeadingZeroBytes = 2

	PoWThreshold = 100 * 1024 * 1024

	// maxAttempts is a safety limit on the number of hash attempts
	// to prevent infinite loops in case of pathological difficulty.
	maxAttempts = 10_000_000
)

var (
	ErrMissingPoW            = errors.New("PoW is required for files smaller than 100 MiB")
	ErrInvalidPoWFormat      = errors.New("invalid PoW format: must be a decimal string")
	ErrPoWVerificationFailed = errors.New("PoW verification failed: insufficient leading zeros")
	ErrAlgorithmMismatch     = errors.New("PoW algorithm mismatch")
	ErrMissingAlgorithm      = errors.New("PoW algorithm identifier is required")
	ErrPoWCancelled          = errors.New("PoW computation cancelled")
)

// DefaultWorkers returns the recommended number of parallel PoW workers.
// Caps at 4 to stay within reasonable memory limits (~80 MB for 4 workers).
func DefaultWorkers() int {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

// NeedsPoW reports whether a file of the given size requires a PoW proof.
func NeedsPoW(dataSize int64) bool {
	return dataSize < PoWThreshold
}

// Verify checks whether the given PoW salt satisfies the difficulty requirement
// for the provided rootCID + dataTXID combination.
func Verify(pow, powAlg, rootCID, dataTXID string, dataSize int64) error {
	if dataSize >= PoWThreshold {
		return nil
	}
	if powAlg == "" {
		return ErrMissingAlgorithm
	}
	if powAlg != Algorithm {
		return fmt.Errorf("%w: expected %s, got %s", ErrAlgorithmMismatch, Algorithm, powAlg)
	}
	if pow == "" {
		return ErrMissingPoW
	}
	salt, err := strconv.ParseUint(pow, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPoWFormat, err)
	}
	password := []byte(rootCID + dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if !hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		return ErrPoWVerificationFailed
	}
	return nil
}

func hasLeadingZeroBytes(data []byte, n int) bool {
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

// ---------------------------------------------------------------------------
// Single-threaded (original) – kept as fallback
// ---------------------------------------------------------------------------

// ComputePoW 计算满足难度要求的 PoW salt（单线程，随机搜索）。
func ComputePoW(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var attempts uint64
	for {
		salt := rng.Uint64()
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		attempts++
		if attempts > maxAttempts {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}

// FastComputePoW uses reduced memory (1 MiB) for testing only, with random salt.
func FastComputePoW(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)
	memory := uint32(1024) // 1 MB
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var attempts uint64
	for {
		salt := rng.Uint64()
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, 1, memory, 1, 32)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		attempts++
		if attempts > maxAttempts {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}

// ---------------------------------------------------------------------------
// Context-aware single-threaded variants (with progress callback)
// ---------------------------------------------------------------------------

// ComputePoWWithProgress is like ComputePoW but respects context cancellation
// and invokes the progress callback with the current attempt number.
func ComputePoWWithProgress(ctx context.Context, rootCID, dataTXID string, progress func(attempts uint64)) (string, error) {
	password := []byte(rootCID + dataTXID)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var attempts uint64
	for {
		select {
		case <-ctx.Done():
			return "", ErrPoWCancelled
		default:
		}

		if progress != nil {
			progress(attempts)
		}

		salt := rng.Uint64()
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		attempts++
		if attempts > maxAttempts {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}

// FastComputePoWWithProgress is like FastComputePoW but respects context
// cancellation and invokes the progress callback with the current attempt.
func FastComputePoWWithProgress(ctx context.Context, rootCID, dataTXID string, progress func(attempts uint64)) (string, error) {
	password := []byte(rootCID + dataTXID)
	memory := uint32(1024) // 1 MB
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var attempts uint64
	for {
		select {
		case <-ctx.Done():
			return "", ErrPoWCancelled
		default:
		}

		if progress != nil {
			progress(attempts)
		}

		salt := rng.Uint64()
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, 1, memory, 1, 32)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		attempts++
		if attempts > maxAttempts {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}

// ---------------------------------------------------------------------------
// Multi-core parallel search
// ---------------------------------------------------------------------------

// ComputePoWParallel searches for a valid PoW salt using numWorkers parallel
// goroutines. Each worker uses an independent random number generator with a
// unique seed (workerID + time.Now().UnixNano()) to avoid lock contention and
// overlapping search spaces.
//
// The first worker to find a valid salt cancels all others via context.
//
// If numWorkers <= 0 the default (min(runtime.NumCPU(), 4)) is used.
func ComputePoWParallel(ctx context.Context, rootCID, dataTXID string, numWorkers int) (string, error) {
	return computePoWParallel(ctx, rootCID, dataTXID, numWorkers, argon2Memory)
}

// ComputePoWParallelWithProgress 带进度回调的并行 PoW 计算
func ComputePoWParallelWithProgress(ctx context.Context, rootCID, dataTXID string, numWorkers int, progress ProgressCallback) (string, error) {
	return computePoWParallelWithProgress(ctx, rootCID, dataTXID, numWorkers, argon2Memory, progress)
}

// FastComputePoWParallel is the reduced-memory variant of ComputePoWParallel
// intended for tests. It uses 1 MiB per Argon2id invocation instead of 20 MiB.
func FastComputePoWParallel(ctx context.Context, rootCID, dataTXID string, numWorkers int) (string, error) {
	return computePoWParallel(ctx, rootCID, dataTXID, numWorkers, 1024)
}

// computePoWParallel is the shared parallel search implementation.
func computePoWParallel(ctx context.Context, rootCID, dataTXID string, numWorkers int, memoryKB uint32) (string, error) {
	if numWorkers <= 0 {
		numWorkers = DefaultWorkers()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	password := []byte(rootCID + dataTXID)
	seedBase := time.Now().UnixNano()

	type result struct {
		salt uint64
		err  error
	}

	resultCh := make(chan result, 1)
	var found atomic.Bool

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			// Independent RNG per worker to avoid lock contention.
			rng := rand.New(rand.NewSource(seedBase + int64(workerID)))
			var attempts uint64
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if found.Load() {
					return
				}

				salt := rng.Uint64()
				saltBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(saltBytes, salt)
				hash := argon2.IDKey(password, saltBytes, argon2Time, memoryKB, argon2Threads, argon2KeyLen)

				if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
					if found.CompareAndSwap(false, true) {
						select {
						case resultCh <- result{salt: salt}:
							cancel()
						default:
						}
					}
					return
				}

				attempts++
				if attempts > maxAttempts {
					if found.CompareAndSwap(false, true) {
						select {
						case resultCh <- result{err: errors.New("PoW computation exceeded safety limit")}:
							cancel()
						default:
						}
					}
					return
				}
			}
		}(w)
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			return "", r.err
		}
		return strconv.FormatUint(r.salt, 10), nil
	case <-ctx.Done():
		return "", ErrPoWCancelled
	}
}

// computePoWParallelWithProgress 带进度回调的并行搜索实现
func computePoWParallelWithProgress(ctx context.Context, rootCID, dataTXID string, numWorkers int, memoryKB uint32, progress ProgressCallback) (string, error) {
	if numWorkers <= 0 {
		numWorkers = DefaultWorkers()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	password := []byte(rootCID + dataTXID)
	seedBase := time.Now().UnixNano()

	type result struct {
		salt uint64
		err  error
	}

	resultCh := make(chan result, 1)
	var found atomic.Bool
	var totalAttempts atomic.Uint64
	var bestSalt atomic.Uint64

	// 进度统计 goroutine
	if progress != nil {
		go func() {
			var prev uint64
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current := totalAttempts.Load()
					speed := float64(current - prev)
					prev = current
					progress(ProgressInfo{
						Attempts: current,
						Speed:    speed,
						BestSalt: bestSalt.Load(),
					})
				}
			}
		}()
	}

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			rng := rand.New(rand.NewSource(seedBase + int64(workerID)))
			var attempts uint64
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if found.Load() {
					return
				}

				salt := rng.Uint64()
				saltBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(saltBytes, salt)
				hash := argon2.IDKey(password, saltBytes, argon2Time, memoryKB, argon2Threads, argon2KeyLen)

				if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
					if found.CompareAndSwap(false, true) {
						totalAttempts.Add(1)
						select {
						case resultCh <- result{salt: salt}:
							cancel()
						default:
						}
					}
					return
				}

				totalAttempts.Add(1)
				bestSalt.Store(salt)
				attempts++
				if attempts > maxAttempts {
					if found.CompareAndSwap(false, true) {
						select {
						case resultCh <- result{err: errors.New("PoW computation exceeded safety limit")}:
							cancel()
						default:
						}
					}
					return
				}
			}
		}(w)
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			return "", r.err
		}
		return strconv.FormatUint(r.salt, 10), nil
	case <-ctx.Done():
		return "", ErrPoWCancelled
	}
}
