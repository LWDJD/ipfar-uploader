// Package pow 提供 IPFAR 工作量证明（PoW）计算与验证功能
// 规范参考: ipfar-specs/V1/项目规划.md §2.1
package pow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	Algorithm = "argon2id-light-v1"

	argon2Memory  = 20 * 1024 // 20 MB (KB)
	argon2Time    = 1
	argon2Threads = 1
	argon2KeyLen  = 32

	MinLeadingZeroBytes = 2

	PoWThreshold = 100 * 1024 * 1024
)

var (
	ErrMissingPoW           = errors.New("PoW is required for files smaller than 100 MiB")
	ErrInvalidPoWFormat     = errors.New("invalid PoW format: must be a decimal string")
	ErrPoWVerificationFailed = errors.New("PoW verification failed: insufficient leading zeros")
	ErrAlgorithmMismatch     = errors.New("PoW algorithm mismatch")
	ErrMissingAlgorithm      = errors.New("PoW algorithm identifier is required")
)

func NeedsPoW(dataSize int64) bool {
	return dataSize < PoWThreshold
}

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

// ComputePoW 计算满足难度要求的 PoW salt
func ComputePoW(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)
	var salt uint64
	for salt = 0; ; salt++ {
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		if salt > 10_000_000 {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}

// FastComputePoW uses reduced memory for testing only
func FastComputePoW(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)
	// Use 1MB memory for fast testing
	memory := uint32(1024) // 1 MB
	var salt uint64
	for salt = 0; ; salt++ {
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)
		hash := argon2.IDKey(password, saltBytes, 1, memory, 1, 32)
		if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
		if salt > 10_000_000 {
			return "", errors.New("PoW computation exceeded safety limit")
		}
	}
}
