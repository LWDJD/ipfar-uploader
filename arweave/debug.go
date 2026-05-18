// Package arweave — debug logging helpers.
package arweave

import (
	"fmt"
	"os"
	"time"
	"runtime"
)

// DebugEnabled controls whether debug logs are written to stderr.
// Set from CLI (--debug flag).
var DebugEnabled bool

// debugLog prints a formatted message to stderr when DebugEnabled is true.
// Format: [DEBUG] <file:line> <message>
func debugLog(format string, args ...interface{}) {
	if !DebugEnabled {
		return
	}
	prefix := "[DEBUG]"
	if _, file, line, ok := runtime.Caller(1); ok {
		// Trim to just the file name (no full path).
		for i := len(file) - 1; i >= 0; i-- {
			if file[i] == '/' {
				file = file[i+1:]
				break
			}
		}
		prefix = fmt.Sprintf("[DEBUG] %s:%d", file, line)
	}
	fmt.Fprintf(os.Stderr, prefix+" "+format+"\n", args...)
}

// debugHTTPStart logs the start of an HTTP request and returns the start time.
func debugHTTPStart(method, url string) time.Time {
	debugLog("HTTP %s %s — start", method, url)
	return time.Now()
}

// debugHTTPDone logs the completion of an HTTP request with status, duration,
// and a truncated body preview.
func debugHTTPDone(start time.Time, statusCode int, body []byte, err error) {
	elapsed := time.Since(start)
	if err != nil {
		debugLog("HTTP %d (%v) error=%v", statusCode, elapsed, err)
		return
	}
	preview := string(body)
	if len(preview) > 200 {
		preview = preview[:200] + "...(truncated)"
	}
	debugLog("HTTP %d (%v) body=%s", statusCode, elapsed, preview)
}
