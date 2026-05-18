// Package uploader — debug logging helpers.
package uploader

import (
	"fmt"
	"os"
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
