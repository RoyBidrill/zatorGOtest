//go:build linux

package main

import (
	"os"
	"runtime/debug"
	"strings"
)

func configureLowMemoryLimit() {
	if strings.TrimSpace(os.Getenv("GOMEMLIMIT")) != "" {
		return
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	if limit := computeLowMemoryLimit(data); limit > 0 {
		debug.SetMemoryLimit(limit)
	}
}
