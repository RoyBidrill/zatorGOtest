package main

import (
	"strconv"
	"strings"
)

const (
	lowMemTotalThreshold = 256 << 20 // 256 MiB
	minAutoMemLimit      = 32 << 20  // 32 MiB
)

// computeLowMemoryLimit рассчитывает мягкий лимит памяти кучи Go по /proc/meminfo
// для малопамятых устройств (MemTotal <= 256 MiB): max(MemTotal/3, 32 MiB).
// Для устройств с большим объёмом памяти или нечитаемых данных возвращает 0.
func computeLowMemoryLimit(meminfo []byte) int64 {
	for _, line := range strings.Split(string(meminfo), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb <= 0 {
			return 0
		}
		total := kb * 1024
		if total > lowMemTotalThreshold {
			return 0
		}
		limit := total / 3
		if limit < minAutoMemLimit {
			limit = minAutoMemLimit
		}
		return limit
	}
	return 0
}
