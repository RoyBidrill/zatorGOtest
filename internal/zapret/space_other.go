//go:build !linux

package zapret

func dirFreeBytes(string) (int64, bool) { return 0, false }
