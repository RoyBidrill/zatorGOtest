package main

import "testing"

func TestComputeLowMemoryLimit(t *testing.T) {
	cases := []struct {
		name    string
		meminfo string
		want    int64
	}{
		{
			name:    "64 MiB router clamps to 32 MiB floor",
			meminfo: "MemTotal:          65536 kB\nMemFree:           10000 kB\n",
			want:    32 << 20,
		},
		{
			name:    "128 MiB router uses third of RAM",
			meminfo: "MemTotal:         131072 kB\n",
			want:    (128 << 20) / 3,
		},
		{
			name:    "256 MiB router uses third of RAM",
			meminfo: "MemTotal:         262144 kB\n",
			want:    (256 << 20) / 3,
		},
		{
			name:    "512 MiB VPS leaves default Go GC",
			meminfo: "MemTotal:         524288 kB\n",
			want:    0,
		},
		{
			name:    "invalid or empty meminfo",
			meminfo: "MemFree: 1000 kB\nMemTotal: oops\n",
			want:    0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeLowMemoryLimit([]byte(tc.meminfo)); got != tc.want {
				t.Fatalf("computeLowMemoryLimit = %d, want %d", got, tc.want)
			}
		})
	}
}
