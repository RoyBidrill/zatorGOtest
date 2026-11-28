package googlevideo

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Значения по умолчанию для локального DNS-резолвинга googlevideo-hosts.txt.
const (
	DefaultResolveMaxHosts    = 64
	DefaultResolveConcurrency = 4
	DefaultResolveHostTimeout = 3 * time.Second
	DefaultResolveTTL         = 21600 // 6h, совпадает с DefaultCacheTTL
)

// ResolveConfig настраивает локальный DNS-резолв SNI-хостов *.googlevideo.com.
type ResolveConfig struct {
	Collector      *Collector
	LookupIPv4     func(ctx context.Context, host string) ([]string, error)
	Force          bool
	MaxHosts       int
	Concurrency    int
	PerHostTimeout time.Duration
	TTL            int
	Now            func() time.Time
}

// ResolveResult — итог ResolveHosts.
type ResolveResult struct {
	Checked  int      // сколько хостов резолвили в этот проход
	Resolved int      // сколько уникальных публичных IPv4 получено в этот проход
	IPs      []string // отсортированные уникальные публичные IPv4 этого прохода
	LiveIPs  []string // все актуальные локальные публичные IPv4 (включая ещё не протухшие из local.tsv)
}

func defaultLookupIPv4(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out, nil
}

// ResolveHosts резолвит хосты *.googlevideo.com в публичные IPv4, записывает их
// в Collector (local.tsv и очередь телеметрии) и возвращает список актуальных
// локальных адресов для синхронизации ядрового набора z2r_googlevideo4.
func ResolveHosts(ctx context.Context, hosts []string, cfg ResolveConfig) ResolveResult {
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = DefaultResolveMaxHosts
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultResolveConcurrency
	}
	if cfg.PerHostTimeout <= 0 {
		cfg.PerHostTimeout = DefaultResolveHostTimeout
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultResolveTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LookupIPv4 == nil {
		cfg.LookupIPv4 = defaultLookupIPv4
	}

	nowUnix := cfg.Now().Unix()
	freshHosts := make(map[string]bool)
	liveSet := make(map[string]struct{})
	if cfg.Collector != nil {
		for _, row := range cfg.Collector.Local() {
			if row.Expires <= nowUnix || !PublicIPv4(row.IP) {
				continue
			}
			liveSet[row.IP] = struct{}{}
			if !cfg.Force {
				freshHosts[row.Host] = true
			}
		}
	}

	seenHosts := make(map[string]struct{}, len(hosts))
	var candidates []string
	for _, raw := range hosts {
		host, ok := NormalizeHostname(raw)
		if !ok {
			continue
		}
		if _, dup := seenHosts[host]; dup {
			continue
		}
		seenHosts[host] = struct{}{}
		if freshHosts[host] {
			continue
		}
		candidates = append(candidates, host)
		if len(candidates) >= cfg.MaxHosts {
			break
		}
	}

	resolvedSet := make(map[string]struct{})
	var batch []Observation
	if len(candidates) > 0 && ctx.Err() == nil {
		workers := cfg.Concurrency
		if workers > len(candidates) {
			workers = len(candidates)
		}
		jobs := make(chan string, len(candidates))
		for _, h := range candidates {
			jobs <- h
		}
		close(jobs)

		var mu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				for host := range jobs {
					if ctx.Err() != nil {
						return
					}
					hCtx, cancel := context.WithTimeout(ctx, cfg.PerHostTimeout)
					addrs, err := cfg.LookupIPv4(hCtx, host)
					cancel()
					if err != nil {
						continue
					}
					for _, rawIP := range addrs {
						ip := strings.TrimSpace(rawIP)
						if !PublicIPv4(ip) {
							continue
						}
						mu.Lock()
						if cfg.Collector != nil {
							batch = append(batch, Observation{
								Host: host,
								Type: "A",
								IP:   ip,
								TTL:  cfg.TTL,
							})
						}
						resolvedSet[ip] = struct{}{}
						liveSet[ip] = struct{}{}
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
	}
	if cfg.Collector != nil && len(batch) > 0 {
		_, _ = cfg.Collector.ObserveBatch(batch)
	}

	res := ResolveResult{
		Checked: len(candidates),
		IPs:     sortedSetKeys(resolvedSet),
		LiveIPs: sortedSetKeys(liveSet),
	}
	res.Resolved = len(res.IPs)
	return res
}

func sortedSetKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
