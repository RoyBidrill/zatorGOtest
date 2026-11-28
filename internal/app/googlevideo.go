package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/firewall"
	"github.com/AloofLibra/zator/internal/googlevideo"
	"github.com/AloofLibra/zator/internal/telemetry"
)

var (
	gvMu                sync.Mutex
	gvListener          *googlevideo.Manager
	gvCollect           *googlevideo.Collector
	gvUploadStop        context.CancelFunc
	gvUploadDone        chan struct{}
	gvRefreshStop       context.CancelFunc
	gvRefreshDone       chan struct{}
	gvLookupIPv4Hook    func(ctx context.Context, host string) ([]string, error)
	gvSyncKernelIPsHook func(ctx context.Context, ips []string) error
)

// GooglevideoHosts возвращает обёртку над lists/googlevideo-hosts.txt.
func (a *App) GooglevideoHosts() *googlevideo.HostsFile {
	return googlevideo.NewHostsFile(a.Paths.GooglevideoHostsFile())
}

func (a *App) newGooglevideoCollector() *googlevideo.Collector {
	centralPath := filepath.Join(a.Paths.ListsDir, "googlevideo-ipv4.txt")
	var central googlevideo.CentralChecker
	cl := &googlevideo.CentralList{File: centralPath}
	if _, err := cl.Load(); err == nil {
		central = cl
	}
	_ = os.MkdirAll(a.Paths.GooglevideoStateDir(), 0o755)
	return googlevideo.NewCollector(googlevideo.CollectorConfig{
		Dir:       a.Paths.GooglevideoStateDir(),
		HostsFile: a.Paths.GooglevideoHostsFile(),
		Central:   central,
	})
}

// GooglevideoCollector возвращает (и при необходимости создаёт) локальный коллектор.
func (a *App) GooglevideoCollector() *googlevideo.Collector {
	gvMu.Lock()
	defer gvMu.Unlock()
	wantLocal := filepath.Join(a.Paths.GooglevideoStateDir(), googlevideo.LocalFileName)
	if gvCollect == nil || gvCollect.LocalFile() != wantLocal {
		gvCollect = a.newGooglevideoCollector()
	}
	return gvCollect
}

func (a *App) syncGooglevideoHostsOnly() (added int, err error) {
	h := a.GooglevideoHosts()
	n1, err1 := h.MergeSNILog(a.Paths.GooglevideoSNILog())
	if err1 != nil {
		return 0, err1
	}
	n2, err2 := h.MergeLocalRows(a.GooglevideoCollector().Local())
	if err2 != nil {
		return n1, err2
	}
	return n1 + n2, nil
}

// SyncGooglevideoHosts сливает SNI-лог и local.tsv в googlevideo-hosts.txt.
// При появлении новых хостов подтягивает ipv4 для WSSIZE.
func (a *App) SyncGooglevideoHosts() (added int, err error) {
	added, err = a.syncGooglevideoHostsOnly()
	if err != nil {
		return added, err
	}
	if added > 0 {
		rctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, _ = a.RefreshGooglevideoIPv4(rctx, false)
		cancel()
	}
	return added, nil
}

// GooglevideoCollectionStatus — enabled|disabled для settings.
func (a *App) GooglevideoCollectionStatus() string {
	gvMu.Lock()
	running := gvListener != nil && gvListener.Running()
	gvMu.Unlock()
	if running {
		return "enabled"
	}
	if nativeGooglevideoCollectorRunning() {
		return "enabled"
	}
	mode := googlevideo.DetectMode(context.Background(), googlevideo.DetectOptions{
		SnifferPath: filepath.Join(a.Paths.ZatorRoot, googlevideo.DefaultSnifferRelPath),
	})
	if mode == googlevideo.ModeOff {
		return "disabled"
	}
	return "enabled"
}

// StartGooglevideoCollection поднимает DNS-listener (если доступен),
// фоновое обновление центрального списка и DNS-резолвинг SNI-хостов, а также
// один раз сливает уже накопленные host в файл. Также стартует seed-воркер
// и mid-stream sync (ipv4/WSSIZE).
func (a *App) StartGooglevideoCollection(ctx context.Context) error {
	_, _ = a.SyncGooglevideoHosts()
	a.EnsureGooglevideoMidstream(ctx)
	a.StartGooglevideoSeeder(ctx)
	a.startGooglevideoRefresher(ctx)
	// The zapret2 custom daemon already owns these same UBus/events and state
	// files. Avoid a second writer/uploader; keep Go listener as fallback.
	if nativeGooglevideoCollectorRunning() {
		return nil
	}

	gvMu.Lock()
	defer gvMu.Unlock()
	if gvListener != nil && gvListener.Running() {
		return nil
	}
	if gvCollect == nil {
		gvCollect = a.newGooglevideoCollector()
	}
	mode := googlevideo.DetectMode(ctx, googlevideo.DetectOptions{
		SnifferPath: filepath.Join(a.Paths.ZatorRoot, googlevideo.DefaultSnifferRelPath),
	})
	if mode == googlevideo.ModeOff {
		return nil
	}
	mgr, err := googlevideo.NewManager(googlevideo.ManagerConfig{
		Mode:        mode,
		SnifferPath: filepath.Join(a.Paths.ZatorRoot, googlevideo.DefaultSnifferRelPath),
		Observer:    gvCollect,
		OnObserved:  a.addGooglevideoIPToKernelSet,
	})
	if err != nil {
		return err
	}
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("googlevideo listener: %w", err)
	}
	gvListener = mgr
	a.startGooglevideoUploader(ctx, gvCollect)
	return nil
}

func nativeGooglevideoCollectorRunning() bool {
	return nativeGooglevideoCollectorRunningAt("/var/run/z2r-googlevideo-dns.pid", "/proc")
}

func nativeGooglevideoCollectorRunningAt(pidFile, procRoot string) bool {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 2 {
		return false
	}
	cmdline, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	return err == nil && strings.Contains(string(cmdline), "googlevideo-dns-sniffer") && strings.Contains(string(cmdline), "--collector")
}

func (a *App) syncGooglevideoIPsToKernelSet(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	if gvSyncKernelIPsHook != nil {
		return gvSyncKernelIPsHook(ctx, ips)
	}
	cfg, err := config.Load(a.Paths.ZapretConfig)
	if err != nil {
		return err
	}
	wcfg, err := firewall.WssizeConfigFromGetter(cfg.Get, a.Paths.ZatorRoot)
	if err != nil {
		return err
	}
	if !wcfg.Active() {
		return nil
	}
	syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return firewall.NewWssize(wcfg, firewall.ExecRunner{}).AddIPs(syncCtx, ips)
}

func (a *App) addGooglevideoIPToKernelSet(obs googlevideo.Observation, result googlevideo.ObserveResult) error {
	if result.Central {
		return nil
	}
	return a.syncGooglevideoIPsToKernelSet(context.Background(), []string{obs.IP})
}

// ResolveGooglevideoHosts резолвит SNI-собранные хосты из lists/googlevideo-hosts.txt
// через системный DNS роутера, записывает в Collector и добавляет IPv4 в z2r_googlevideo4.
func (a *App) ResolveGooglevideoHosts(ctx context.Context, force bool) (googlevideo.ResolveResult, error) {
	return a.resolveGooglevideoHosts(ctx, force, false)
}

func (a *App) resolveGooglevideoHosts(ctx context.Context, force, syncOnlyNew bool) (googlevideo.ResolveResult, error) {
	hosts, err := a.GooglevideoHosts().List()
	if err != nil {
		return googlevideo.ResolveResult{}, err
	}
	res := googlevideo.ResolveHosts(ctx, hosts, googlevideo.ResolveConfig{
		Collector:  a.GooglevideoCollector(),
		LookupIPv4: gvLookupIPv4Hook,
		Force:      force,
	})
	syncIPs := res.LiveIPs
	if syncOnlyNew {
		syncIPs = res.IPs
	}
	if len(syncIPs) > 0 {
		_ = a.syncGooglevideoIPsToKernelSet(ctx, syncIPs)
	}
	return res, nil
}

// GooglevideoLocalIPCount возвращает число уникальных актуальных локальных IPv4.
func (a *App) GooglevideoLocalIPCount() int {
	now := time.Now().Unix()
	seen := make(map[string]struct{})
	for _, r := range a.GooglevideoCollector().Local() {
		if r.Expires > now && googlevideo.PublicIPv4(r.IP) {
			seen[r.IP] = struct{}{}
		}
	}
	return len(seen)
}

// StopGooglevideoCollection останавливает listener (для тестов/shutdown).
func (a *App) StopGooglevideoCollection() {
	a.StopGooglevideoSeeder()
	gvMu.Lock()
	stopUpload, uploadDone := gvUploadStop, gvUploadDone
	gvUploadStop, gvUploadDone = nil, nil
	stopRefresh, refreshDone := gvRefreshStop, gvRefreshDone
	gvRefreshStop, gvRefreshDone = nil, nil
	gvMu.Unlock()
	if stopRefresh != nil {
		stopRefresh()
	}
	if stopUpload != nil {
		stopUpload()
	}
	gvMu.Lock()
	l := gvListener
	gvListener = nil
	gvMu.Unlock()
	if l != nil {
		_ = l.Stop()
	}
	if refreshDone != nil {
		<-refreshDone
	}
	if uploadDone != nil {
		<-uploadDone
	}
}

func gvRefreshBackoff(failures int) time.Duration {
	switch {
	case failures <= 1:
		return 5 * time.Minute
	case failures == 2:
		return 15 * time.Minute
	case failures == 3:
		return 30 * time.Minute
	default:
		return 60 * time.Minute
	}
}

func (a *App) startGooglevideoRefresher(parent context.Context) {
	gvMu.Lock()
	if gvRefreshStop != nil {
		gvMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	gvRefreshStop, gvRefreshDone = cancel, done
	gvMu.Unlock()

	failCount := 0
	var nextRemoteTry time.Time
	runOnce := func(initial bool) {
		rctx, rcancel := context.WithTimeout(ctx, 25*time.Second)
		defer rcancel()
		now := time.Now()
		if initial || failCount == 0 || !now.Before(nextRemoteTry) {
			if _, err := a.refreshGooglevideoIPv4(rctx, false, !initial); err != nil {
				failCount++
				nextRemoteTry = now.Add(gvRefreshBackoff(failCount))
			} else {
				failCount = 0
				nextRemoteTry = time.Time{}
			}
		}
		_, _ = a.syncGooglevideoHostsOnly()
		_, _ = a.resolveGooglevideoHosts(rctx, false, !initial)
	}
	go func() {
		defer close(done)
		runOnce(true)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runOnce(false)
			}
		}
	}()
}

func (a *App) startGooglevideoUploader(parent context.Context, collector *googlevideo.Collector) {
	if gvUploadStop != nil || collector == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	client := telemetry.New(a.Paths)
	uploader, err := googlevideo.NewUploader(googlevideo.UploaderConfig{
		Collector: collector,
		Central:   a.GooglevideoCentralList(),
		IngestURL: googlevideo.IngestURLFromEnv(),
		Consent: func() googlevideo.Consent {
			settings, err := client.LoadSettings()
			if err != nil || !settings.Enabled || strings.TrimSpace(settings.UUID) == "" {
				return googlevideo.Consent{}
			}
			return googlevideo.Consent{Enabled: true, UUID: settings.UUID, Token: os.Getenv(telemetry.EnvStatsToken)}
		},
	})
	if err != nil {
		cancel()
		return
	}
	done := make(chan struct{})
	gvUploadStop, gvUploadDone = cancel, done
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := uploader.Upload(ctx, false); err != nil {
					// Очередь остаётся на диске и будет повторена в следующий цикл.
					continue
				}
			}
		}
	}()
}

// GooglevideoCentralList — кеш lists/googlevideo-ipv4.txt для WSSIZE mark/ipset.
// Использует Z2R_GOOGLEVIDEO_IPS_URL (по умолчанию LegacyRemoteListURL; "off" отключает feed).
func (a *App) GooglevideoCentralList() *googlevideo.CentralList {
	return &googlevideo.CentralList{
		File:        filepath.Join(a.Paths.ListsDir, googlevideo.ListFileName),
		RequestPath: filepath.Join(a.Paths.GooglevideoStateDir(), googlevideo.ListFileName+".request"),
		URL:         googlevideo.ListURLFromEnv(),
		OnUpdate:    func(ips []string) error { return a.syncGooglevideoIPsToKernelSet(context.Background(), ips) },
	}
}

func (a *App) refreshGooglevideoIPv4(ctx context.Context, force, skipFreshNotify bool) (googlevideo.UpdateResult, error) {
	if err := os.MkdirAll(a.Paths.ListsDir, 0o755); err != nil {
		return googlevideo.UpdateResult{}, err
	}
	cl := a.GooglevideoCentralList()
	cl.SkipFreshNotify = skipFreshNotify
	// Подмешиваем локально наблюдаемые IP (коллектор) в OnUpdate не нужно —
	// они живут отдельно; central list — публичный CIDR/IP feed.
	return cl.Update(ctx, force)
}

// RefreshGooglevideoIPv4 обновляет центральный ipv4-список (TTL или force).
// Нужен для mid-stream: WSSIZE lite маркирует только адреса из этого файла/ipset.
func (a *App) RefreshGooglevideoIPv4(ctx context.Context, force bool) (googlevideo.UpdateResult, error) {
	return a.refreshGooglevideoIPv4(ctx, force, false)
}
