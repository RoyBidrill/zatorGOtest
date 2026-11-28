package webapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/deploy"
	"github.com/AloofLibra/zator/internal/googlevideo"
	"github.com/AloofLibra/zator/internal/orchestra"
	"github.com/AloofLibra/zator/internal/telemetry"
)

var (
	// (?i) — TLS_ClientHello_*.bin тоже в пикере (исторические имена с заглавными).
	tlsBlobFileRe = regexp.MustCompile(`(?i)^(tls_[A-Za-z0-9_.-]+\.bin|custom_tls\.bin)$`)
	wgBlobFileRe  = regexp.MustCompile(`(?i)^wg_initial_fake_[A-Za-z0-9_.-]+\.bin$`)
)

const (
	blobDefault = "fake_default_tls"
	cliHint     = " Обновите конфиг через Web UI (Настройки → Конфиг) или zator update."
)

// normSetting приводит имя настройки к каноничному виду.
func normSetting(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.ReplaceAll(name, "-", "_")
}

// GET|POST /cgi-bin/settings.cgi
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, p params) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.Method == http.MethodPost {
		out, err := s.settingsPost(r, p)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	name := normSetting(p.Get("setting"))
	if name == "supersweep" {
		s.writeSupersweep(w)
		return
	}
	if name == "zapret_releases" {
		writeJSON(w, http.StatusOK, s.zapretReleasesGet(r.Context(), p.Get("refresh") == "1"))
		return
	}
	cfg, _ := s.readConfig()
	out, err := s.settingGet(r.Context(), cfg, name)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// settingGet возвращает полезную нагрузку настройки (GET settings.cgi?setting=name).
func (s *Server) settingGet(ctx context.Context, cfg *config.Config, name string) (any, error) {
	switch normSetting(name) {
	case "wg_blob":
		return s.wgBlobGet(cfg), nil
	case "wg_state":
		return wgStateGet(cfg), nil
	case "fallback", "fallback_state":
		st := cfg.FallbackText()
		return map[string]any{"state": st, "enabled": st == "включен"}, nil
	case "udp_games", "udp_games_state":
		st := cfg.UDPGamesText()
		return map[string]any{
			"state":   st,
			"enabled": st == "Включен",
			"ports":   config.UDPGamesPorts,
		}, nil
	case "wssize_ramp":
		return s.wssizeGet(cfg), nil
	case "auto_mode", "auto_mode_state":
		st := cfg.AutoModeText()
		return map[string]any{"state": st, "enabled": st == "включен"}, nil
	case "hostlist", "hostlist_state":
		st := cfg.HostlistText()
		return map[string]any{"state": st, "auto": st == "авто"}, nil
	case "rst_guard", "rst_guard_state":
		st := cfg.RSTGuardText()
		_, err := os.Stat(filepath.Join(s.paths.LuaDir, "rst-guard.lua"))
		return map[string]any{"state": st, "enabled": st == "включен", "lua_available": err == nil}, nil
	case "reasm", "reasm_state":
		st := cfg.ReasmText()
		return map[string]any{"state": st, "enabled": st == "включено"}, nil
	case "dns_desync", "dns_desync_state":
		st := cfg.DNSDesyncText()
		return map[string]any{"state": st, "enabled": st == "Включен"}, nil
	case "ports":
		return map[string]any{"tcp": cfg.PortsFor("tcp"), "udp": cfg.PortsFor("udp")}, nil
	case "provider":
		return map[string]any{"provider": s.providerText()}, nil
	case "telemetry":
		c := telemetry.New(s.paths)
		settings, err := c.LoadSettings()
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"decided":    settings.Decided,
			"enabled":    settings.Enabled,
			"configured": strings.TrimSpace(c.Token) != "" && strings.TrimSpace(c.Endpoint) != "",
		}, nil
	case "fwtype":
		v := cfg.FWType()
		return map[string]any{"state": v, "value": v}, nil
	case "flowoffload":
		v := cfg.FlowOffload()
		return map[string]any{"state": v, "value": v}, nil
	case "ifaces", "iface", "iface_wan", "interfaces":
		return s.ifacesPayload(cfg), nil
	case "client_scope":
		return s.scopesPayload(cfg), nil
	case "update_check":
		return s.updateCheck(), nil
	case "recommendations":
		return s.recommendations(), nil
	case "config_raw", "config":
		return s.configRawGet(), nil
	case "nfqws2_errors", "errors":
		return s.nfqws2ErrorsGet(), nil
	case "h3_curl":
		return s.h3Env().Detect(s.paths), nil
	case "zapret_releases":
		return s.zapretReleasesGet(ctx, false), nil
	case "", "tls_blob":
		return s.tlsBlobGet(cfg)
	default:
		return nil, errf(http.StatusBadRequest, "Неизвестная настройка")
	}
}

// listFake возвращает отсортированные имена файлов FakeDir, подходящих под re.
func (s *Server) listFake(re *regexp.Regexp) []string {
	entries, _ := os.ReadDir(s.paths.FakeDir)
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && re.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// blobDisplay переводит значение blob_override.tsv в вид контракта
// (файлы слотов хранятся без расширения .bin).
func blobDisplay(v string) string {
	if v == "" || v == blobDefault {
		return v
	}
	return v + ".bin"
}

func (s *Server) listFakeProfile(profile int) []string {
	entries, _ := os.ReadDir(s.paths.FakeDir)
	profStr := strconv.Itoa(profile)
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && orchestra.ValidBlobFileForProfile(e.Name(), profStr) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) resolveProfileBlobDisplay(cfg *config.Config, raw string, blobFiles map[string]string) string {
	if raw == "" || raw == blobDefault {
		return raw
	}
	if strings.HasPrefix(raw, orchestra.BlobSlotPrefix) {
		if cfg != nil {
			if f, ok := cfg.SlotBlobFile(raw); ok && f != "" {
				return f
			}
		}
		if f, ok := blobFiles[raw]; ok && f != "" {
			return f
		}
		return ""
	}
	return blobDisplay(raw)
}

func (s *Server) tlsBlobGet(cfg *config.Config) (any, error) {
	blobs := map[string]string{}
	modes := map[string]string{}
	snis := map[string]string{}
	sizes := map[string]string{}
	blobMap, _ := s.store.OverrideMap(orchestra.OverrideBlob)
	blobFiles, _ := s.store.BlobFilesMap()
	sniMap, _ := s.store.OverrideMap(orchestra.OverrideSNI)
	sizeMap, _ := s.store.OverrideMap(orchestra.OverrideCloneSize)
	modeMap, _ := s.store.OverrideMap(orchestra.OverrideMode)
	for _, id := range orchestra.BlobOverrideProfiles {
		k := strconv.Itoa(id)
		blobs[k] = s.resolveProfileBlobDisplay(cfg, blobMap[k], blobFiles)
	}
	for _, id := range orchestra.OverrideProfiles {
		k := strconv.Itoa(id)
		snis[k] = sniMap[k]
		sizes[k] = sizeMap[k]
		mode := modeMap[k]
		if mode == "" {
			mode = orchestra.ModeClassic
		}
		modes[k] = mode
	}
	return map[string]any{
		"current_mode":      cfg.TLSBlobModeValue(),
		"current_blob":      cfg.TLSBlobFile(),
		"available_blobs":   s.listFake(tlsBlobFileRe),
		"quic_blobs":        s.listFakeProfile(5),
		"profile_blobs":     blobs,
		"profile_modes":     modes,
		"profile_snis":      snis,
		"profile_sizes":     sizes,
		"global_clone_size": sizeMap["0"],
	}, nil
}

func (s *Server) wgBlobGet(cfg *config.Config) any {
	file, repeats := cfg.WireGuardBlob()
	return map[string]any{
		"current_blob":    file,
		"current_repeats": repeats,
		"available_blobs": s.listFake(wgBlobFileRe),
	}
}

func wgStateGet(cfg *config.Config) any {
	state := ""
	switch cfg.WireGuardText() {
	case "включено":
		state = "1"
	case "выключено":
		state = "0"
	}
	return map[string]any{"state": state, "enabled": state == "1"}
}

func (s *Server) wssizeGet(cfg *config.Config) any {
	scale, err := strconv.Atoi(cfg.GetDefault("Z2R_WSSIZE_RAMP_SCALE", "1"))
	if err != nil {
		scale = 1
	}
	mode := strings.ToLower(cfg.GetDefault("Z2R_WSSIZE_RAMP_MODE", "lite"))
	if mode != "lite" {
		mode = "full"
	}
	ips := 0
	ipv4Fresh := false
	generated := ""
	if cl := s.app.GooglevideoCentralList(); cl != nil {
		ipv4Fresh = cl.Fresh()
		if l, lerr := cl.Load(); lerr == nil {
			ips = len(l.IPs)
			generated = l.Generated
		} else {
			ips = cl.Count()
		}
	} else if lines, err := readListLines(filepath.Join(s.paths.ListsDir, "googlevideo-ipv4.txt")); err == nil {
		ips = len(listEntries(lines))
	}
	hostsCount := 0
	if hosts, herr := s.app.GooglevideoHosts().List(); herr == nil {
		hostsCount = len(hosts)
	}
	return map[string]any{
		"enabled":                      cfg.GetDefault("Z2R_WSSIZE_RAMP_ENABLE", "1") == "1",
		"mode":                         mode,
		"scale":                        scale,
		"googlevideo_ips":              ips,
		"googlevideo_ipv4_fresh":       ipv4Fresh,
		"googlevideo_generated":        generated,
		"googlevideo_feed_enabled":     googlevideo.ListURLFromEnv() != "",
		"googlevideo_hosts":            hostsCount,
		"googlevideo_local_ips":        s.app.GooglevideoLocalIPCount(),
		"googlevideo_local_collection": s.app.GooglevideoCollectionStatus(),
	}
}

// updateCheck проверяет наличие обновлений через internal/deploy.
func (s *Server) updateCheck() any {
	out := map[string]any{
		"update_available":  false,
		"update_zator":      false,
		"update_config":     false,
		"release":           "",
		"latest_zator_date": "",
		"latest_webui_date": "",
		"checked_at":        s.now().Format("2006-01-02 15:04"),
		"error":             "",
	}
	u := deploy.New(s.paths)
	if off := deploy.ResolveOfflineBundle(os.Getenv); off.Offline {
		u.Offline = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := u.CheckLatest(ctx)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	out["update_available"] = res.UpdateAvailable()
	out["update_zator"] = res.UpdateZator || res.UpdateWebUI
	out["update_config"] = res.UpdateConfig
	if res.Latest != nil {
		out["release"] = res.Latest.Release
		out["latest_zator_date"] = res.Latest.ZatorDate
		out["latest_webui_date"] = res.Latest.WebUIDate
	}
	if !res.CheckedAt.IsZero() {
		out["checked_at"] = res.CheckedAt.Format("2006-01-02 15:04")
	}
	return out
}

// recommendations отдаёт подсказки стратегий из telemetry (кэш/сеть).
func (s *Server) recommendations() any {
	empty := func() map[string]any {
		return map[string]any{
			"samples": 0, "top": []any{}, "clone_recommended": false,
			"classic_pct": nil, "clone_pct": nil,
		}
	}
	profiles := map[string]any{"1": empty(), "2": empty(), "3": empty(), "4": empty()}
	out := map[string]any{
		"provider":     s.providerText(),
		"samples":      0,
		"minimum":      telemetry.MinSamples,
		"generated_at": 0,
		"status":       telemetry.StatusUnavailable,
		"profiles":     profiles,
	}
	c := telemetry.New(s.paths)
	ctx, cancel := context.WithTimeout(context.Background(), telemetry.RecsTimeout)
	defer cancel()
	rec, err := c.FetchRecommendations(ctx)
	if err != nil || rec == nil {
		if err != nil {
			out["error"] = err.Error()
		}
		return out
	}
	out["provider"] = rec.Provider
	out["samples"] = rec.Samples
	out["generated_at"] = rec.GeneratedAt
	out["status"] = rec.Status
	for i := 1; i <= 4; i++ {
		pr := rec.Profiles[i]
		top := []any{}
		for _, st := range rec.Top(i) {
			top = append(top, map[string]any{
				"strategy":    st.Strategy,
				"success_pct": st.SuccessPct,
				"samples":     st.Samples,
				"mode":        st.Mode,
			})
		}
		profiles[strconv.Itoa(i)] = map[string]any{
			"samples":           pr.Samples,
			"top":               top,
			"clone_recommended": pr.CloneRecommended,
			"classic_pct":       pr.ClassicPct,
			"clone_pct":         pr.ClonePct,
		}
	}
	out["profiles"] = profiles
	return out
}
