package webapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AloofLibra/zator/internal/sweep"
	"github.com/AloofLibra/zator/internal/zapret"
)

type rewriteHostTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (rt rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = rt.target.Scheme
	cloned.URL.Host = rt.target.Host
	return rt.base.RoundTrip(cloned)
}

func TestZapretReleasesGetAndCache(t *testing.T) {
	e := newEnv(t, envOpts{})
	if err := os.WriteFile(filepath.Join(e.app.Paths.ZapretRoot, zapret.VersionFile),
		[]byte("version=1.0.7-reasm-fix\nsource=fork\narch=linux-x86_64\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var hits int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/MarkinAlexander/zapret2/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"tag_name":     "v1.0.8-reasm-fix",
					"published_at": "2026-11-25T20:56:54Z",
					"html_url":     "https://github.com/MarkinAlexander/zapret2/releases/tag/v1.0.8-reasm-fix",
					"assets":       []map[string]string{{"name": "zapret2-v1.0.8-reasm-fix.tar.gz"}},
				},
			})
		case "/repos/bol-van/zapret2/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"tag_name":     "v1.0.8",
					"published_at": "2026-11-25T08:32:59Z",
					"html_url":     "https://github.com/bol-van/zapret2/releases/tag/v1.0.8",
					"assets":       []map[string]string{{"name": "zapret2-v1.0.8.tar.gz"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(gh.Close)
	u, _ := url.Parse(gh.URL)
	e.srv.zapretHTTP = &http.Client{Transport: rewriteHostTransport{target: u, base: gh.Client().Transport}}

	// /api/state сразу возвращает сведения об установленном zapret2 без сетевого похода.
	resp, state := e.get("/api/state")
	wantStatus(t, resp, http.StatusOK)
	verMap, _ := state["version"].(map[string]any)
	if verMap["zapret2_version"] != "1.0.7-reasm-fix" || verMap["zapret2_source"] != "fork" || verMap["zapret2_arch"] != "linux-x86_64" {
		t.Fatalf("unexpected state version = %+v", verMap)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("state must not hit GitHub API, hits=%d", hits)
	}

	// Первый запрос zapret_releases идёт на GitHub.
	resp, body := e.get("/api/settings?setting=zapret_releases")
	wantStatus(t, resp, http.StatusOK)
	if body["cached"] != false || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("first fetch cached=%v hits=%d body=%+v", body["cached"], hits, body)
	}
	inst, _ := body["installed"].(map[string]any)
	if inst["version"] != "1.0.7-reasm-fix" || inst["source"] != "fork" {
		t.Fatalf("installed = %+v", inst)
	}
	forkList, _ := body["fork"].([]any)
	offList, _ := body["official"].([]any)
	if len(forkList) != 1 || len(offList) != 1 {
		t.Fatalf("lists = fork:%v official:%v", forkList, offList)
	}

	// Повторный запрос в пределах 10 минут берёт из кэша.
	resp, body = e.get("/api/settings?setting=zapret_releases")
	wantStatus(t, resp, http.StatusOK)
	if body["cached"] != true || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("expected cached response without GitHub hits, cached=%v hits=%d", body["cached"], hits)
	}

	// refresh=1 принудительно обновляет кэш.
	resp, body = e.get("/api/settings?setting=zapret_releases&refresh=1")
	wantStatus(t, resp, http.StatusOK)
	if body["cached"] != false || atomic.LoadInt32(&hits) != 4 {
		t.Fatalf("expected refresh=1 to bypass cache, cached=%v hits=%d", body["cached"], hits)
	}
}

func TestPostZapretVersionValidationAndSwitch(t *testing.T) {
	e := newEnv(t, envOpts{})

	// 1. Валидация source/version.
	resp, body := e.post("/api/settings", "setting", "zapret_version", "version", "1.0.8")
	wantStatus(t, resp, http.StatusBadRequest)
	if body["error"] == nil {
		t.Fatal("expected error for missing source")
	}

	resp, _ = e.post("/api/settings", "setting", "zapret_version", "source", "official", "version", "1.0.8-reasm-fix")
	wantStatus(t, resp, http.StatusBadRequest)

	resp, _ = e.post("/api/settings", "setting", "zapret_version", "source", "fork", "version", "../evil")
	wantStatus(t, resp, http.StatusBadRequest)

	// 2. Во время активного суперавтопрогона — 409 Conflict.
	_ = e.sweeper.Start(context.Background(), sweep.Params{})
	resp, _ = e.post("/api/settings", "setting", "zapret_version", "source", "fork", "version", "1.0.8-reasm-fix")
	wantStatus(t, resp, http.StatusConflict)
	_ = e.sweeper.Cancel()

	// 3. Успешное переключение fork -> official -> fork.
	var got []zapret.Options
	e.srv.zapretInstall = func(_ context.Context, opts zapret.Options) (*zapret.Result, error) {
		got = append(got, opts)
		return &zapret.Result{
			Root:    opts.Root,
			Source:  opts.Source,
			Version: opts.Version,
			ArchDir: "linux-x86_64",
		}, nil
	}
	resp, body = e.post("/api/settings", "setting", "zapret_version", "source", "official", "version", "1.0.7")
	wantOK(t, resp, body)
	if body["version"] != "1.0.7" || body["source"] != "official" || body["restarted"] != true {
		t.Fatalf("unexpected response: %+v", body)
	}
	if e.app.Config.ZapretSource != "official" {
		t.Fatalf("expected persisted ZapretSource=official, got %q", e.app.Config.ZapretSource)
	}
	if len(got) != 1 || !got[0].Force || got[0].Source != zapret.SourceOfficial || got[0].Version != "1.0.7" {
		t.Fatalf("install opts = %+v", got)
	}
	calls := e.svc.called()
	if len(calls) != 1 || calls[0] != "restart" {
		t.Fatalf("svc calls = %v, want [restart]", calls)
	}

	// Зафиксируем время кэша от серверных часов, чтобы проверить ttl-протухание.
	cur := time.Date(2026, 11, 26, 1, 0, 0, 0, time.UTC)
	e.srv.now = func() time.Time { return cur }
	_ = e.srv.zapretRelCache
}

func TestPostZapretVersionInsufficientStorage(t *testing.T) {
	e := newEnv(t, envOpts{})
	called := false
	e.srv.zapretInstall = func(_ context.Context, opts zapret.Options) (*zapret.Result, error) {
		called = true
		return &zapret.Result{}, nil
	}
	prevCheck := zapretSpaceCheckFn
	zapretSpaceCheckFn = func(root string, embedded bool) (int64, int64, bool, error) {
		return 2 << 20, 8 << 20, false, nil
	}
	t.Cleanup(func() { zapretSpaceCheckFn = prevCheck })

	resp, body := e.post("/api/settings", "setting", "zapret_version", "source", "fork", "version", "1.0.8-reasm-fix")
	wantStatus(t, resp, http.StatusInsufficientStorage)
	if called {
		t.Fatal("zapretInstall must not be called when disk space preflight fails")
	}
	if body["error"] == nil {
		t.Fatalf("expected error message in 507 response, got %+v", body)
	}
}
