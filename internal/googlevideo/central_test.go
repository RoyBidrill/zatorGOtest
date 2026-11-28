package googlevideo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const goodHeader = "# googlevideo IPv4; generated=2026-11-10T00:00:00Z; max_age=604800s\n"

func genIPs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("11.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
	}
	return out
}

func listBody(ips ...string) string {
	return goodHeader + strings.Join(ips, "\n") + "\n"
}

func TestParseList(t *testing.T) {
	l, err := ParseList([]byte(goodHeader + "\n8.8.8.8\n\n1.1.1.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Generated != "2026-11-10T00:00:00Z" || len(l.IPs) != 2 || l.IPs[0] != "8.8.8.8" || !l.Contains("1.1.1.1") || l.Contains("9.9.9.9") {
		t.Errorf("list = %+v", l)
	}
	// Файл без завершающего перевода строки допустим.
	if l, err := ParseList([]byte(goodHeader + "8.8.8.8")); err != nil || len(l.IPs) != 1 {
		t.Errorf("no trailing newline: %v %+v", err, l)
	}
	// generated= без «;».
	if l, err := ParseList([]byte("# googlevideo IPv4; generated=123\n8.8.8.8\n")); err != nil || l.Generated != "123" {
		t.Errorf("generated: %v %+v", err, l)
	}
}

func TestParseList_Errors(t *testing.T) {
	big := make([]byte, MaxListBytes+1)
	for i := range big {
		big[i] = '\n'
	}
	copy(big, goodHeader)
	cases := []struct {
		name string
		data string
		want error
	}{
		{"empty", "", ErrListEmpty},
		{"no header", "8.8.8.8\n", ErrListHeader},
		{"wrong header", "# googlevideo IPv6; generated=x\n8.8.8.8\n", ErrListHeader},
		{"header only", goodHeader, ErrListCount},
		{"header and blanks only", goodHeader + "\n\n", ErrListCount},
		{"private ip", goodHeader + "10.0.0.1\n", ErrListAddress},
		{"reserved among valid", goodHeader + "8.8.8.8\n192.168.0.1\n", ErrListAddress},
		{"garbage", goodHeader + "not-an-ip\n", ErrListAddress},
		{"leading zero", goodHeader + "08.8.8.8\n", ErrListAddress},
		{"comment after header", goodHeader + "# note\n8.8.8.8\n", ErrListAddress},
		{"two columns", goodHeader + "8.8.8.8 9.9.9.9\n", ErrListAddress},
		{"crlf", goodHeader + "8.8.8.8\r\n", ErrListAddress},
		{"ipv6", goodHeader + "2001:db8::1\n", ErrListAddress},
		{"too many", listBody(genIPs(MaxListIPs + 1)...), ErrListCount},
		{"too large", string(big), ErrListTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseList([]byte(tc.data))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if ValidateList([]byte(tc.data)) == nil {
				t.Error("ValidateList must fail")
			}
		})
	}
}

func TestParseList_ExactLimits(t *testing.T) {
	ips := genIPs(MaxListIPs)
	l, err := ParseList([]byte(listBody(ips...)))
	if err != nil || len(l.IPs) != MaxListIPs {
		t.Fatalf("8192 addresses must pass: %v", err)
	}
	if len(listBody(ips...)) > MaxListBytes {
		t.Fatal("fixture exceeds 256KB limit")
	}
	if err := ValidateList([]byte(listBody("8.8.8.8"))); err != nil {
		t.Error(err)
	}
}

// listServer отдаёт body и считает запросы.
type listServer struct {
	*httptest.Server
	hits   atomic.Int32
	body   atomic.Value // string
	status atomic.Int32
}

func newListServer(t *testing.T, body string) *listServer {
	t.Helper()
	s := &listServer{}
	s.body.Store(body)
	s.status.Store(200)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if code := int(s.status.Load()); code != 200 {
			http.Error(w, "boom", code)
			return
		}
		_, _ = w.Write([]byte(s.body.Load().(string)))
	}))
	t.Cleanup(s.Close)
	return s
}

func newCentral(t *testing.T, srv *listServer) (*CentralList, *time.Time) {
	t.Helper()
	now := time.Now()
	c := &CentralList{
		URL:  srv.URL,
		File: filepath.Join(t.TempDir(), "lists", ListFileName),
		Now:  func() time.Time { return now },
	}
	return c, &now
}

func TestCentralList_UpdateFetchesAndCaches(t *testing.T) {
	srv := newListServer(t, listBody("8.8.8.8", "8.8.4.4"))
	c, now := newCentral(t, srv)
	var synced []string
	c.OnUpdate = func(ips []string) error { synced = ips; return errors.New("ignored") }

	res, err := c.Update(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != UpdateFetched || res.Count != 2 || res.Generated != "2026-11-10T00:00:00Z" {
		t.Errorf("result = %+v", res)
	}
	if len(synced) != 2 {
		t.Errorf("OnUpdate ips = %v", synced)
	}
	raw, _ := os.ReadFile(c.File)
	if string(raw) != listBody("8.8.8.8", "8.8.4.4") {
		t.Errorf("file content differs: %q", raw)
	}
	if c.Count() != 2 || !c.Contains("8.8.8.8") || c.Contains("1.1.1.1") {
		t.Errorf("count=%d", c.Count())
	}
	if at, ok, have := c.RequestStatus(); !have || !ok || at.Unix() != now.Unix() {
		t.Errorf("request marker: %v %v %v", at, ok, have)
	}
	if b, _ := os.ReadFile(c.RequestFile()); string(b) != fmt.Sprintf("%d\nok\n", now.Unix()) {
		t.Errorf("request file = %q", b)
	}

	// Свежий кеш: сеть не используется, но OnUpdate получает актуальный список.
	synced = nil
	res, err = c.Update(context.Background(), false)
	if err != nil || res.Status != UpdateFresh || res.Count != 2 {
		t.Fatalf("fresh: %v %+v", err, res)
	}
	if srv.hits.Load() != 1 || len(synced) != 2 {
		t.Errorf("hits = %d synced = %v", srv.hits.Load(), synced)
	}

	// force обходит кеш.
	srv.body.Store(listBody("9.9.9.9"))
	if res, err = c.Update(context.Background(), true); err != nil || res.Count != 1 || srv.hits.Load() != 2 {
		t.Fatalf("force: %v %+v hits=%d", err, res, srv.hits.Load())
	}
	if c.Contains("8.8.8.8") || !c.Contains("9.9.9.9") {
		t.Error("Contains cache must follow the replaced file")
	}
}

func TestCentralList_TTLExpiry(t *testing.T) {
	srv := newListServer(t, listBody("8.8.8.8"))
	c, now := newCentral(t, srv)
	if _, err := c.Update(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(DefaultCacheTTL - time.Minute)
	if !c.Fresh() {
		t.Error("cache must be fresh just before 6h")
	}
	*now = now.Add(2 * time.Minute)
	if c.Fresh() {
		t.Error("cache must be stale after 6h")
	}
	srv.body.Store(listBody("1.1.1.1"))
	res, err := c.Update(context.Background(), false)
	if err != nil || res.Status != UpdateFetched || !c.Contains("1.1.1.1") {
		t.Fatalf("stale refresh: %v %+v", err, res)
	}

	// Свой TTL и «всегда обновлять».
	c.TTL = time.Minute
	*now = now.Add(2 * time.Minute)
	if c.Fresh() {
		t.Error("custom TTL 1m")
	}
	c.TTL = -1
	if err := os.Chtimes(c.File, *now, *now); err != nil {
		t.Fatal(err)
	}
	if c.Fresh() {
		t.Error("negative TTL means always refresh")
	}
}

func TestCentralList_InvalidPayloadKeepsCache(t *testing.T) {
	srv := newListServer(t, listBody("8.8.8.8"))
	c, _ := newCentral(t, srv)
	if _, err := c.Update(context.Background(), false); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"private":   goodHeader + "10.0.0.1\n",
		"no header": "8.8.4.4\n",
		"empty":     "",
		"too many":  listBody(genIPs(MaxListIPs + 1)...),
	} {
		srv.body.Store(body)
		_, err := c.Update(context.Background(), true)
		if err == nil {
			t.Errorf("%s: update must fail", name)
			continue
		}
		if !c.Contains("8.8.8.8") || c.Count() != 1 {
			t.Errorf("%s: previous cache must survive", name)
		}
		if _, ok, have := c.RequestStatus(); !have || ok {
			t.Errorf("%s: request marker must say failed", name)
		}
	}
	// После сбоя валидный список снова принимается.
	srv.body.Store(listBody("1.1.1.1"))
	if _, err := c.Update(context.Background(), true); err != nil || !c.Contains("1.1.1.1") {
		t.Fatalf("recovery: %v", err)
	}
	if _, ok, _ := c.RequestStatus(); !ok {
		t.Error("marker must be ok again")
	}
}

func TestCentralList_OversizeResponseRejected(t *testing.T) {
	huge := goodHeader + strings.Repeat("8.8.8.8\n", MaxListBytes/8+10)
	srv := newListServer(t, huge)
	c, _ := newCentral(t, srv)
	_, err := c.Update(context.Background(), true)
	if !errors.Is(err, ErrListTooLarge) && !errors.Is(err, ErrListCount) {
		t.Errorf("err = %v", err)
	}
	if _, serr := os.Stat(c.File); !os.IsNotExist(serr) {
		t.Error("oversize list must not be stored")
	}
}

func TestCentralList_HTTPAndTransportErrors(t *testing.T) {
	srv := newListServer(t, listBody("8.8.8.8"))
	c, _ := newCentral(t, srv)
	srv.status.Store(503)
	if _, err := c.Update(context.Background(), true); !errors.Is(err, ErrFetch) || !strings.Contains(err.Error(), "503") {
		t.Errorf("HTTP 503: %v", err)
	}
	srv.status.Store(200)
	srv.Close()
	if _, err := c.Update(context.Background(), true); !errors.Is(err, ErrFetch) {
		t.Errorf("closed server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Update(ctx, true); !errors.Is(err, ErrFetch) {
		t.Errorf("cancelled: %v", err)
	}
	if _, err := (&CentralList{}).Update(context.Background(), true); err == nil {
		t.Error("empty File must fail")
	}
	bad := &CentralList{URL: "://bad", File: filepath.Join(t.TempDir(), "x")}
	if _, err := bad.Update(context.Background(), true); !errors.Is(err, ErrFetch) {
		t.Errorf("bad url: %v", err)
	}
}

func TestCentralList_LoadAndHelpers(t *testing.T) {
	dir := t.TempDir()
	c := &CentralList{File: filepath.Join(dir, ListFileName)}
	if l, err := c.Load(); err != nil || len(l.IPs) != 0 {
		t.Errorf("missing file: %v %+v", err, l)
	}
	if c.Count() != 0 || c.Contains("8.8.8.8") || len(c.IPs()) != 0 || c.Fresh() {
		t.Error("missing file must give empty results")
	}
	if _, _, have := c.RequestStatus(); have {
		t.Error("no marker yet")
	}

	// Count/Contains терпимы к невалидному файлу (как grep/awk в оригинале).
	if err := os.WriteFile(c.File, []byte("# comment\n8.8.8.8\n10.0.0.1\nfoo bar\n\n  1.1.1.1  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c.Count() != 3 {
		t.Errorf("lenient count = %d, want 3", c.Count())
	}
	if !c.Contains("10.0.0.1") || !c.Contains("1.1.1.1") || c.Contains("foo") {
		t.Error("lenient Contains")
	}
	if _, err := c.Load(); err == nil {
		t.Error("strict Load must reject an invalid file")
	}
	if len(c.IPs()) != 0 {
		t.Error("IPs of an invalid file must be empty")
	}

	// Повреждённый маркер.
	if err := os.WriteFile(c.RequestFile(), []byte("x\nok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, have := c.RequestStatus(); have {
		t.Error("corrupt marker must be ignored")
	}
	if err := os.WriteFile(c.RequestFile(), []byte("123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, have := c.RequestStatus(); have {
		t.Error("one-line marker must be ignored")
	}
}

func TestCentralList_Defaults(t *testing.T) {
	c := &CentralList{}
	if c.url() != DefaultListURL || c.ttl() != DefaultCacheTTL || c.client().Timeout != DefaultFetchTimeout || c.now().IsZero() {
		t.Error("defaults")
	}
	if DefaultListURL != "" {
		t.Error("DefaultListURL must be empty (self-contained)")
	}
	if DefaultCacheTTL != 6*time.Hour || MaxListIPs != 8192 || MaxListBytes != 256*1024 {
		t.Error("limits must match the reference implementation")
	}
}

func TestCentralList_LocalOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ListFileName)
	c := &CentralList{File: path} // URL пуст — без сети
	if _, err := c.Update(context.Background(), true); !errors.Is(err, ErrFetch) {
		t.Fatalf("empty local: %v", err)
	}
	body := listBody("8.8.8.8", "1.1.1.1")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := c.Update(context.Background(), true)
	if err != nil || res.Status != UpdateFresh || res.Count != 2 {
		t.Fatalf("local: %v %+v", err, res)
	}
	if !c.Contains("8.8.8.8") {
		t.Error("Contains")
	}
}

func TestBundledGooglevideoIPv4(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "assets", "lists", ListFileName))
	if err != nil {
		t.Fatalf("asset missing: %v", err)
	}
	l, err := ParseList(data)
	if err != nil || len(l.IPs) == 0 {
		t.Fatalf("bundled list invalid: %v count=%d", err, len(l.IPs))
	}
}

func TestCentralList_ImplementsChecker(t *testing.T) {
	var _ CentralChecker = (*CentralList)(nil)
}

func TestListURLFromEnv(t *testing.T) {
	t.Setenv(EnvListURL, "")
	if got := ListURLFromEnv(); got != LegacyRemoteListURL {
		t.Fatalf("unset ListURLFromEnv() = %q, want %q", got, LegacyRemoteListURL)
	}
	for _, off := range []string{"off", "OFF", "none", "0", "false", "disabled", "  Off "} {
		t.Setenv(EnvListURL, off)
		if got := ListURLFromEnv(); got != "" {
			t.Errorf("ListURLFromEnv(%q) = %q, want empty", off, got)
		}
	}
	const mirror = "https://mirror.example/ips.txt"
	t.Setenv(EnvListURL, " "+mirror+" ")
	if got := ListURLFromEnv(); got != mirror {
		t.Errorf("custom ListURLFromEnv() = %q, want %q", got, mirror)
	}
}

func TestCentralList_RequestPathAndSkipFreshNotify(t *testing.T) {
	srv := newListServer(t, listBody("8.8.8.8", "1.1.1.1"))
	dir := t.TempDir()
	reqPath := filepath.Join(dir, "tmpfs", "state", "googlevideo-ipv4.txt.request")
	var notifies int
	c := &CentralList{
		URL:             srv.URL,
		File:            filepath.Join(dir, "lists", ListFileName),
		RequestPath:     reqPath,
		SkipFreshNotify: true,
		OnUpdate: func(ips []string) error {
			notifies++
			return nil
		},
	}

	if c.RequestFile() != reqPath {
		t.Fatalf("RequestFile() = %q, want %q", c.RequestFile(), reqPath)
	}
	res, err := c.Update(context.Background(), false)
	if err != nil || res.Status != UpdateFetched || notifies != 1 {
		t.Fatalf("initial fetch: res=%+v err=%v notifies=%d", res, err, notifies)
	}
	if _, _, ok := c.RequestStatus(); !ok {
		t.Fatalf("expected request marker at %s", reqPath)
	}
	if _, err := os.Stat(c.File + ".request"); !os.IsNotExist(err) {
		t.Fatalf("expected no .request alongside File when RequestPath is set, err=%v", err)
	}

	// Повторный Update на свежем кеше при SkipFreshNotify=true не дёргает OnUpdate.
	res, err = c.Update(context.Background(), false)
	if err != nil || res.Status != UpdateFresh || notifies != 1 {
		t.Fatalf("fresh with SkipFreshNotify: res=%+v err=%v notifies=%d", res, err, notifies)
	}
}
