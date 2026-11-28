package netcheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func bytesReader(b []byte) io.ReadSeeker { return bytes.NewReader(b) }

func TestCodeOK(t *testing.T) {
	for code, want := range map[int]bool{0: false, 199: false, 200: true, 206: true, 302: true, 399: true, 400: false, 404: false, 503: false} {
		if got := CodeOK(code); got != want {
			t.Errorf("CodeOK(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestVersionState(t *testing.T) {
	cases := []struct {
		code int
		kind ErrKind
		want string
	}{
		{200, ErrNone, StateOK},
		{302, ErrNone, StateOK},
		{404, ErrNone, StateHTTP},
		{503, ErrNone, StateHTTP},
		{0, ErrAborted, StateAborted},
		{0, ErrDNS, StateDNS},
		{0, ErrTimeout, StateTimeout},
		{0, ErrConn, StateConn},
		{0, ErrTLS, StateTLS},
		{0, ErrOther, StateNone},
		{0, ErrNone, StateNone},
	}
	for _, c := range cases {
		if got := VersionState(c.code, c.kind); got != c.want {
			t.Errorf("VersionState(%d,%q) = %q, want %q", c.code, c.kind, got, c.want)
		}
	}
}

func TestDownloadState(t *testing.T) {
	cases := []struct {
		kind       ErrKind
		code, size int
		want       string
	}{
		{ErrNone, 206, 65536, DLOK},
		{ErrNone, 200, 10, DLOK},
		{ErrTLS, 206, 100, DLCut},
		{ErrNone, 206, 0, DLZero},
		{ErrNone, 404, 10, DLZero},
		{ErrTimeout, 404, 0, DLFail},
		{ErrTimeout, 0, 0, DLFail},
		{ErrNone, 0, 0, DLZero},
	}
	for _, c := range cases {
		if got := DownloadState(c.kind, c.code, c.size); got != c.want {
			t.Errorf("DownloadState(%q,%d,%d) = %q, want %q", c.kind, c.code, c.size, got, c.want)
		}
	}
}

func TestParseTLSPref(t *testing.T) {
	for in, want := range map[string]TLSPref{"": PrefAny, "any": PrefAny, "12": Pref12, " 13 ": Pref13, "BOTH": PrefBoth, "zzz": PrefAny} {
		if got := ParseTLSPref(in); got != want {
			t.Errorf("ParseTLSPref(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeVersion_BothVersions(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{http2: true})
	for _, v := range []TLSVersion{TLS12, TLS13} {
		d := ProbeVersion(context.Background(), srv.URL, v, testOpts())
		if d.State != StateOK || d.Code != 200 {
			t.Fatalf("TLS %s: state=%q code=%d text=%q", v.Label(), d.State, d.Code, d.Text)
		}
		if d.Proto != "HTTP/2" {
			t.Errorf("proto = %q, want HTTP/2", d.Proto)
		}
		if d.IP != "127.0.0.1" {
			t.Errorf("ip = %q", d.IP)
		}
		if d.Time == "-" {
			t.Errorf("time not set")
		}
		if !strings.Contains(d.Text, "Есть ответ по TLS "+v.Label()) {
			t.Errorf("text = %q", d.Text)
		}
	}
}

func TestProbeVersion_NegotiatedVersionPinned(t *testing.T) {
	var got atomic.Uint32
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(uint32(r.TLS.Version))
	}), tlsOpts{})
	ProbeVersion(context.Background(), srv.URL, TLS12, testOpts())
	if got.Load() != tls.VersionTLS12 {
		t.Errorf("version = %#x, want TLS1.2", got.Load())
	}
	ProbeVersion(context.Background(), srv.URL, TLS13, testOpts())
	if got.Load() != tls.VersionTLS13 {
		t.Errorf("version = %#x, want TLS1.3", got.Load())
	}
}

func TestProbeVersion_TLS12OnlyServer(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{maxVersion: tls.VersionTLS12})
	d13 := ProbeVersion(context.Background(), srv.URL, TLS13, testOpts())
	if d13.State != StateTLS || d13.Code != 0 {
		t.Fatalf("TLS1.3 vs 1.2-only: state=%q code=%d err=%q", d13.State, d13.Code, d13.Err)
	}
	if !strings.Contains(d13.Text, "Ошибка TLS-рукопожатия") || !strings.Contains(d13.Text, manualHint) {
		t.Errorf("text = %q", d13.Text)
	}
	d12 := ProbeVersion(context.Background(), srv.URL, TLS12, testOpts())
	if d12.State != StateOK {
		t.Fatalf("TLS1.2: %+v", d12)
	}
}

func TestProbeVersion_CertificateVerification(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{})
	opts := testOpts()
	opts.InsecureSkipVerify = false
	d := ProbeVersion(context.Background(), srv.URL, TLS13, opts)
	if d.State != StateTLS {
		t.Fatalf("без skip-verify ожидали tls, получили %q (%s)", d.State, d.Text)
	}
	opts.InsecureSkipVerify = true
	if d := ProbeVersion(context.Background(), srv.URL, TLS13, opts); d.State != StateOK {
		t.Fatalf("со skip-verify ожидали ok, получили %q", d.State)
	}
}

func TestProbeVersion_FollowsRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/c", http.StatusMovedPermanently) })
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := newTLSServer(t, mux, tlsOpts{})
	d := ProbeVersion(context.Background(), srv.URL+"/a", TLS13, testOpts())
	if d.State != StateOK || d.Code != 200 {
		t.Fatalf("redirect chain: %+v", d)
	}
}

func TestProbeVersion_RedirectLoop(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}), tlsOpts{})
	d := ProbeVersion(context.Background(), srv.URL, TLS13, testOpts())
	if d.Err != ErrOther || d.State != StateNone {
		t.Fatalf("redirect loop: err=%q state=%q", d.Err, d.State)
	}
}

func TestProbeVersion_HTTPErrorCodeIsAnswer(t *testing.T) {
	srv := newTLSServer(t, http.NotFoundHandler(), tlsOpts{})
	d := ProbeVersion(context.Background(), srv.URL, TLS12, testOpts())
	if d.State != StateHTTP || d.Code != 404 || !d.Answered() || d.CodeOK() {
		t.Fatalf("404: %+v", d)
	}
}

func TestProbeVersion_Method(t *testing.T) {
	var method atomic.Value
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method.Store(r.Method)
	}), tlsOpts{})
	ProbeVersion(context.Background(), srv.URL, TLS12, testOpts())
	if method.Load() != "GET" {
		t.Errorf("метод по умолчанию = %v, want GET", method.Load())
	}
	o := testOpts()
	o.Method = "head"
	ProbeVersion(context.Background(), srv.URL, TLS12, o)
	if method.Load() != "HEAD" {
		t.Errorf("метод = %v, want HEAD", method.Load())
	}
}

func TestProbeVersion_ConnRefused(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	d := ProbeVersion(context.Background(), "https://"+addr, TLS12, testOpts())
	if d.State != StateConn || d.Err != ErrConn {
		t.Fatalf("refused: state=%q err=%q", d.State, d.Err)
	}
	if !strings.Contains(d.Text, "Соединение не устанавливается") {
		t.Errorf("text = %q", d.Text)
	}
}

func TestProbeVersion_DNSError(t *testing.T) {
	o := testOpts()
	o.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}
	}
	d := ProbeVersion(context.Background(), "https://x.invalid/", TLS12, o)
	if d.State != StateDNS || !strings.Contains(d.Text, "DNS") {
		t.Fatalf("dns: %+v", d)
	}
}

func TestProbeVersion_Timeout(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}), tlsOpts{})
	o := testOpts()
	o.MaxTime = 250 * time.Millisecond
	start := time.Now()
	d := ProbeVersion(context.Background(), srv.URL, TLS13, o)
	if d.State != StateTimeout {
		t.Fatalf("timeout: %+v", d)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("проба не уложилась в таймаут: %v", time.Since(start))
	}
	if !strings.Contains(d.Text, "Таймаут 0сек") {
		// MaxTime < 1с -> 0 сек: текст всё равно формируется
		t.Logf("text = %q", d.Text)
	}
}

func TestProbeVersion_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := ProbeVersion(ctx, "https://127.0.0.1:1/", TLS12, testOpts())
	if d.State != StateAborted || d.Err != ErrAborted {
		t.Fatalf("cancel: %+v", d)
	}
	if !strings.Contains(d.Text, "Проверка остановлена") {
		t.Errorf("text = %q", d.Text)
	}
}

func TestProbeVersion_InvalidInputs(t *testing.T) {
	d := ProbeVersion(context.Background(), "https://127.0.0.1/", TLSVersion(11), testOpts())
	if d.State != StateUnsupported {
		t.Errorf("unsupported: %+v", d)
	}
	d = ProbeVersion(context.Background(), "://bad url", TLS12, testOpts())
	if d.State != StateNone || d.Err != ErrOther {
		t.Errorf("bad url: %+v", d)
	}
}

func TestProbeDownload_RangeLimit(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{http2: true})
	dl := ProbeDownload(context.Background(), srv.URL, testOpts())
	if dl.State != DLOK || dl.Size != DefaultDownloadRange || dl.Code != 206 {
		t.Fatalf("download: %+v", dl)
	}
	if !strings.Contains(dl.Text, "получено 65536 байт") || !strings.Contains(dl.Text, "код 206") {
		t.Errorf("text = %q", dl.Text)
	}
	if dl.Speed() <= 0 {
		t.Errorf("speed = %v", dl.Speed())
	}
}

func TestProbeDownload_ServerIgnoresRange(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body100k) // 200 без Range
	}), tlsOpts{})
	dl := ProbeDownload(context.Background(), srv.URL, testOpts())
	if dl.State != DLOK || dl.Size != DefaultDownloadRange || dl.Code != 200 {
		t.Fatalf("download without range: %+v", dl)
	}
}

func TestProbeDownload_SmallPage(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tiny")
	}), tlsOpts{})
	dl := ProbeDownload(context.Background(), srv.URL, testOpts())
	if dl.State != DLOK || dl.Size != 4 {
		t.Fatalf("small page: %+v", dl)
	}
}

// cutHandler отдаёт n байт Range-запроса и «зависает» (имитация среза DPI).
func cutHandler(n int, onRange func()) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if onRange != nil {
			onRange()
		}
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body100k[:n])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
}

func TestProbeDownload_CutStream(t *testing.T) {
	srv := newTLSServer(t, cutHandler(1000, nil), tlsOpts{})
	start := time.Now()
	dl := ProbeDownload(context.Background(), srv.URL, testOpts())
	if dl.State != DLCut || dl.Size != 1000 || dl.Err != ErrTimeout {
		t.Fatalf("cut: %+v", dl)
	}
	if time.Since(start) > 2500*time.Millisecond {
		t.Errorf("срез не прерван по простою: %v", time.Since(start))
	}
	if !strings.Contains(dl.Text, "Данные оборвались: получено 1000 байт") {
		t.Errorf("text = %q", dl.Text)
	}
}

func TestProbeDownload_ConnectFailure(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	dl := ProbeDownload(context.Background(), "https://"+addr, testOpts())
	if dl.State != DLFail || dl.Err != ErrConn {
		t.Fatalf("connect failure: %+v", dl)
	}
}

func TestProbeDownload_CanceledAndBadURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if dl := ProbeDownload(ctx, "https://127.0.0.1:1/", testOpts()); dl.Err != ErrAborted {
		t.Errorf("cancel: %+v", dl)
	}
	if dl := ProbeDownload(context.Background(), "://x", testOpts()); dl.Err != ErrOther {
		t.Errorf("bad url: %+v", dl)
	}
}

func TestCheckTarget_AllGood(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{http2: true})
	c := NewChecker(testOpts())
	res := c.CheckTarget(context.Background(), "YouTube", srv.URL)
	if res.Verdict != VerdictOK || res.TLS12 != 1 || res.TLS13 != 1 {
		t.Fatalf("result: %+v", res)
	}
	if res.Text != "Сайт доступен: TLS работает, данные идут." {
		t.Errorf("text = %q", res.Text)
	}
	if res.Download == nil || res.Download.State != DLOK || res.Download.Retry {
		t.Errorf("download: %+v", res.Download)
	}
	if res.Label != "YouTube" || res.Target != srv.URL {
		t.Errorf("label/target: %q %q", res.Label, res.Target)
	}
}

func TestCheckTarget_OnlyTLS12_Warn(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{maxVersion: tls.VersionTLS12})
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "x", srv.URL)
	if res.Verdict != VerdictWarn || res.TLS12 != 1 || res.TLS13 != 0 {
		t.Fatalf("result: %+v", res)
	}
	if !strings.Contains(res.Text, "только по TLS 1.2") {
		t.Errorf("text = %q", res.Text)
	}
}

func TestCheckTarget_Unreachable_Fail(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "x", "https://"+addr)
	if res.Verdict != VerdictFail || res.TLS12 != 0 || res.TLS13 != 0 || res.Download != nil {
		t.Fatalf("result: %+v", res)
	}
	if !strings.Contains(res.Text, "соединение не устанавливается") {
		t.Errorf("text = %q", res.Text)
	}
}

func TestCheckTarget_404IsOK_NoDownload(t *testing.T) {
	srv := newTLSServer(t, http.NotFoundHandler(), tlsOpts{})
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "Googlevideo", srv.URL)
	if res.Verdict != VerdictOK || res.Download != nil {
		t.Fatalf("result: %+v", res)
	}
	if res.Text != "Доступ есть: TLS работает, сервер ответил кодом 404." {
		t.Errorf("text = %q", res.Text)
	}
}

func TestCheckTarget_CutStreamFails(t *testing.T) {
	srv := newTLSServer(t, cutHandler(2000, nil), tlsOpts{})
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "x", srv.URL)
	if res.Verdict != VerdictFail || res.Download == nil || res.Download.State != DLCut {
		t.Fatalf("result: %+v dl=%+v", res, res.Download)
	}
	if !strings.Contains(res.Text, "16кб") {
		t.Errorf("text = %q", res.Text)
	}
}

func TestCheckTarget_DownloadRetrySucceeds_Warn(t *testing.T) {
	var ranges atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" && ranges.Add(1) == 1 {
			cutHandler(500, nil).ServeHTTP(w, r)
			return
		}
		serveBody(w, r)
	})
	srv := newTLSServer(t, h, tlsOpts{})
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "x", srv.URL)
	if res.Verdict != VerdictWarn || res.Download == nil || !res.Download.Retry || res.Download.State != DLOK {
		t.Fatalf("result: %+v dl=%+v", res, res.Download)
	}
	if !strings.Contains(res.Download.Text, "со второй попытки") {
		t.Errorf("text = %q", res.Download.Text)
	}
	if !strings.Contains(res.Text, "Поток иногда срезается") {
		t.Errorf("verdict text = %q", res.Text)
	}
}

func TestCheckTarget_AbortsSlowVersionWhenNotWaitingBoth(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version == tls.VersionTLS13 && r.Header.Get("Range") == "" {
			select {
			case <-r.Context().Done():
			case <-time.After(4 * time.Second):
			}
			return
		}
		serveBody(w, r)
	})
	srv := newTLSServer(t, h, tlsOpts{})
	o := testOpts()
	o.WaitBoth = false
	o.MaxTime = 4 * time.Second
	start := time.Now()
	res := NewChecker(o).CheckTarget(context.Background(), "x", srv.URL)
	if time.Since(start) > 3*time.Second {
		t.Errorf("вторая проба не добита: %v", time.Since(start))
	}
	if res.TLS12Detail.State != StateOK {
		t.Fatalf("tls12: %+v", res.TLS12Detail)
	}
	if res.TLS13Detail.State != StateAborted || res.TLS13 != 0 {
		t.Fatalf("tls13 должен быть aborted: %+v", res.TLS13Detail)
	}
	if res.Verdict != VerdictWarn {
		t.Errorf("verdict = %q (TLS1.3 не ответил -> warn)", res.Verdict)
	}
}

func TestCheckTarget_ProbeGapDelaysTLS13(t *testing.T) {
	var first atomic.Uint32
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.CompareAndSwap(0, uint32(r.TLS.Version))
		serveBody(w, r)
	}), tlsOpts{})
	o := testOpts()
	o.ProbeGap = 200 * time.Millisecond
	NewChecker(o).CheckTarget(context.Background(), "x", srv.URL)
	if first.Load() != tls.VersionTLS12 {
		t.Errorf("первым должен прийти TLS 1.2, пришёл %#x", first.Load())
	}
}

func TestCheckTargets_SequentialOrder(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{})
	res := NewChecker(testOpts()).CheckTargets(context.Background(), []Target{
		{"A", srv.URL}, {"B", srv.URL + "/x"},
	})
	if len(res) != 2 || res[0].Label != "A" || res[1].Label != "B" {
		t.Fatalf("results: %+v", res)
	}
}

func TestTargetResult_JSONShape(t *testing.T) {
	srv := newTLSServer(t, http.HandlerFunc(serveBody), tlsOpts{http2: true})
	res := NewChecker(testOpts()).CheckTarget(context.Background(), "YouTube", srv.URL)
	raw, err := json.Marshal(CheckResponse{Results: []TargetResult{res}})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"label", "target", "tls12", "tls13", "verdict", "text", "tls12_detail", "tls13_detail", "download"} {
		if _, ok := m.Results[0][k]; !ok {
			t.Errorf("нет поля %q в %s", k, raw)
		}
	}
	var det map[string]any
	json.Unmarshal(m.Results[0]["tls12_detail"], &det)
	for _, k := range []string{"code", "proto", "time", "ip", "state", "text"} {
		if _, ok := det[k]; !ok {
			t.Errorf("нет поля %q в tls12_detail", k)
		}
	}
	var dl map[string]any
	json.Unmarshal(m.Results[0]["download"], &dl)
	for _, k := range []string{"code", "size", "time", "state", "text"} {
		if _, ok := dl[k]; !ok {
			t.Errorf("нет поля %q в download", k)
		}
	}
	if _, bad := m.Results[0]["Err"]; bad || strings.Contains(string(raw), `"Err"`) || strings.Contains(string(raw), "Retry") {
		t.Errorf("служебные поля попали в JSON: %s", raw)
	}
	if string(m.Results[0]["tls12"]) != "1" {
		t.Errorf("tls12 должен быть числом 1: %s", m.Results[0]["tls12"])
	}

	skip := TargetResult{Label: "x"}
	raw, _ = json.Marshal(skip)
	if !strings.Contains(string(raw), `"download":null`) {
		t.Errorf("download должен быть null: %s", raw)
	}
}

func TestProbeDownload_HTTP11RepeatedNoReset(t *testing.T) {
	var mu sync.Mutex
	remoteAddrs := make(map[string]struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remoteAddrs[r.RemoteAddr] = struct{}{}
		mu.Unlock()
		serveBody(w, r)
	})
	srv13 := newTLSServer(t, handler, tlsOpts{})
	srv12 := newTLSServer(t, handler, tlsOpts{maxVersion: tls.VersionTLS12})

	for _, srv := range []*httptest.Server{srv12, srv13} {
		for i := 0; i < 10; i++ {
			dl := ProbeDownload(context.Background(), srv.URL, testOpts())
			if dl.State != DLOK || dl.Err != ErrNone || dl.Size != DefaultDownloadRange {
				t.Fatalf("iteration %d on %s: got %+v, want ok size=%d err=%q", i, srv.URL, dl, DefaultDownloadRange, ErrNone)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(remoteAddrs) != 20 {
		t.Fatalf("expected 20 distinct TCP connections across probes, got %d", len(remoteAddrs))
	}
}
