package fetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(mirrors ...Mirror) *Client {
	c := NewClient(mirrors...)
	c.RetryDelay = 0
	return c
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestDownloadOK(t *testing.T) {
	body := []byte("hello zapret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "sub", "f.bin")
	if err := testClient().Download(context.Background(), srv.URL, dest, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, body) {
		t.Fatalf("содержимое: %q", got)
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Fatal("остался .part")
	}
}

func TestDownloadSHA256(t *testing.T) {
	body := []byte("payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	dir := t.TempDir()

	if err := testClient().Download(context.Background(), srv.URL, filepath.Join(dir, "ok"), strings.ToUpper(sum(body))); err != nil {
		t.Fatalf("верная сумма: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	err := testClient().Download(context.Background(), srv.URL, bad, strings.Repeat("0", 64))
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("ожидалась ErrChecksum, получено %v", err)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("файл с неверной суммой не должен остаться")
	}
	if _, err := os.Stat(bad + ".part"); !os.IsNotExist(err) {
		t.Fatal("остался .part")
	}
}

func TestDownloadRetries(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "f")
	if err := testClient().Download(context.Background(), srv.URL, dest, ""); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&n) != 3 {
		t.Fatalf("попыток: %d", n)
	}
}

func TestDownloadGivesUpAfterRetries(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := testClient().Download(context.Background(), srv.URL, filepath.Join(t.TempDir(), "f"), "")
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 500 {
		t.Fatalf("ожидалась HTTPError 500, получено %v", err)
	}
	if atomic.LoadInt32(&n) != DefaultRetries {
		t.Fatalf("попыток: %d", n)
	}
}

func TestDownloadNoRetryOn404(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if err := testClient().Download(context.Background(), srv.URL, filepath.Join(t.TempDir(), "f"), ""); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if atomic.LoadInt32(&n) != 1 {
		t.Fatalf("404 не должен повторяться, попыток: %d", n)
	}
}

func TestDownloadMirrorFallback(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("from-mirror:" + r.URL.Path))
	}))
	defer mirror.Close()

	c := testClient(HostMirror(strings.TrimPrefix(primary.URL, "http://"), mirror.URL))
	dest := filepath.Join(t.TempDir(), "f")
	if err := c.Download(context.Background(), primary.URL+"/a/b", dest, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "from-mirror:/a/b" {
		t.Fatalf("содержимое: %q", got)
	}
}

func TestDownloadContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := testClient().Download(ctx, srv.URL, filepath.Join(t.TempDir(), "f"), ""); err == nil {
		t.Fatal("ожидалась ошибка отмены")
	}
}

func TestURLHelpers(t *testing.T) {
	rel := GitHubReleaseURL("MarkinAlexander", "zapret2", "v0.8.2", "zapret2-v0.8.2.tar.gz")
	if rel != "https://github.com/MarkinAlexander/zapret2/releases/download/v0.8.2/zapret2-v0.8.2.tar.gz" {
		t.Fatal(rel)
	}
	o, r, tag, asset, ok := ParseGitHubRelease(rel)
	if !ok || o != "MarkinAlexander" || r != "zapret2" || tag != "v0.8.2" || asset != "zapret2-v0.8.2.tar.gz" {
		t.Fatal(o, r, tag, asset, ok)
	}
	if _, _, _, _, ok := ParseGitHubRelease("https://example.com/a/b/releases/download/v1/x"); ok {
		t.Fatal("чужой хост")
	}

	m := ReleaseMirror("https://mirror.example/rel/")
	got, ok := m(rel)
	if !ok || got != "https://mirror.example/rel/v0.8.2/zapret2-v0.8.2.tar.gz" {
		t.Fatal(got, ok)
	}
	if _, ok := ReleaseMirror("")(rel); ok {
		t.Fatal("пустая база отключает зеркало")
	}

	raw := GitHubRawURL("bol-van", "zapret2", "master", "init.d/sysv/zapret2")
	if raw != "https://raw.githubusercontent.com/bol-van/zapret2/master/init.d/sysv/zapret2" {
		t.Fatal(raw)
	}
	px, ok := PxMirror(PxMirrorBase + "/zapret2")(raw)
	if !ok || px != "https://git.px.rkn.quest/zapret2/plain/init.d/sysv/zapret2?h=master" {
		t.Fatal(px, ok)
	}
	if _, ok := PxMirror(PxMirrorBase + "/zapret2")(rel); ok {
		t.Fatal("PxMirror не применим к релизам")
	}
}

func TestCandidatesDedup(t *testing.T) {
	c := NewClient(ReleaseMirror("https://m/x"), ReleaseMirror("https://m/x"))
	u := GitHubReleaseURL("a", "b", "v1", "f.tar.gz")
	got := c.Candidates(u)
	if len(got) != 2 || got[0] != u || got[1] != "https://m/x/v1/f.tar.gz" {
		t.Fatalf("%v", got)
	}
}

// ---- tar ----

type entry struct {
	name     string
	body     string
	typ      byte
	linkname string
	mode     int64
}

func makeTarGz(t *testing.T, entries []entry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Linkname: e.linkname}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSafeUntarOK(t *testing.T) {
	arc := makeTarGz(t, []entry{
		{name: "root/", typ: tar.TypeDir},
		{name: "root/a.txt", body: "A"},
		{name: "./root/sub/b.sh", body: "B", mode: 0o755},
	})
	dest := t.TempDir()
	if err := SafeUntar(arc, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "root", "a.txt")); string(b) != "A" {
		t.Fatalf("a.txt: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "root", "sub", "b.sh")); string(b) != "B" {
		t.Fatalf("b.sh: %q", b)
	}
}

func TestSafeUntarRejectsUnsafe(t *testing.T) {
	cases := map[string][]entry{
		"dotdot":        {{name: "../evil", body: "x"}},
		"dotdot-nested": {{name: "a/../../evil", body: "x"}},
		"absolute":      {{name: "/etc/passwd", body: "x"}},
		"backslash":     {{name: `a\..\evil`, body: "x"}},
		"drive":         {{name: "C:/evil", body: "x"}},
		"symlink-abs":   {{name: "l", typ: tar.TypeSymlink, linkname: "/etc"}},
		"symlink-up":    {{name: "d/l", typ: tar.TypeSymlink, linkname: "../../x"}},
		"hardlink-up":   {{name: "h", typ: tar.TypeLink, linkname: "../x"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			// Безопасная запись идёт первой: валидация обязана сработать до записи.
			arc := makeTarGz(t, append([]entry{{name: "ok.txt", body: "ok"}}, entries...))
			dest := t.TempDir()
			err := SafeUntar(arc, dest)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("ожидалась ErrUnsafePath, получено %v", err)
			}
			if _, err := os.Stat(filepath.Join(dest, "ok.txt")); !os.IsNotExist(err) {
				t.Fatal("архив не должен распаковываться частично")
			}
		})
	}
}

func TestSafeUntarFiltered(t *testing.T) {
	arc := makeTarGz(t, []entry{
		{name: "r/keep/x", body: "X", mode: 0o755},
		{name: "r/skip/y", body: "Y"},
	})
	dest := t.TempDir()
	err := SafeUntarFiltered(arc, dest, func(name string, _ os.FileMode) (string, bool) {
		if name == "r/keep/x" {
			return "out/x", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "out", "x")); string(b) != "X" {
		t.Fatalf("x: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dest, "r")); !os.IsNotExist(err) {
		t.Fatal("отфильтрованные записи не должны попасть на диск")
	}
}

func TestSafeUntarFilterCannotEscape(t *testing.T) {
	arc := makeTarGz(t, []entry{{name: "a", body: "x"}})
	err := SafeUntarFiltered(arc, t.TempDir(), func(string, os.FileMode) (string, bool) { return "../escape", true })
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("получено %v", err)
	}
}

func TestSafeUntarNotGzip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	os.WriteFile(p, []byte("<html>portal</html>"), 0o644)
	if err := SafeUntar(p, t.TempDir()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestListTarGzRejectsUnsafeHardlinkAndSafeUntarFilteredValidated(t *testing.T) {
	bad := makeTarGz(t, []entry{
		{name: "ok.txt", body: "ok"},
		{name: "badlink", typ: tar.TypeLink, linkname: "../escape"},
	})
	if _, err := ListTarGz(bad); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ListTarGz hardlink error = %v, want ErrUnsafePath", err)
	}

	good := makeTarGz(t, []entry{
		{name: "r/keep/a", body: "A", mode: 0o755},
		{name: "r/drop/b", body: "B"},
	})
	names, err := ListTarGz(good)
	if err != nil || len(names) != 2 {
		t.Fatalf("ListTarGz = %v, err=%v", names, err)
	}
	dest := t.TempDir()
	if err := SafeUntarFilteredValidated(good, dest, func(name string, _ os.FileMode) (string, bool) {
		if name == "r/keep/a" {
			return "out/a", true
		}
		return "", false
	}); err != nil {
		t.Fatalf("SafeUntarFilteredValidated: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "out", "a")); err != nil || string(b) != "A" {
		t.Fatalf("extracted = %q, err=%v", b, err)
	}
}
