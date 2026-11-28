package netcheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AloofLibra/zator/internal/paths"
)

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDetectH3ArchMIPSAndStandard(t *testing.T) {
	if got, err := (H3Env{Arch: "amd64"}).DetectArch(); err != nil || got != "x86_64" {
		t.Fatalf("amd64 = %q, %v", got, err)
	}
	if got, err := (H3Env{Arch: "aarch64"}).DetectArch(); err != nil || got != "aarch64" {
		t.Fatalf("aarch64 = %q, %v", got, err)
	}
	dir := t.TempDir()
	elfLE := filepath.Join(dir, "elf-le")
	elfBE := filepath.Join(dir, "elf-be")
	_ = os.WriteFile(elfLE, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1}, 0o644)
	_ = os.WriteFile(elfBE, []byte{0x7f, 'E', 'L', 'F', 1, 2, 1}, 0o644)

	if got, err := (H3Env{Arch: "mips", ELFPath: elfLE}).DetectArch(); err != nil || got != "mipsel" {
		t.Fatalf("mips LE = %q, %v", got, err)
	}
	if got, err := (H3Env{Arch: "mips", ELFPath: elfBE}).DetectArch(); err != nil || got != "mipssf" {
		t.Fatalf("mips BE = %q, %v", got, err)
	}
}

func TestDetectCascadeAndInstallLimits(t *testing.T) {
	root := t.TempDir()
	p := paths.New(filepath.Join(root, "zator"), filepath.Join(root, "zapret2"))

	// Serve controlled gzip artifacts for valid, oversize and undersize tests.
	var payload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "z2r-curl-h3-linux-x86_64.gz") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(gzipBytes(t, payload))
	}))
	defer srv.Close()

	env := H3Env{
		Arch:            "amd64",
		ReleaseBase:     srv.URL,
		EntwareCurlPath: filepath.Join(root, "missing-opt-curl"),
		LookPathFn:      func(string) (string, error) { return "", os.ErrNotExist },
		VersionCheckFn: func(bin string) (string, error) {
			if strings.Contains(bin, "curl-h3-x86_64") || strings.Contains(bin, "custom-h3") {
				return "curl 8.11.0 Features: HTTP3 nghttp3", nil
			}
			return "curl 8.0.0 Features: HTTP2", nil
		},
	}

	// Undersize (<1 MiB) must fail cleanly.
	payload = bytes.Repeat([]byte("A"), MinH3CurlSize-1)
	if _, err := env.Install(context.Background(), p, false); !errors.Is(err, ErrH3InvalidArtifact) {
		t.Fatalf("undersize expected ErrH3InvalidArtifact, got %v", err)
	}

	// Oversize (>10 MiB) must fail cleanly without writing file.
	payload = bytes.Repeat([]byte("B"), MaxH3CurlSize+128)
	if _, err := env.Install(context.Background(), p, false); !errors.Is(err, ErrH3InvalidArtifact) {
		t.Fatalf("oversize expected ErrH3InvalidArtifact, got %v", err)
	}

	// Valid artifact installs into ToolsBinDir with Managed=true.
	payload = bytes.Repeat([]byte("C"), MinH3CurlSize+1024)
	dest, err := env.Install(context.Background(), p, false)
	if err != nil {
		t.Fatalf("valid Install failed: %v", err)
	}
	st := env.Detect(p)
	if !st.Found || !st.Managed || st.Path != dest || st.Arch != "x86_64" {
		t.Fatalf("unexpected Detect status: %+v", st)
	}

	// Z2R_QUIC_CURL override takes precedence over managed path with Managed=false.
	customBin := filepath.Join(root, "custom-h3")
	_ = os.WriteFile(customBin, []byte("bin"), 0o755)
	envOverride := env
	envOverride.EnvOverride = customBin
	stOvr := envOverride.Detect(p)
	if !stOvr.Found || stOvr.Managed || stOvr.Path != customBin {
		t.Fatalf("expected override priority, got %+v", stOvr)
	}

	// RemoveH3Curl deletes only curl-h3-* inside ToolsBinDir.
	if err := RemoveH3Curl(p); err != nil {
		t.Fatalf("RemoveH3Curl: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("managed h3-curl should be removed, err=%v", err)
	}
	if _, err := os.Stat(customBin); err != nil {
		t.Fatalf("custom bin outside tools/bin should remain: %v", err)
	}
}

func TestInstallPreservesExistingOnVerifyFailureAndRemovesTemp(t *testing.T) {
	root := t.TempDir()
	p := paths.New(filepath.Join(root, "zator"), filepath.Join(root, "zapret2"))
	toolsDir := p.ToolsBinDir()
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(toolsDir, "curl-h3-x86_64")
	const existingBody = "working-h3-curl-binary"
	if err := os.WriteFile(dest, []byte(existingBody), 0o755); err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("D"), MinH3CurlSize+256)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzipBytes(t, payload))
	}))
	defer srv.Close()

	env := H3Env{
		Arch:        "amd64",
		ReleaseBase: srv.URL,
		VersionCheckFn: func(bin string) (string, error) {
			return "curl 8.0.0 Features: HTTP2", nil // no http3/nghttp3 -> fail verify
		},
	}

	if _, err := env.Install(context.Background(), p, true); !errors.Is(err, ErrH3InvalidArtifact) {
		t.Fatalf("expected ErrH3InvalidArtifact, got %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != existingBody {
		t.Fatalf("existing working binary was altered/removed: %q, err=%v", got, err)
	}
	ents, _ := os.ReadDir(toolsDir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file in toolsDir: %s", e.Name())
		}
	}
}

func TestDetectMIPSEndiannessHeaderAndFallback(t *testing.T) {
	dir := t.TempDir()
	shortELF := filepath.Join(dir, "short")
	if err := os.WriteFile(shortELF, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatal(err)
	}
	relFile := filepath.Join(dir, "openwrt_release")
	if err := os.WriteFile(relFile, []byte("DISTRIB_ARCH='mips_24kc'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := (H3Env{Arch: "mips", ELFPath: shortELF, OpenWrtReleasePath: relFile}).DetectArch()
	if err != nil || got != "mipssf" {
		t.Fatalf("short ELF fallback = %q, %v; want mipssf", got, err)
	}
}
