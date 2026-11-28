package netcheck

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/AloofLibra/zator/internal/paths"
)

const (
	// DefaultH3CurlReleaseBase — базовый URL релизов статических бинарников curl с HTTP/3.
	DefaultH3CurlReleaseBase = "https://github.com/MarkinAlexander/z2r-curl-h3/releases/latest/download"

	MinH3CurlSize = 1 << 20  // 1 MiB
	MaxH3CurlSize = 10 << 20 // 10 MiB
)

var (
	ErrH3ArchUnsupported = errors.New("netcheck: неподдерживаемая архитектура для h3-curl")
	ErrH3Offline         = errors.New("netcheck: оффлайн-режим (Z2R_OFFLINE=1)")
	ErrH3InvalidArtifact = errors.New("netcheck: повреждённый или некорректный артефакт h3-curl")
)

// H3CurlStatus отражает состояние локального h3-curl для WebUI, CLI и checker.
type H3CurlStatus struct {
	Found   bool   `json:"found"`
	Path    string `json:"path"`
	Arch    string `json:"arch"`
	Managed bool   `json:"managed"`
}

// H3Env позволяет изолировать внешние зависимости при тестировании h3-curl.
type H3Env struct {
	Arch               string
	ELFPath            string
	OpenWrtReleasePath string
	OpkgArchFn         func() string
	ReleaseBase        string
	Offline            bool
	HTTPClient         *http.Client
	VersionCheckFn     func(bin string) (string, error)
	EnvOverride        string
	EntwareCurlPath    string
	LookPathFn         func(file string) (string, error)
	CABundleOverride   string
}

func (e H3Env) releaseBase() string {
	if strings.TrimSpace(e.ReleaseBase) != "" {
		return strings.TrimRight(strings.TrimSpace(e.ReleaseBase), "/")
	}
	if v := strings.TrimSpace(os.Getenv("Z2R_CURL_H3_RELEASE_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultH3CurlReleaseBase
}

func (e H3Env) isOffline() bool {
	if e.Offline {
		return true
	}
	return os.Getenv("Z2R_OFFLINE") == "1"
}

func (e H3Env) elfPath() string {
	if e.ELFPath != "" {
		return e.ELFPath
	}
	if v := os.Getenv("Z2R_QUIC_ELF_FILE"); v != "" {
		return v
	}
	return "/proc/self/exe"
}

func (e H3Env) openWrtReleasePath() string {
	if e.OpenWrtReleasePath != "" {
		return e.OpenWrtReleasePath
	}
	if v := os.Getenv("Z2R_QUIC_OPENWRT_RELEASE"); v != "" {
		return v
	}
	return "/etc/openwrt_release"
}

func (e H3Env) envOverride() string {
	if e.EnvOverride != "" {
		return e.EnvOverride
	}
	return os.Getenv("Z2R_QUIC_CURL")
}

func (e H3Env) entwarePath() string {
	if e.EntwareCurlPath != "" {
		return e.EntwareCurlPath
	}
	return "/opt/bin/curl"
}

func (e H3Env) lookPath(file string) (string, error) {
	if e.LookPathFn != nil {
		return e.LookPathFn(file)
	}
	return exec.LookPath(file)
}

func (e H3Env) versionOutput(bin string) (string, error) {
	if e.VersionCheckFn != nil {
		return e.VersionCheckFn(bin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	return string(out), err
}

func (e H3Env) httpClient() *http.Client {
	if e.HTTPClient != nil {
		return e.HTTPClient
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (e H3Env) supportsHTTP3(bin string) bool {
	if bin == "" {
		return false
	}
	out, err := e.versionOutput(bin)
	if err != nil {
		return false
	}
	low := strings.ToLower(out)
	return strings.Contains(low, "http3") || strings.Contains(low, "nghttp3")
}

// DetectArch возвращает архитектуру артефакта `z2r-curl-h3-linux-<arch>.gz`.
func (e H3Env) DetectArch() (string, error) {
	machine := strings.TrimSpace(strings.ToLower(e.Arch))
	if machine == "" {
		machine = runtime.GOARCH
	}
	switch machine {
	case "amd64", "x86_64":
		return "x86_64", nil
	case "386", "i386", "i486", "i586", "i686":
		return "i686", nil
	case "arm64", "aarch64":
		return "aarch64", nil
	case "arm", "armv6l", "armv7l", "armv8l":
		return "arm", nil
	case "riscv64":
		return "riscv64", nil
	case "mipsle", "mipsel":
		return "mipsel", nil
	case "mips", "mips64":
		if strings.HasPrefix(machine, "mipsel") || strings.HasPrefix(machine, "mipsle") {
			return "mipsel", nil
		}
		endian := e.detectMIPSEndianness()
		if endian == "big" {
			return "mipssf", nil
		}
		return "mipsel", nil
	default:
		if strings.HasPrefix(machine, "mipsel") || strings.HasPrefix(machine, "mipsle") {
			return "mipsel", nil
		}
		if strings.HasPrefix(machine, "mips") {
			if e.detectMIPSEndianness() == "big" {
				return "mipssf", nil
			}
			return "mipsel", nil
		}
		return "", fmt.Errorf("%w: %s", ErrH3ArchUnsupported, machine)
	}
}

func (e H3Env) detectMIPSEndianness() string {
	if f, err := os.Open(e.elfPath()); err == nil {
		var hdr [6]byte
		n, rerr := io.ReadFull(f, hdr[:])
		_ = f.Close()
		if rerr == nil && n == 6 {
			switch hdr[5] {
			case 1:
				return "little"
			case 2:
				return "big"
			}
		}
	}
	if raw, err := os.ReadFile(e.openWrtReleasePath()); err == nil {
		for _, ln := range strings.Split(string(raw), "\n") {
			ln = strings.TrimSpace(ln)
			if !strings.HasPrefix(ln, "DISTRIB_ARCH=") {
				continue
			}
			val := strings.Trim(strings.TrimPrefix(ln, "DISTRIB_ARCH="), `"' `)
			if strings.HasPrefix(val, "mipsel") || strings.HasPrefix(val, "mipsle") {
				return "little"
			}
			if strings.HasPrefix(val, "mips") {
				return "big"
			}
			break
		}
	}
	var opkgArch string
	if e.OpkgArchFn != nil {
		opkgArch = strings.TrimSpace(e.OpkgArchFn())
	} else if lp, err := e.lookPath("opkg"); err == nil {
		if out, err := exec.Command(lp, "print-architecture").Output(); err == nil {
			for _, ln := range strings.Split(string(out), "\n") {
				fields := strings.Fields(ln)
				if len(fields) >= 2 && fields[1] != "all" && fields[1] != "noarch" {
					opkgArch = fields[1]
					break
				}
			}
		}
	}
	if strings.HasPrefix(opkgArch, "mipsel") || strings.HasPrefix(opkgArch, "mipsle") {
		return "little"
	}
	if strings.HasPrefix(opkgArch, "mips") {
		return "big"
	}
	return "little"
}

// Detect выполняет каскадный поиск рабочего curl с поддержкой HTTP/3.
func (e H3Env) Detect(p paths.Paths) H3CurlStatus {
	arch, _ := e.DetectArch()
	toolsDir := p.ToolsBinDir()
	var managedPath string
	if arch != "" && toolsDir != "" {
		managedPath = filepath.Join(toolsDir, "curl-h3-"+arch)
	}

	candidates := []string{e.envOverride(), e.entwarePath(), managedPath}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if e.isUsableBinary(c) && e.supportsHTTP3(c) {
			return H3CurlStatus{
				Found:   true,
				Path:    c,
				Arch:    arch,
				Managed: managedPath != "" && filepath.Clean(c) == filepath.Clean(managedPath),
			}
		}
	}
	if lp, err := e.lookPath("curl"); err == nil && lp != "" {
		if e.supportsHTTP3(lp) {
			return H3CurlStatus{
				Found:   true,
				Path:    lp,
				Arch:    arch,
				Managed: managedPath != "" && filepath.Clean(lp) == filepath.Clean(managedPath),
			}
		}
	}
	return H3CurlStatus{Found: false, Arch: arch}
}

func (e H3Env) isUsableBinary(path string) bool {
	if path == "" {
		return false
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return true
	}
	if lp, err := e.lookPath(path); err == nil && lp != "" {
		return true
	}
	return false
}

// Install скачивает, распаковывает (с лимитом 1..10 MiB) и проверяет h3-curl в tools/bin/.
func (e H3Env) Install(ctx context.Context, p paths.Paths, force bool) (string, error) {
	if e.isOffline() {
		return "", ErrH3Offline
	}
	arch, err := e.DetectArch()
	if err != nil {
		return "", err
	}
	toolsDir := p.ToolsBinDir()
	if toolsDir == "" {
		return "", fmt.Errorf("netcheck: пустой ToolsBinDir")
	}
	dest := filepath.Join(toolsDir, "curl-h3-"+arch)
	if !force {
		if st, err := os.Stat(dest); err == nil && !st.IsDir() && e.supportsHTTP3(dest) {
			return dest, nil
		}
	}

	urlStr := fmt.Sprintf("%s/z2r-curl-h3-linux-%s.gz", e.releaseBase(), arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("загрузка %s: %w", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: HTTP %d при загрузке %s", ErrH3InvalidArtifact, resp.StatusCode, urlStr)
	}

	gz, err := gzip.NewReader(io.LimitReader(resp.Body, MaxH3CurlSize+1024*1024))
	if err != nil {
		return "", fmt.Errorf("%w: gzip header: %v", ErrH3InvalidArtifact, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return "", fmt.Errorf("подготовка %s: %w", toolsDir, err)
	}
	tmp, err := os.CreateTemp(toolsDir, ".curl-h3-"+arch+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("временный файл в %s: %w", toolsDir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	n, err := io.Copy(tmp, io.LimitReader(gz, MaxH3CurlSize+1))
	if err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("%w: распаковка gzip: %v", ErrH3InvalidArtifact, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("синхронизация %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("закрытие %s: %w", tmpName, err)
	}
	if n > MaxH3CurlSize || n < MinH3CurlSize {
		return "", fmt.Errorf("%w: размер бинарника %d Б вне диапазона %d..%d Б", ErrH3InvalidArtifact, n, MinH3CurlSize, MaxH3CurlSize)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", fmt.Errorf("права %s: %w", tmpName, err)
	}
	if !e.supportsHTTP3(tmpName) {
		return "", fmt.Errorf("%w: скачанный бинарник не прошёл проверку --version (HTTP3/nghttp3)", ErrH3InvalidArtifact)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(dest)
			err = os.Rename(tmpName, dest)
		}
		if err != nil {
			return "", fmt.Errorf("запись %s: %w", dest, err)
		}
	}
	cleanup = false
	return dest, nil
}

// FindCABundle находит путь к системному CA-бандлу (важно для Entware curl с флагом -q).
func (e H3Env) FindCABundle() string {
	if e.CABundleOverride != "" {
		if _, err := os.Stat(e.CABundleOverride); err == nil {
			return e.CABundleOverride
		}
		return ""
	}
	if v := strings.TrimSpace(os.Getenv("Z2R_QUIC_CA_BUNDLE")); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v
		}
		return ""
	}
	for _, p := range []string{
		"/opt/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DetectH3Arch возвращает архитектуру текущей платформы для z2r-curl-h3.
func DetectH3Arch() (string, error) { return (H3Env{}).DetectArch() }

// DetectH3Curl ищет установленный HTTP/3-совместимый curl.
func DetectH3Curl(p paths.Paths) H3CurlStatus { return (H3Env{}).Detect(p) }

// InstallH3Curl загружает и устанавливает curl-h3-<arch> в p.ToolsBinDir().
func InstallH3Curl(ctx context.Context, p paths.Paths, force bool) (string, error) {
	return (H3Env{}).Install(ctx, p, force)
}

// RemoveH3Curl удаляет управляемые бинарники curl-h3-* из p.ToolsBinDir().
func RemoveH3Curl(p paths.Paths) error {
	dir := p.ToolsBinDir()
	if dir == "" {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var errs []string
	var removed []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "curl-h3-") || strings.Contains(name, "..") {
			continue
		}
		target := filepath.Join(dir, name)
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		} else {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	if len(errs) > 0 {
		return fmt.Errorf("ошибка удаления h3-curl: %s", strings.Join(errs, "; "))
	}
	return nil
}
