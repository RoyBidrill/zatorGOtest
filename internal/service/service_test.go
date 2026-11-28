package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AloofLibra/zator/internal/paths"
	"github.com/AloofLibra/zator/internal/platform"
)

// fakeRunner записывает вызовы и отвечает по таблице.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	resp  func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	f.mu.Unlock()
	if f.resp != nil {
		return f.resp(name, args)
	}
	return nil, nil
}

// exitErr порождает настоящую *exec.ExitError с ненулевым кодом.
func exitErr(t *testing.T) error {
	t.Helper()
	var cmd *exec.Cmd
	if os.PathSeparator == '\\' {
		cmd = exec.Command("cmd", "/c", "exit 3")
	} else {
		cmd = exec.Command("sh", "-c", "exit 3")
	}
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("не удалось получить ExitError: %v", err)
	}
	return err
}

type env struct {
	root, proc string
	p          paths.Paths
	runner     *fakeRunner
}

func newEnv(t *testing.T) env {
	t.Helper()
	d := t.TempDir()
	e := env{
		root:   filepath.Join(d, "root"),
		proc:   filepath.Join(d, "proc"),
		p:      paths.New(filepath.Join(d, "zator"), filepath.Join(d, "zapret2")),
		runner: &fakeRunner{},
	}
	os.MkdirAll(e.root, 0o755)
	os.MkdirAll(e.proc, 0o755)
	for path, body := range map[string]string{
		filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2"):            "#!/bin/sh\n# upstream-sysv\n",
		filepath.Join(e.p.ZapretRoot, "init.d", "systemd", "zapret2.service"): "[Service]\nExecStart=/opt/zapret2/init.d/sysv/zapret2 start\n",
		filepath.Join(e.p.ZapretRoot, "init.d", "openwrt", "zapret2"):         "#!/bin/sh /etc/rc.common\n# upstream-openwrt\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e env) ctl(t *testing.T, plat platform.Platform, mut ...func(*Config)) Controller {
	t.Helper()
	cfg := Config{Platform: plat, Paths: e.p, Root: e.root, ProcRoot: e.proc, Runner: e.runner}
	for _, f := range mut {
		f(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e env) addProc(t *testing.T, pid, comm string, cmdline ...string) {
	t.Helper()
	dir := filepath.Join(e.proc, pid)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(cmdline, "\x00")+"\x00"), 0o644)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	platSystemd = platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSystemd, Arch: platform.ArchX86_64}
	platOpenRC  = platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitOpenRC, OSID: "alpine", Arch: platform.ArchX86_64}
	platProcd   = platform.Platform{Kind: platform.KindOpenWRT, InitSystem: platform.InitProcd}
	platSysV    = platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSysV}
	platKeen    = platform.Platform{Kind: platform.KindEntware, Hardware: platform.HardwareKeenetic, InitSystem: platform.InitEntware}
	platMerlin  = platform.Platform{Kind: platform.KindEntware, Hardware: platform.HardwareMerlin, InitSystem: platform.InitEntware}
	platEntware = platform.Platform{Kind: platform.KindEntware, InitSystem: platform.InitEntware}
)

func TestDetectBackendAndHook(t *testing.T) {
	cases := []struct {
		p    platform.Platform
		b    Backend
		hook Hook
	}{
		{platSystemd, BackendSystemd, HookNone},
		{platOpenRC, BackendOpenRC, HookNone},
		{platProcd, BackendProcd, HookNone},
		{platSysV, BackendSysV, HookNone},
		{platKeen, BackendEntware, HookKeenetic},
		{platMerlin, BackendEntware, HookMerlin},
		{platEntware, BackendEntware, HookNone},
		{platform.Platform{Hardware: platform.HardwareNetcraze, InitSystem: platform.InitEntware}, BackendEntware, HookKeenetic},
		// Хук только для Entware, даже если оборудование распознано.
		{platform.Platform{Hardware: platform.HardwareKeenetic, InitSystem: platform.InitSysV}, BackendSysV, HookNone},
		// Запасной выбор по виду платформы.
		{platform.Platform{Kind: platform.KindOpenWRT}, BackendProcd, HookNone},
		{platform.Platform{Kind: platform.KindEntware}, BackendEntware, HookNone},
		{platform.Platform{}, BackendSysV, HookNone},
	}
	for _, c := range cases {
		if got := DetectBackend(c.p); got != c.b {
			t.Errorf("%s: backend %s, ожидалось %s", c.p, got, c.b)
		}
		if got := DetectHook(c.p); got != c.hook {
			t.Errorf("%s: hook %q, ожидалось %q", c.p, got, c.hook)
		}
	}
}

func TestNewValidation(t *testing.T) {
	e := newEnv(t)
	if _, err := New(Config{Platform: platSystemd, Paths: e.p, Backend: "bogus"}); err == nil {
		t.Error("неизвестный backend")
	}
	if _, err := New(Config{Platform: platSystemd, Paths: e.p, ZatorBin: "/opt/z ator/zator"}); err == nil {
		t.Error("пробел в пути должен быть отвергнут")
	}
	if _, err := New(Config{Platform: platSystemd, Paths: e.p, FWHook: "/x\nExecStart=/bin/evil"}); err == nil {
		t.Error("перевод строки в пути должен быть отвергнут")
	}
	c, err := New(Config{Platform: platSystemd, Paths: e.p})
	if err != nil || c.Backend() != BackendSystemd {
		t.Fatal(c, err)
	}
	if err := c.Start(context.Background(), Unit("evil")); err == nil {
		t.Error("неизвестная служба")
	}
}

func TestRenderSystemd(t *testing.T) {
	e := newEnv(t)
	c := e.ctl(t, platSystemd, func(c *Config) { c.FWHook = "/opt/zapret2/fw.sh" }).(*manager)

	got, err := RenderSystemd(c.templateData(UnitZapret2))
	if err != nil {
		t.Fatal(err)
	}
	nfq := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "nfq2", "nfqws2"))
	args := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "nfqws2.args"))
	zbin := filepath.ToSlash(filepath.Join(e.p.BinDir, "zator"))
	for _, want := range []string{
		"[Unit]", "Description=zapret2 (nfqws2)", "[Service]", "Type=simple",
		"Environment=ZATOR_ROOT=" + filepath.ToSlash(e.p.ZatorRoot),
		"Environment=ZAPRET2_ROOT=" + filepath.ToSlash(e.p.ZapretRoot),
		"ExecStart=" + zbin + " exec-nfqws2 " + nfq + " " + args,
		"ExecStartPre=-/opt/zapret2/fw.sh start",
		"ExecStopPost=-/opt/zapret2/fw.sh stop",
		"ExecStartPre=-" + zbin + " wssize-hook start",
		"ExecStopPost=-" + zbin + " wssize-hook stop",
		"Restart=on-failure", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в unit нет %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "@"+args) {
		t.Errorf("systemd unit не должен запускать nfqws2 через @args (лимит 16 КБ):\n%s", got)
	}
	if strings.Contains(got, "{{") {
		t.Errorf("остались необработанные директивы:\n%s", got)
	}

	web, err := RenderSystemd(c.templateData(UnitWebUI))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(web, "ExecStart="+zbin+" webui") || strings.Contains(web, "ExecStartPre") || strings.Contains(web, "wssize-hook") {
		t.Errorf("unit webui:\n%s", web)
	}

	val, err := RenderSystemd(c.templateData(UnitValidator))
	if err != nil {
		t.Fatal(err)
	}
	vscript := filepath.ToSlash(filepath.Join(e.p.LuaDir, "strategy-validator.sh"))
	if !strings.Contains(val, "ExecStart="+vscript+" --daemon") || strings.Contains(val, "ExecStartPre") {
		t.Errorf("unit validator:\n%s", val)
	}
	if !strings.Contains(val, "strategy-validator") {
		t.Errorf("unit validator description:\n%s", val)
	}

	// Без FWHook строк Pre/Post нет.
	c2 := e.ctl(t, platSystemd).(*manager)
	plain, _ := RenderSystemd(c2.templateData(UnitZapret2))
	if strings.Contains(plain, "ExecStartPre") || strings.Contains(plain, "ExecStopPost") {
		t.Errorf("лишние Pre/Post:\n%s", plain)
	}
}

func TestRenderProcd(t *testing.T) {
	e := newEnv(t)
	c := e.ctl(t, platProcd, func(c *Config) { c.FWHook = "/opt/zapret2/fw.sh" }).(*manager)
	got, err := RenderProcd(c.templateData(UnitZapret2))
	if err != nil {
		t.Fatal(err)
	}
	args := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "nfqws2.args"))
	for _, want := range []string{
		"#!/bin/sh /etc/rc.common", "START=90", "USE_PROCD=1", "procd_open_instance",
		"procd_set_param command", "exec-nfqws2", "nfqws2", "nfqws2.args", "procd_set_param respawn", "procd_close_instance",
		"/opt/zapret2/fw.sh start", "wssize-hook start", "wssize-hook stop", "EXTRA_COMMANDS=\"restart_fw\"",
		"export ZATOR_ROOT ZAPRET2_ROOT",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в procd-скрипте нет %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "@"+args) {
		t.Errorf("procd-скрипт не должен запускать nfqws2 через @args (лимит 16 КБ):\n%s", got)
	}
	web, _ := RenderProcd(c.templateData(UnitWebUI))
	if !strings.Contains(web, "START=95") || strings.Contains(web, "fw.sh") || strings.Contains(web, "wssize-hook") || !strings.Contains(web, "webui") {
		t.Errorf("procd webui:\n%s", web)
	}
}

func TestRenderSysV(t *testing.T) {
	e := newEnv(t)
	c := e.ctl(t, platEntware, func(c *Config) { c.FWHook = "/opt/zapret2/fw.sh" }).(*manager)
	d := c.templateData(UnitZapret2)
	got, err := RenderSysV(d)
	if err != nil {
		t.Fatal(err)
	}
	args := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "nfqws2.args"))
	for _, want := range []string{
		"#!/bin/sh", "NAME=zapret2", "PIDFILE=/opt/var/run/zapret2.pid", "LOGFILE=", "nohup", "exec-nfqws2", "nfqws2", "nfqws2.args",
		"LOG_MAX_BYTES", "не запустился", "restart-fw) fw restart", "status)",
		"wssize-hook \"$1\"", "ZATOR_ROOT=",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в sysv-скрипте нет %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "@"+args) {
		t.Errorf("sysv-скрипт не должен запускать nfqws2 через @args (лимит 16 КБ):\n%s", got)
	}
	sysv := e.ctl(t, platSysV).(*manager)
	if got, _ := RenderSysV(sysv.templateData(UnitWebUI)); !strings.Contains(got, "PIDFILE=/var/run/zator-webui.pid") {
		t.Errorf("pidfile:\n%s", got)
	}
}

func TestServiceTemplatesPersistReleaseRepository(t *testing.T) {
	e := newEnv(t)
	t.Setenv("ZATOR_OWNER", "AloofLibra")
	t.Setenv("ZATOR_REPO", "zatorGOtest")
	c := e.ctl(t, platSystemd).(*manager)
	d := c.templateData(UnitWebUI)

	checks := []struct {
		name   string
		render func(TemplateData) (string, error)
	}{
		{"systemd", RenderSystemd},
		{"procd", RenderProcd},
		{"sysv", RenderSysV},
	}
	for _, check := range checks {
		got, err := check.render(d)
		if err != nil {
			t.Fatalf("%s: %v", check.name, err)
		}
		if !strings.Contains(got, "AloofLibra") || !strings.Contains(got, "zatorGOtest") {
			t.Errorf("%s unit does not persist release repository:\n%s", check.name, got)
		}
	}

	d.ReleaseOwner = "AloofLibra\nExecStart=/bin/evil"
	if got, _ := RenderSystemd(d); strings.Contains(got, "Environment=ZATOR_OWNER=") {
		t.Errorf("invalid release owner was written to the systemd unit:\n%s", got)
	}
}

func TestShellQuoting(t *testing.T) {
	cases := map[string]string{
		"plain":     "plain",
		"/a/b-c.d":  "/a/b-c.d",
		"@/x/y":     "@/x/y",
		"a b":       "'a b'",
		"it's":      `'it'\''s'`,
		"$(rm -rf)": "'$(rm -rf)'",
		"":          "''",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, ожидалось %s", in, got, want)
		}
	}
}

func TestRenderKeeneticHook(t *testing.T) {
	got, err := RenderKeeneticHook(TemplateData{InitScript: "/opt/zapret2/init.d/sysv/zapret2"})
	if err != nil {
		t.Fatal(err)
	}
	want := "#!/bin/sh\n" +
		"# ndm пересобирает firewall при сетевых событиях: возвращаем правила zapret2.\n" +
		"[ \"$table\" != \"mangle\" ] && [ \"$table\" != \"nat\" ] && exit 0\n" +
		"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n" +
		"export PATH\n" +
		"/opt/zapret2/init.d/sysv/zapret2 restart-fw\n" +
		"exit 0\n"
	if got != want {
		t.Errorf("хук:\n%s\nожидалось:\n%s", got, want)
	}
}

func TestRenderOutputHashes(t *testing.T) {
	wantHashes := map[string]string{
		"systemd-all":    "a22bc16cf486337de626d80bfd19a37d7ad4c87e2a69de560b9dd407e9c21616",
		"systemd-wssize": "72dfc2ff8178fd091d36e3ea997dcf05d2e225cddf7850a252abcd435bb39976",
		"systemd-fw":     "9fc66c47cc6767eb97e28aabc0093a8722d488e55cf6fdaa228cdbe3db2d99cb",
		"systemd-none":   "f098a898dcefd35f99a020645dab08d27ac5d31a10e178569d7bac788e837aac",
		"procd-all":      "a86ed72b3d8968f850999ef17e17f3795c51de7e9e6c45dc86cb41ca463ffc24",
		"procd-wssize":   "31c5f6d393287f23fad065581fd9b5674eb3e30ca13300fb970f7ba36aa8d01b",
		"procd-fw":       "b2fac92819d1c8105b6212e80f2c0045e97ba59091360dee1a49e6e3e0ca3cab",
		"procd-none":     "89199227dd6949b0c135f5b0deefecfb4f66543b8b40219714f05673faa66ac0",
		"sysv-all":       "32788959015c30f878ddb1c1f7914fb6f9f214e4a155301b282cc0e36ead6bac",
		"sysv-wssize":    "732ba21f94a08e2bc9989ee9f2ab73f926b21f0c7e41da50f44a46425e2d572e",
		"sysv-fw":        "d860d3a8561dcf18e12dd00aa5a20b9ef24e137c5433fd5f7da02a1a2afe9f77",
		"sysv-none":      "459f95084a0e5476a5e75d09e276d903eb6a68744ddb70c804058c16364edc57",
		"keenetic":       "255470adb071d29b475a14151a07cb31a3c6b158781f3d0432d877ddd10aa975",
	}
	all := TemplateData{
		Name: "zator'", Description: "desc & <text>",
		Command: []string{"/opt/bin/my zator", "arg's", "$(cmd)"},
		PIDFile: "/var/run/name.pid", LogFile: "/tmp/a log",
		InitScript: "/opt/init's", FWHook: "/opt/fw hook's", WssizeBin: "/opt/zator bin",
		ZatorRoot: "/opt/zator root", ZapretRoot: "/opt/zapret2", Path: "/usr/bin:/bin", Start: 90,
	}
	noHooks := all
	noHooks.FWHook, noHooks.WssizeBin = "", ""
	wssizeOnly := all
	wssizeOnly.FWHook = ""
	fwOnly := all
	fwOnly.WssizeBin = ""
	renders := []struct {
		name   string
		data   TemplateData
		render func(TemplateData) (string, error)
	}{
		{"systemd-all", all, RenderSystemd}, {"systemd-wssize", wssizeOnly, RenderSystemd},
		{"systemd-fw", fwOnly, RenderSystemd}, {"systemd-none", noHooks, RenderSystemd},
		{"procd-all", all, RenderProcd}, {"procd-wssize", wssizeOnly, RenderProcd},
		{"procd-fw", fwOnly, RenderProcd}, {"procd-none", noHooks, RenderProcd},
		{"sysv-all", all, RenderSysV}, {"sysv-wssize", wssizeOnly, RenderSysV},
		{"sysv-fw", fwOnly, RenderSysV}, {"sysv-none", noHooks, RenderSysV},
		{"keenetic", all, RenderKeeneticHook},
	}
	for _, tc := range renders {
		got, err := tc.render(tc.data)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if hash := fmt.Sprintf("%x", sha256.Sum256([]byte(got))); hash != wantHashes[tc.name] {
			t.Errorf("%s output changed: %s", tc.name, hash)
		}
	}
}

func TestHookLines(t *testing.T) {
	line := MerlinHookLine("/opt/zapret2/init.d/sysv/zapret2")
	if line != "/opt/zapret2/init.d/sysv/zapret2 restart-fw" {
		t.Fatal(line)
	}
	c := AddHookLine("", line)
	if c != "#!/bin/sh\n"+line+"\n" {
		t.Fatalf("%q", c)
	}
	if again := AddHookLine(c, line); again != c {
		t.Fatalf("повторное добавление изменило файл: %q", again)
	}
	if got := AddHookLine("#!/bin/sh\necho hi", line); got != "#!/bin/sh\necho hi\n"+line+"\n" {
		t.Fatalf("%q", got)
	}
	if got := RemoveHookLine(c, line); got != "#!/bin/sh\n" {
		t.Fatalf("%q", got)
	}
	if got := RemoveHookLine("a\nb\n", line); got != "a\nb\n" {
		t.Fatalf("%q", got)
	}
}

func TestSystemdInstallControlUninstall(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platSystemd)

	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(e.root, "etc", "systemd", "system", "zapret2.service")
	if got := readFile(t, unit); got != "[Service]\nExecStart=/opt/zapret2/init.d/sysv/zapret2 start\n" {
		t.Fatalf("не установлен upstream unit: %q", got)
	}
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"start", "stop", "restart"} {
		var err error
		switch f {
		case "start":
			err = c.Start(ctx, UnitZapret2)
		case "stop":
			err = c.Stop(ctx, UnitZapret2)
		case "restart":
			err = c.Restart(ctx, UnitWebUI)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"systemctl daemon-reload", "systemctl enable zapret2.service",
		"systemctl daemon-reload", "systemctl enable zator-webui.service",
		"systemctl start zapret2.service", "systemctl stop zapret2.service",
		"systemctl restart zator-webui.service",
	}
	if !reflect.DeepEqual(e.runner.calls, want) {
		t.Fatalf("вызовы:\n%v\nожидалось:\n%v", e.runner.calls, want)
	}

	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Fatal("unit не удалён")
	}
}

func TestSystemdControlErrorIncludesOutput(t *testing.T) {
	e := newEnv(t)
	e.runner.resp = func(string, []string) ([]byte, error) {
		return []byte("Unit not found.\n"), errors.New("exit status 5")
	}
	err := e.ctl(t, platSystemd).Start(context.Background(), UnitZapret2)
	if err == nil || !strings.Contains(err.Error(), "Unit not found.") {
		t.Fatalf("получено %v", err)
	}
}

func TestUninstallPreservesServiceFilesWhenStopOrDisableFails(t *testing.T) {
	tests := []struct {
		name     string
		platform platform.Platform
		unit     Unit
		file     string
		fails    func(string, []string) bool
	}{
		{
			name:     "systemd disable-now",
			platform: platSystemd, unit: UnitWebUI,
			file: filepath.Join("etc", "systemd", "system", "zator-webui.service"),
			fails: func(name string, args []string) bool {
				return name == "systemctl" && len(args) > 0 && args[0] == "disable"
			},
		},
		{
			name:     "procd stop",
			platform: platProcd, unit: UnitWebUI,
			file: filepath.Join("etc", "init.d", "zator-webui"),
			fails: func(name string, args []string) bool {
				return name == "/etc/init.d/zator-webui" && len(args) > 0 && args[0] == "stop"
			},
		},
		{
			name:     "sysv stop",
			platform: platSysV, unit: UnitWebUI,
			file: filepath.Join("etc", "init.d", "zator-webui"),
			fails: func(name string, args []string) bool {
				return name == "/etc/init.d/zator-webui" && len(args) > 0 && args[0] == "stop"
			},
		},
		{
			name:     "entware stop",
			platform: platKeen, unit: UnitWebUI,
			file: filepath.Join("opt", "etc", "init.d", "S92zator-webui"),
			fails: func(name string, args []string) bool {
				return strings.HasSuffix(name, "S92zator-webui") && len(args) > 0 && args[0] == "stop"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			c := e.ctl(t, tt.platform)
			if err := c.Install(ctx, tt.unit); err != nil {
				t.Fatal(err)
			}
			e.runner.resp = func(name string, args []string) ([]byte, error) {
				if tt.fails(name, args) {
					return []byte("stop/disable rejected"), errors.New("exit status 1")
				}
				return nil, nil
			}
			if err := c.Uninstall(ctx, tt.unit); err == nil {
				t.Fatal("expected uninstall error")
			}
			if _, err := os.Stat(filepath.Join(e.root, tt.file)); err != nil {
				t.Fatalf("service file removed despite failed stop/disable: %v", err)
			}
		})
	}
}

func TestSysVUninstallPreservesScriptWhenDisableFails(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platSysV)
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}
	e.runner.resp = func(name string, args []string) ([]byte, error) {
		if name == "update-rc.d" || name == "chkconfig" {
			return []byte("disable rejected"), errors.New("exit status 1")
		}
		return nil, nil
	}
	if err := c.Uninstall(ctx, UnitWebUI); err == nil {
		t.Fatal("expected disable failure")
	}
	if _, err := os.Stat(filepath.Join(e.root, "etc", "init.d", "zator-webui")); err != nil {
		t.Fatalf("init script removed despite failed disable: %v", err)
	}
}

func TestProcdInstallControl(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platProcd)
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(e.root, "etc", "init.d", "zapret2")
	if !strings.HasPrefix(readFile(t, script), "#!/bin/sh /etc/rc.common") {
		t.Fatal("init-скрипт не записан")
	}
	if os.PathSeparator == '/' {
		st, _ := os.Stat(script)
		if st.Mode()&0o111 == 0 {
			t.Error("скрипт не исполняемый")
		}
	}
	c.Restart(ctx, UnitZapret2)
	c.Stop(ctx, UnitWebUI)
	want := []string{
		"/etc/init.d/zapret2 enable",
		"/etc/init.d/zapret2 restart",
		"/etc/init.d/zator-webui stop",
	}
	if !reflect.DeepEqual(e.runner.calls, want) {
		t.Fatalf("вызовы: %v", e.runner.calls)
	}
	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Fatal("скрипт не удалён")
	}
}

func TestSysVInstall(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platSysV)
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, filepath.Join(e.root, "etc", "init.d", "zator-webui")), "webui") {
		t.Fatal("скрипт не записан")
	}
	if e.runner.calls[0] != "update-rc.d zator-webui defaults" {
		t.Fatalf("вызовы: %v", e.runner.calls)
	}
	c.Start(ctx, UnitWebUI)
	if last := e.runner.calls[len(e.runner.calls)-1]; last != "/etc/init.d/zator-webui start" {
		t.Fatal(last)
	}
}

func TestEntwareKeeneticInstall(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platKeen)
	if c.Hook() != HookKeenetic || c.Backend() != BackendEntware {
		t.Fatal(c.Backend(), c.Hook())
	}
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2")
	body := readFile(t, script)
	if body != "#!/bin/sh\n# upstream-sysv\n" {
		t.Errorf("установлен не upstream init:\n%s", body)
	}
	// Повторная установка не должна затирать существующий init.
	marker := "#!/bin/sh\n# upstream-keep\nstart(){ :; }\n"
	if err := os.WriteFile(script, []byte(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, script); got != marker {
		t.Fatalf("init zapret2 перезаписан:\n%s", got)
	}
	body = marker
	// S90-симлинк (или копия) указывает на init-скрипт.
	link := filepath.Join(e.root, "opt", "etc", "init.d", "S90-zapret2")
	if got := readFile(t, link); got != body {
		t.Error("S90-zapret2 не соответствует init-скрипту")
	}
	if target, err := os.Readlink(link); err == nil && target != script {
		t.Errorf("S90 указывает на %s", target)
	}
	hook := readFile(t, filepath.Join(e.root, "opt", "etc", "ndm", "netfilter.d", "000-zapret2.sh"))
	if !strings.Contains(hook, filepath.ToSlash(script)+" restart-fw") {
		t.Errorf("ndm-хук:\n%s", hook)
	}
	if !strings.Contains(readFile(t, filepath.Join(e.root, "opt", "etc", "init.d", "S92zator-webui")), "webui") {
		t.Error("S92zator-webui не записан")
	}

	if err := c.Restart(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if last := e.runner.calls[len(e.runner.calls)-1]; last != filepath.ToSlash(script)+" restart" {
		t.Fatal(last)
	}

	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	// Upstream init в zapret2/ оставляем; снимаем только S90/ndm-хуки zator.
	if _, err := os.Stat(script); err != nil {
		t.Errorf("upstream init удалён: %v", err)
	}
	for _, p := range []string{link, filepath.Join(e.root, "opt", "etc", "ndm", "netfilter.d", "000-zapret2.sh")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("не удалён %s", p)
		}
	}
}

func TestEntwareRequiresUpstreamInit(t *testing.T) {
	e := newEnv(t)
	script := filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2")
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := e.ctl(t, platKeen).Install(context.Background(), UnitZapret2); err == nil || !strings.Contains(err.Error(), "upstream zapret2 init is required") {
		t.Fatalf("missing upstream init accepted: %v", err)
	}
}

func TestEntwareMerlinHook(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platMerlin)
	fwStart := filepath.Join(e.root, "jffs", "scripts", "firewall-start")
	os.MkdirAll(filepath.Dir(fwStart), 0o755)
	os.WriteFile(fwStart, []byte("#!/bin/sh\necho existing\n"), 0o755)

	for i := 0; i < 2; i++ { // идемпотентность
		if err := c.Install(ctx, UnitZapret2); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2"))
	got := readFile(t, fwStart)
	if got != "#!/bin/sh\necho existing\n"+script+" restart-fw\n" {
		t.Fatalf("firewall-start:\n%q", got)
	}
	if _, err := os.Stat(filepath.Join(e.root, "opt", "etc", "ndm")); !os.IsNotExist(err) {
		t.Error("ndm-хук не нужен на Merlin")
	}
	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, fwStart); got != "#!/bin/sh\necho existing\n" {
		t.Fatalf("после удаления:\n%q", got)
	}
}

func TestEntwareMerlinCreatesFirewallStart(t *testing.T) {
	e := newEnv(t)
	if err := e.ctl(t, platMerlin).Install(context.Background(), UnitZapret2); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, filepath.Join(e.root, "jffs", "scripts", "firewall-start"))
	if !strings.HasPrefix(got, "#!/bin/sh\n") || !strings.HasSuffix(got, " restart-fw\n") {
		t.Fatalf("%q", got)
	}
}

// ---------------------------------------------------------------- процессы

func TestStatusProcessAbsent(t *testing.T) {
	e := newEnv(t)
	e.addProc(t, "1", "systemd", "/sbin/init")
	e.addProc(t, "42", "bash", "bash")
	ctx := context.Background()

	for _, plat := range []platform.Platform{platSystemd, platProcd, platSysV, platKeen} {
		c := e.ctl(t, plat)
		for _, u := range Units() {
			st, err := c.Status(ctx, u)
			if err != nil {
				t.Fatalf("%s/%s: %v", plat, u, err)
			}
			if st.Running || len(st.PIDs) != 0 || st.Unit != u {
				t.Errorf("%s/%s: %+v", plat, u, st)
			}
		}
	}
	if len(e.runner.calls) != 0 {
		t.Errorf("при доступном procfs команды не нужны: %v", e.runner.calls)
	}
}

func TestStatusEmptyProcRoot(t *testing.T) {
	e := newEnv(t) // каталог proc пуст
	st, err := e.ctl(t, platSystemd).Status(context.Background(), UnitZapret2)
	if err != nil || st.Running {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestStatusProcessPresent(t *testing.T) {
	e := newEnv(t)
	e.addProc(t, "100", "nfqws2", "/opt/zapret2/nfq2/nfqws2", "@/opt/zapret2/nfqws2.args")
	e.addProc(t, "200", "zator", "/opt/zator/bin/zator", "webui")
	e.addProc(t, "300", "zator", "/opt/zator/bin/zator", "status") // не webui
	e.addProc(t, "abc", "nfqws2")                                  // не PID
	c := e.ctl(t, platSystemd)

	st, err := c.Status(context.Background(), UnitZapret2)
	if err != nil || !st.Running || !reflect.DeepEqual(st.PIDs, []int{100}) || st.Backend != BackendSystemd {
		t.Fatalf("%+v %v", st, err)
	}
	st, err = c.Status(context.Background(), UnitWebUI)
	if err != nil || !st.Running || !reflect.DeepEqual(st.PIDs, []int{200}) {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestStatusMatchesByCmdlineWhenCommDiffers(t *testing.T) {
	e := newEnv(t)
	e.addProc(t, "7", "renamed", "/usr/bin/nfqws2", "--qnum=200")
	st, _ := e.ctl(t, platSystemd).Status(context.Background(), UnitZapret2)
	if !st.Running {
		t.Fatalf("%+v", st)
	}
}

func TestStatusFallbackPidof(t *testing.T) {
	e := newEnv(t)
	missing := filepath.Join(e.root, "no-proc")
	e.runner.resp = func(name string, args []string) ([]byte, error) {
		if name == "pidof" && args[0] == "nfqws2" {
			return []byte("12 5\n"), nil
		}
		return nil, exitErr(t)
	}
	c := e.ctl(t, platSystemd, func(c *Config) { c.ProcRoot = missing })
	st, err := c.Status(context.Background(), UnitZapret2)
	if err != nil || !st.Running || !reflect.DeepEqual(st.PIDs, []int{5, 12}) {
		t.Fatalf("%+v %v", st, err)
	}
	// pidof вернул 1: процессов нет.
	st, err = c.Status(context.Background(), UnitWebUI)
	if err != nil || st.Running {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestStatusFallbackToBackendQuery(t *testing.T) {
	e := newEnv(t)
	missing := filepath.Join(e.root, "no-proc")
	notFound := &exec.Error{Name: "pidof", Err: exec.ErrNotFound}
	active := false
	e.runner.resp = func(name string, args []string) ([]byte, error) {
		if name == "pidof" {
			return nil, notFound
		}
		if name == "systemctl" && args[0] == "is-active" {
			if active {
				return nil, nil
			}
			return nil, exitErr(t)
		}
		return nil, nil
	}
	c := e.ctl(t, platSystemd, func(c *Config) { c.ProcRoot = missing })
	st, err := c.Status(context.Background(), UnitZapret2)
	if err != nil || st.Running {
		t.Fatalf("%+v %v", st, err)
	}
	active = true
	st, err = c.Status(context.Background(), UnitZapret2)
	if err != nil || !st.Running {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestIsNfqws2Running(t *testing.T) {
	// Не должно паниковать и не должно сообщать «запущен» на тестовой машине без nfqws2.
	if IsNfqws2Running() {
		t.Skip("на машине действительно запущен nfqws2")
	}
}

func TestMatchers(t *testing.T) {
	if !MatchNfqws2("nfqws2", nil) || !MatchNfqws2("x", []string{"/a/nfqws2"}) || MatchNfqws2("nfqws", []string{"/a/nfqws"}) {
		t.Error("MatchNfqws2")
	}
	if !MatchWebUI("", []string{"/opt/zator/bin/zator", "webui", "-port", "1"}) ||
		!MatchWebUI("", []string{"C:\\zator.exe", "serve"}) ||
		MatchWebUI("", []string{"/bin/zator"}) ||
		MatchWebUI("", []string{"/bin/other", "webui"}) {
		t.Error("MatchWebUI")
	}
	if !MatchValidator("strategy-validator.sh", nil) ||
		!MatchValidator("sh", []string{"/bin/sh", "/opt/zator/lua/strategy-validator.sh", "--daemon"}) ||
		MatchValidator("nfqws2", []string{"/opt/zapret2/nfq2/nfqws2", "--comment=strategy-validator.lua"}) ||
		MatchValidator("bash", []string{"bash", "-c", "echo"}) {
		t.Error("MatchValidator")
	}
}

func TestRenderOpenRCAndWrapper(t *testing.T) {
	e := newEnv(t)
	t.Setenv("ZATOR_OWNER", "AloofLibra")
	t.Setenv("ZATOR_REPO", "zatorGOtest")
	c := e.ctl(t, platOpenRC).(*manager)
	got, err := RenderOpenRC(c.templateData(UnitWebUI))
	if err != nil {
		t.Fatal(err)
	}
	zbin := filepath.ToSlash(filepath.Join(e.p.BinDir, "zator"))
	for _, want := range []string{
		"#!/sbin/openrc-run",
		"command=" + zbin,
		`command_args="webui"`,
		`command_background="yes"`,
		`pidfile="/run/${RC_SVCNAME}.pid"`,
		"output_log=",
		"error_log=",
		`LOG_MAX_BYTES="${Z2R_SERVICE_LOG_MAX:-262144}"`,
		`mv -f "$output_log" "$output_log.old"`,
		`PATH="${PATH:+$PATH:}"`,
		"ZATOR_OWNER=AloofLibra",
		"ZATOR_REPO=zatorGOtest",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderOpenRC missing %q:\n%s", want, got)
		}
	}
	noLogData := c.templateData(UnitWebUI)
	noLogData.LogFile = ""
	noLogScript, err := RenderOpenRC(noLogData)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(noLogScript, "LOG_MAX_BYTES") {
		t.Errorf("RenderOpenRC without LogFile must not rotate output_log:\n%s", noLogScript)
	}

	wrap, err := RenderOpenRCZapretWrapper("/opt/zapret2/init.d/sysv/zapret2")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#!/sbin/openrc-run",
		`extra_commands="restart_fw"`,
		"/opt/zapret2/init.d/sysv/zapret2 start",
		"/opt/zapret2/init.d/sysv/zapret2 stop",
		"/opt/zapret2/init.d/sysv/zapret2 status",
		"/opt/zapret2/init.d/sysv/zapret2 restart-fw",
	} {
		if !strings.Contains(wrap, want) {
			t.Errorf("RenderOpenRCZapretWrapper missing %q:\n%s", want, wrap)
		}
	}
	if _, err := RenderOpenRCZapretWrapper("/opt/bad;rm"); err == nil {
		t.Fatal("expected unsafe path rejection")
	}
}

func TestOpenRCActiveInstallControlUninstall(t *testing.T) {
	e := newEnv(t)
	softlevel := filepath.Join(e.root, "run", "openrc", "softlevel")
	if err := os.MkdirAll(filepath.Dir(softlevel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(softlevel, []byte("default\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	openrcInit := filepath.Join(e.p.ZapretRoot, "init.d", "openrc", "zapret2")
	openrcFn := filepath.Join(e.p.ZapretRoot, "init.d", "openrc", "functions")
	if err := os.MkdirAll(filepath.Dir(openrcInit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openrcInit, []byte("#!/sbin/openrc-run\n. \"$EXEDIR/functions\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openrcFn, []byte("# openrc functions\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	c := e.ctl(t, platOpenRC)
	if c.Backend() != BackendOpenRC {
		t.Fatalf("backend = %s", c.Backend())
	}
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}

	zapretDst := filepath.Join(e.root, "etc", "init.d", "zapret2")
	if runtime.GOOS != "windows" {
		target, err := os.Readlink(zapretDst)
		if err != nil || target != openrcInit {
			t.Fatalf("zapret2 symlink = %q (%v), want %q", target, err, openrcInit)
		}
	} else if !strings.Contains(readFile(t, zapretDst), "#!/sbin/openrc-run") {
		t.Fatalf("zapret2 script missing openrc-run shebang")
	}
	webuiDst := filepath.Join(e.root, "etc", "init.d", "zator-webui")
	if !strings.HasPrefix(readFile(t, webuiDst), "#!/sbin/openrc-run") {
		t.Fatalf("webui script must use openrc-run:\n%s", readFile(t, webuiDst))
	}

	want := []string{
		"rc-update add zapret2 default",
		"rc-update add zator-webui default",
		"rc-service zapret2 restart",
		"rc-service zator-webui stop",
	}
	if !reflect.DeepEqual(e.runner.calls, want) {
		t.Fatalf("calls = %v, want %v", e.runner.calls, want)
	}

	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(zapretDst); !os.IsNotExist(err) {
		t.Fatalf("zapret2 init still exists: %v", err)
	}
	// Оригинальный openrc/zapret2 в ZapretRoot должен остаться нетронутым.
	if _, err := os.Stat(openrcInit); err != nil {
		t.Fatalf("upstream openrc/zapret2 removed: %v", err)
	}
}

func TestOpenRCFallbackWrapperWhenNoUpstreamOpenRC(t *testing.T) {
	e := newEnv(t)
	softlevel := filepath.Join(e.root, "run", "openrc", "softlevel")
	if err := os.MkdirAll(filepath.Dir(softlevel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(softlevel, []byte("default\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := e.ctl(t, platOpenRC)
	if err := c.Install(context.Background(), UnitZapret2); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(e.root, "etc", "init.d", "zapret2")
	got := readFile(t, dst)
	sysvPath := filepath.ToSlash(filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2"))
	if !strings.HasPrefix(got, "#!/sbin/openrc-run") || !strings.Contains(got, sysvPath+" start") {
		t.Fatalf("expected OpenRC wrapper over sysv/zapret2, got:\n%s", got)
	}
}

func TestOpenRCContainerDirectFallback(t *testing.T) {
	e := newEnv(t) // без softlevel
	ctx := context.Background()
	c := e.ctl(t, platOpenRC)
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitWebUI); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, filepath.Join(e.root, "etc", "init.d", "zapret2")), "upstream-sysv") {
		t.Fatal("container mode should link sysv/zapret2")
	}
	if !strings.HasPrefix(readFile(t, filepath.Join(e.root, "etc", "init.d", "zator-webui")), "#!/bin/sh\n") {
		t.Fatal("container mode webui should use SysV POSIX script")
	}
	want := []string{"/etc/init.d/zapret2 restart"}
	if !reflect.DeepEqual(e.runner.calls, want) {
		t.Fatalf("container calls = %v, want %v", e.runner.calls, want)
	}
}

func TestWriteFileDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		probeDir := t.TempDir()
		if err := os.Symlink("target", filepath.Join(probeDir, "link")); err != nil {
			t.Skip("Windows symlink creation needs elevated privileges")
		}
	}
	e := newEnv(t)
	m := e.ctl(t, platOpenRC).(*manager)
	target := filepath.Join(e.root, "upstream-openrc-zapret2")
	link := filepath.Join(e.root, "etc", "init.d", "zapret2")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/sbin/openrc-run\nORIGINAL\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := m.writeFile(link, "#!/sbin/openrc-run\nWRAPPER\n", 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "#!/sbin/openrc-run\nORIGINAL\n" {
		t.Fatalf("writeFile followed symlink and corrupted target: %q", got)
	}
	if got := readFile(t, link); got != "#!/sbin/openrc-run\nWRAPPER\n" {
		t.Fatalf("writeFile did not write link path: %q", got)
	}
}

func TestSysVNativeZapretSymlinkAndIgnoreNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platSysV)
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(e.root, "etc", "init.d", "zapret2")
	src := filepath.Join(e.p.ZapretRoot, "init.d", "sysv", "zapret2")
	if runtime.GOOS != "windows" {
		target, err := os.Readlink(dst)
		if err != nil || target != src {
			t.Fatalf("sysv zapret2 link = %q (%v), want %q", target, err, src)
		}
	}
	// Когда update-rc.d и chkconfig отсутствуют (exec.ErrNotFound), uninstall не падает.
	e.runner.resp = func(name string, args []string) ([]byte, error) {
		if name == "update-rc.d" || name == "chkconfig" {
			return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return nil, nil
	}
	if err := c.Uninstall(ctx, UnitZapret2); err != nil {
		t.Fatalf("uninstall should succeed when update-rc.d/chkconfig are absent: %v", err)
	}
}

func TestProcdPreservesLocalAndCleansLinks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.ctl(t, platProcd)

	// 1. Локально изменённый скрипт без маркера zator сохраняется.
	localPath := filepath.Join(e.root, "etc", "init.d", "zapret2")
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	localBody := "#!/bin/sh /etc/rc.common\n# locally modified\nSTART=21\n"
	if err := os.WriteFile(localPath, []byte(localBody), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, localPath); got != localBody {
		t.Fatalf("local OpenWrt script overwritten: %q", got)
	}

	// 2. Скрипт с маркером "(создано zator)" заменяется на upstream и старые rc.d ссылки чистятся.
	if err := os.WriteFile(localPath, []byte("#!/bin/sh /etc/rc.common\n# zapret2 (создано zator)\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.Install(ctx, UnitZapret2); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, localPath); !strings.Contains(got, "# upstream-openwrt") {
		t.Fatalf("zator-generated script not replaced by upstream: %q", got)
	}

	if runtime.GOOS != "windows" {
		rcDir := filepath.Join(e.root, "etc", "rc.d")
		if err := os.MkdirAll(rcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(localPath, []byte("START=21\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"S90zapret2", "K89zapret2", "S21zapret2", "K10zapret2", "S90other"} {
			if err := os.Symlink("../init.d/zapret2", filepath.Join(rcDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := cleanupOpenWrtInitLinks(localPath, rcDir); err != nil {
			t.Fatal(err)
		}
		for _, stale := range []string{"S90zapret2", "K89zapret2"} {
			if _, err := os.Lstat(filepath.Join(rcDir, stale)); !os.IsNotExist(err) {
				t.Errorf("stale link %s remains: %v", stale, err)
			}
		}
		for _, keep := range []string{"S21zapret2", "K10zapret2", "S90other"} {
			if _, err := os.Lstat(filepath.Join(rcDir, keep)); err != nil {
				t.Errorf("expected link %s removed: %v", keep, err)
			}
		}
	}
}

func TestExecRunnerDoesNotHangOnInheritedFD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell background descriptor test requires Unix/Linux")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	out, err := ExecRunner().Run(ctx, sh, "-c", "sleep 5 >/dev/null & echo started; echo warn >&2")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ExecRunner failed: %v (output=%q)", err, string(out))
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("ExecRunner blocked on background child FD: elapsed=%v", elapsed)
	}
	text := string(out)
	if !strings.Contains(text, "started") || !strings.Contains(text, "warn") {
		t.Fatalf("unexpected ExecRunner output: %q", text)
	}
}

func TestExecRunnerErrorMissingBinary(t *testing.T) {
	_, err := ExecRunner().Run(context.Background(), "nonexistent-zator-cmd-xyz")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("got %v, want exec.ErrNotFound", err)
	}
}

func TestOpenRCInstallStopsLegacySysVBeforeOverwrite(t *testing.T) {
	e := newEnv(t)
	softlevel := filepath.Join(e.root, "run", "openrc", "softlevel")
	if err := os.MkdirAll(filepath.Dir(softlevel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(softlevel, []byte("default\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(e.root, "etc", "init.d", "zator-webui")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("#!/bin/sh\necho legacy\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := e.ctl(t, platOpenRC)
	if err := c.Install(context.Background(), UnitWebUI); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/etc/init.d/zator-webui stop",
		"rc-update add zator-webui default",
	}
	if !reflect.DeepEqual(e.runner.calls, want) {
		t.Fatalf("calls = %v, want %v", e.runner.calls, want)
	}
	if got := readFile(t, legacyPath); !strings.HasPrefix(got, "#!/sbin/openrc-run") {
		t.Fatalf("legacy script was not replaced with openrc-run:\n%s", got)
	}
}
