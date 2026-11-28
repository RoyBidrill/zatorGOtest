package sysprofile

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/AloofLibra/zator/internal/paths"
	"github.com/AloofLibra/zator/internal/platform"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMatrix(t *testing.T) {
	rootActive := t.TempDir()
	writeFile(t, filepath.Join(rootActive, "run", "openrc", "softlevel"), "default\n")

	rootEmpty := t.TempDir()

	cases := []struct {
		name         string
		plat         platform.Platform
		root         string
		wantName     string
		wantActiveRC bool
		wantInitMode InitMode
		wantUpstream string
		wantCtl      CmdSpec
	}{
		{
			name:         "systemd",
			plat:         platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSystemd},
			root:         rootEmpty,
			wantName:     "systemd",
			wantInitMode: InitModeCopy,
			wantUpstream: "init.d/systemd/zapret2.service",
			wantCtl:      CmdSpec{Name: "systemctl", Args: []string{"restart", "zapret2.service"}},
		},
		{
			name:         "openrc active",
			plat:         platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitOpenRC, OSID: "alpine"},
			root:         rootActive,
			wantName:     "openrc",
			wantActiveRC: true,
			wantInitMode: InitModeSymlink,
			wantUpstream: "init.d/openrc/zapret2",
			wantCtl:      CmdSpec{Name: "rc-service", Args: []string{"zapret2", "restart"}},
		},
		{
			name:         "openrc container direct",
			plat:         platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitOpenRC, OSID: "alpine"},
			root:         rootEmpty,
			wantName:     "openrc-direct",
			wantActiveRC: false,
			wantInitMode: InitModeSymlink,
			wantUpstream: "init.d/sysv/zapret2",
			wantCtl:      CmdSpec{Name: "/etc/init.d/zapret2", Args: []string{"restart"}},
		},
		{
			name:         "procd openwrt",
			plat:         platform.Platform{Kind: platform.KindOpenWRT, InitSystem: platform.InitProcd},
			root:         rootEmpty,
			wantName:     "procd",
			wantInitMode: InitModeSymlink,
			wantUpstream: "init.d/openwrt/zapret2",
			wantCtl:      CmdSpec{Name: "/etc/init.d/zapret2", Args: []string{"restart"}},
		},
		{
			name:         "entware",
			plat:         platform.Platform{Kind: platform.KindEntware, InitSystem: platform.InitEntware},
			root:         rootEmpty,
			wantName:     "entware",
			wantInitMode: InitModeInPlace,
			wantUpstream: "init.d/sysv/zapret2",
			wantCtl:      CmdSpec{Name: "/opt/zapret2/init.d/sysv/zapret2", Args: []string{"restart"}},
		},
		{
			name:         "sysv",
			plat:         platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSysV},
			root:         rootEmpty,
			wantName:     "sysv",
			wantInitMode: InitModeSymlink,
			wantUpstream: "init.d/sysv/zapret2",
			wantCtl:      CmdSpec{Name: "/etc/init.d/zapret2", Args: []string{"restart"}},
		},
	}

	p := paths.New("/opt/zator", "/opt/zapret2")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prof := Resolve(tc.plat, Options{Root: tc.root})
			if prof.Name() != tc.wantName {
				t.Fatalf("Name() = %q, want %q", prof.Name(), tc.wantName)
			}
			if prof.OpenRCActive() != tc.wantActiveRC {
				t.Fatalf("OpenRCActive() = %t, want %t", prof.OpenRCActive(), tc.wantActiveRC)
			}
			nat := prof.NativeZapret(p)
			if nat.Mode != tc.wantInitMode || nat.UpstreamRel != tc.wantUpstream {
				t.Fatalf("NativeZapret = %+v", nat)
			}
			gotCtl := prof.ControlCmd("zapret2", "restart", p)
			if !reflect.DeepEqual(gotCtl, tc.wantCtl) {
				t.Fatalf("ControlCmd = %+v, want %+v", gotCtl, tc.wantCtl)
			}
		})
	}
}

func TestOpenRCValidateAndFirewallReload(t *testing.T) {
	dir := t.TempDir()
	zr := filepath.Join(dir, "zapret2")
	p := paths.New(filepath.Join(dir, "zator"), zr)

	root := filepath.Join(dir, "root")
	writeFile(t, filepath.Join(root, "run", "openrc", "softlevel"), "default\n")
	writeFile(t, filepath.Join(zr, "init.d", "sysv", "functions"), "# sysv fn\n")
	writeFile(t, filepath.Join(zr, "init.d", "sysv", "zapret2"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(zr, "init.d", "openrc", "zapret2"), "#!/sbin/openrc-run\n. \"$EXEDIR/functions\"\n")

	prof := Resolve(platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitOpenRC}, Options{Root: root})

	// Нет openrc/functions при ссылке на EXEDIR/functions -> ValidateUpstreamZapret == false.
	if prof.ValidateUpstreamZapret(zr) {
		t.Fatal("expected invalid when openrc/functions is missing")
	}

	// Добавляем functions -> валидно.
	writeFile(t, filepath.Join(zr, "init.d", "openrc", "functions"), "# fn\n")
	if !prof.ValidateUpstreamZapret(zr) {
		t.Fatal("expected valid openrc layout")
	}

	// Перезаписанный SysV-скриптом openrc/zapret2 (как в v0.1.43-test15) -> false.
	writeFile(t, filepath.Join(zr, "init.d", "openrc", "zapret2"), "#!/bin/sh\n. \"$EXEDIR/functions\"\n")
	if prof.ValidateUpstreamZapret(zr) {
		t.Fatal("expected invalid when openrc/zapret2 has #!/bin/sh")
	}

	// FirewallReloadCmd всегда выбирает sysv/zapret2, а не openrc-run в /etc/init.d/zapret2.
	writeFile(t, filepath.Join(root, "etc", "init.d", "zapret2"), "#!/sbin/openrc-run\n")
	cmd, ok := prof.FirewallReloadCmd(p, root)
	if !ok || cmd.Name != filepath.Join(zr, "init.d", "sysv", "zapret2") || !reflect.DeepEqual(cmd.Args, []string{"restart-fw"}) {
		t.Fatalf("FirewallReloadCmd = %+v, ok=%t", cmd, ok)
	}
}

func TestOpenRCCustomDFlavorsSkipsSymlink(t *testing.T) {
	zr := t.TempDir()
	writeFile(t, filepath.Join(zr, "init.d", "sysv", "custom.d", ".keep"), "")

	prof := openrcProfile{active: true}
	if got := prof.CustomDFlavors(zr); !reflect.DeepEqual(got, []string{"sysv"}) {
		t.Fatalf("without openrc/custom.d: %v", got)
	}

	realDir := filepath.Join(zr, "init.d", "openrc", "custom.d")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := prof.CustomDFlavors(zr); !reflect.DeepEqual(got, []string{"sysv", "openrc"}) {
		t.Fatalf("with real openrc/custom.d: %v", got)
	}

	if runtime.GOOS == "windows" {
		return
	}
	_ = os.RemoveAll(realDir)
	if err := os.Symlink("../sysv/custom.d", realDir); err != nil {
		t.Fatal(err)
	}
	if got := prof.CustomDFlavors(zr); !reflect.DeepEqual(got, []string{"sysv"}) {
		t.Fatalf("with symlink openrc/custom.d: %v", got)
	}
}

func TestDepsAndPkgSpecs(t *testing.T) {
	openrc := Resolve(platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitOpenRC}, Options{})
	nftDeps := openrc.RequiredDeps(platform.FWNftables)
	if len(nftDeps.Binaries) != 1 || nftDeps.Binaries[0].Name != "nft" || !nftDeps.Binaries[0].Critical {
		t.Fatalf("unexpected nft binaries: %+v", nftDeps.Binaries)
	}
	if !nftDeps.PreferModprobe || !reflect.DeepEqual(nftDeps.Packages, []string{"nftables"}) {
		t.Fatalf("unexpected nft deps: %+v", nftDeps)
	}
	iptDeps := openrc.RequiredDeps(platform.FWIptables)
	if len(iptDeps.Binaries) != 2 || iptDeps.Binaries[0].Name != "iptables" || iptDeps.Binaries[1].Name != "ipset" {
		t.Fatalf("unexpected ipt binaries: %+v", iptDeps.Binaries)
	}
	apkCmd := openrc.PkgInstallCmd("apk", "/sbin/apk", []string{"nftables"})
	if apkCmd.Name != "/sbin/apk" || !reflect.DeepEqual(apkCmd.Args, []string{"add", "--no-cache", "nftables"}) {
		t.Fatalf("apk cmd = %+v", apkCmd)
	}

	// Модули: preferModprobe ставит modprobe первым, insmod запасным.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib", "modules", "6.6.0", "nft_queue.ko"), "ko")
	cmds := openrc.ModuleLoadCmds("nft_queue", "6.6.0", root, func(b string) string {
		if b == "modprobe" || b == "insmod" {
			return "/sbin/" + b
		}
		return ""
	})
	if len(cmds) != 2 || cmds[0].Name != "/sbin/modprobe" || cmds[1].Name != "/sbin/insmod" {
		t.Fatalf("ModuleLoadCmds = %+v", cmds)
	}

	// Entware никогда не использует modprobe и opkg без -y.
	ent := Resolve(platform.Platform{Kind: platform.KindEntware, InitSystem: platform.InitEntware}, Options{})
	entCmds := ent.ModuleLoadCmds("nft_queue", "6.6.0", root, func(b string) string { return "/opt/sbin/" + b })
	if len(entCmds) != 1 || entCmds[0].Name != "/opt/sbin/insmod" {
		t.Fatalf("entware ModuleLoadCmds = %+v", entCmds)
	}
	opkgCmd := ent.PkgInstallCmd("opkg", "/opt/bin/opkg", []string{"iptables"})
	if !reflect.DeepEqual(opkgCmd.Args, []string{"install", "iptables"}) {
		t.Fatalf("opkg cmd = %+v", opkgCmd)
	}

	// OpenWrt procd поддерживает как opkg (старые), так и apk (25.12+).
	procd := Resolve(platform.Platform{Kind: platform.KindOpenWRT, InitSystem: platform.InitProcd}, Options{})
	if !reflect.DeepEqual(procd.PkgManagerOrder(), []string{"opkg", "apk"}) {
		t.Fatalf("procd PkgManagerOrder = %v", procd.PkgManagerOrder())
	}
	if upd, ok := procd.PkgUpdateCmd("opkg", "/bin/opkg"); !ok || upd.Name != "/bin/opkg" || !reflect.DeepEqual(upd.Args, []string{"update"}) {
		t.Fatalf("procd opkg update = %+v, %t", upd, ok)
	}
	if _, ok := procd.PkgUpdateCmd("apk", "/usr/bin/apk"); ok {
		t.Fatal("procd apk must not need separate update command")
	}
	if cmd := procd.PkgInstallCmd("apk", "/usr/bin/apk", []string{"nftables"}); !reflect.DeepEqual(cmd.Args, []string{"add", "--no-cache", "nftables"}) {
		t.Fatalf("procd apk install = %+v", cmd)
	}

	// VPS systemd/sysv поддерживают apt-get, dnf, yum, pacman и apk.
	sysd := Resolve(platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSystemd}, Options{})
	sysv := Resolve(platform.Platform{Kind: platform.KindVPS, InitSystem: platform.InitSysV}, Options{})
	wantOrder := []string{"apt-get", "dnf", "yum", "pacman", "apk"}
	if !reflect.DeepEqual(sysd.PkgManagerOrder(), wantOrder) || !reflect.DeepEqual(sysv.PkgManagerOrder(), wantOrder) {
		t.Fatalf("VPS PkgManagerOrder = systemd:%v sysv:%v", sysd.PkgManagerOrder(), sysv.PkgManagerOrder())
	}
	if cmd := sysd.PkgInstallCmd("pacman", "/usr/bin/pacman", []string{"nftables"}); !reflect.DeepEqual(cmd.Args, []string{"-S", "--noconfirm", "--needed", "nftables"}) {
		t.Fatalf("pacman cmd = %+v", cmd)
	}
	if cmd := sysd.PkgInstallCmd("dnf", "/usr/bin/dnf", []string{"iptables", "ipset"}); !reflect.DeepEqual(cmd.Args, []string{"install", "-y", "iptables", "ipset"}) {
		t.Fatalf("dnf cmd = %+v", cmd)
	}
	if cmd := sysd.PkgInstallCmd("yum", "/usr/bin/yum", []string{"nftables"}); !reflect.DeepEqual(cmd.Args, []string{"install", "-y", "nftables"}) {
		t.Fatalf("yum cmd = %+v", cmd)
	}
}
