package sysprofile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AloofLibra/zator/internal/paths"
	"github.com/AloofLibra/zator/internal/platform"
)

const (
	systemdDir     = "/etc/systemd/system"
	initDir        = "/etc/init.d"
	entwareInitDir = "/opt/etc/init.d"
	unitZapret2    = "zapret2"
)

// Resolve выбирает системный профиль по результату определения платформы.
func Resolve(plat platform.Platform, opts Options) Profile {
	return ResolveForInit(plat.InitSystem, plat.Kind, opts)
}

// ResolveForInit выбирает системный профиль по системе инициализации с запасным
// выбором по виду платформы (когда InitSystem не задан).
func ResolveForInit(init platform.InitSystem, kind platform.Kind, opts Options) Profile {
	switch init {
	case platform.InitSystemd:
		return systemdProfile{}
	case platform.InitOpenRC:
		return openrcProfile{active: platform.HasOpenRCSoftlevel(opts.root())}
	case platform.InitProcd:
		return procdProfile{}
	case platform.InitEntware:
		return entwareProfile{}
	case platform.InitSysV:
		return sysvProfile{}
	}
	switch kind {
	case platform.KindOpenWRT:
		return procdProfile{}
	case platform.KindEntware:
		return entwareProfile{}
	}
	return sysvProfile{}
}

// ---------------------------------------------------------------- systemd

type systemdProfile struct{}

func (systemdProfile) Name() string                   { return "systemd" }
func (systemdProfile) InitSystem() platform.InitSystem { return platform.InitSystemd }
func (systemdProfile) OpenRCActive() bool             { return false }

func (systemdProfile) NativeZapret(_ paths.Paths) NativeZapretSpec {
	return NativeZapretSpec{
		UpstreamRel: "init.d/systemd/zapret2.service",
		SystemPath:  systemdDir + "/zapret2.service",
		Mode:        InitModeCopy,
	}
}

func (systemdProfile) ValidateUpstreamZapret(zapretRoot string) bool {
	return regularFile(filepath.Join(zapretRoot, "init.d", "systemd", "zapret2.service")) &&
		regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "zapret2")) &&
		regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "functions"))
}

func (systemdProfile) ServiceScriptPath(unit string, _ paths.Paths) string {
	return systemdDir + "/" + unit + ".service"
}

func (systemdProfile) ControlCmd(unit, action string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: "systemctl", Args: []string{action, unit + ".service"}}
}

func (systemdProfile) QueryCmd(unit string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: "systemctl", Args: []string{"is-active", "--quiet", unit + ".service"}}
}

func (systemdProfile) EnableOps(unit string, _ paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: "systemctl", Args: []string{"daemon-reload"}}},
		{Primary: CmdSpec{Name: "systemctl", Args: []string{"enable", unit + ".service"}}},
	}
}

func (systemdProfile) DisableOps(unit string, _ paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: "systemctl", Args: []string{"disable", "--now", unit + ".service"}}},
	}
}

func (systemdProfile) PostUninstallOps(_ string, _ paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: "systemctl", Args: []string{"daemon-reload"}}},
	}
}

func (systemdProfile) FirewallReloadCmd(p paths.Paths, root string) (CmdSpec, bool) {
	return firstExistingCmd([]string{
		filepath.Join(p.ZapretRoot, "init.d", "sysv", unitZapret2),
		sysPath(root, initDir+"/"+unitZapret2),
	}, "restart-fw")
}

func (systemdProfile) CustomDFlavors(_ string) []string { return []string{"sysv"} }

func (systemdProfile) PkgManagerOrder() []string { return []string{"apt-get", "dnf", "yum", "pacman", "apk"} }

func (systemdProfile) PkgUpdateCmd(_, _ string) (CmdSpec, bool) { return CmdSpec{}, false }

func (systemdProfile) PkgInstallCmd(mgr, binPath string, pkgs []string) CmdSpec {
	return linuxPkgInstallCmd(mgr, binPath, pkgs)
}

func (systemdProfile) RequiredDeps(fw platform.FWType) DepsSpec { return vpsDeps(fw) }

func (systemdProfile) ModuleLoadCmds(modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	return moduleLoadCmds(true, modName, kernelRel, root, findBin)
}

// ---------------------------------------------------------------- OpenRC (Alpine / Gentoo)

type openrcProfile struct {
	active bool
}

func (p openrcProfile) Name() string {
	if p.active {
		return "openrc"
	}
	return "openrc-direct"
}

func (openrcProfile) InitSystem() platform.InitSystem { return platform.InitOpenRC }
func (p openrcProfile) OpenRCActive() bool             { return p.active }

func (p openrcProfile) NativeZapret(_ paths.Paths) NativeZapretSpec {
	if p.active {
		return NativeZapretSpec{
			UpstreamRel:   "init.d/openrc/zapret2",
			FallbackRel:   "init.d/sysv/zapret2",
			SystemPath:    initDir + "/" + unitZapret2,
			Mode:          InitModeSymlink,
			OpenRCWrapper: true,
		}
	}
	return NativeZapretSpec{
		UpstreamRel: "init.d/sysv/zapret2",
		SystemPath:  initDir + "/" + unitZapret2,
		Mode:        InitModeSymlink,
	}
}

func (openrcProfile) ValidateUpstreamZapret(zapretRoot string) bool {
	if !regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "functions")) ||
		!regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "zapret2")) {
		return false
	}
	openrcInit := filepath.Join(zapretRoot, "init.d", "openrc", "zapret2")
	if _, err := os.Lstat(openrcInit); err == nil {
		return ValidOpenRCZapretScript(zapretRoot, openrcInit)
	} else if !os.IsNotExist(err) {
		return false
	}
	return true
}

// ValidOpenRCZapretScript проверяет, что init.d/openrc/zapret2 — настоящий
// openrc-run скрипт (не перезаписан SysV-копией) и его ссылка functions цела.
func ValidOpenRCZapretScript(zapretRoot, scriptPath string) bool {
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return false
	}
	text := string(data)
	if !strings.HasPrefix(text, "#!/sbin/openrc-run") {
		return false
	}
	if strings.Contains(text, "EXEDIR/functions") || strings.Contains(text, "openrc/functions") {
		if !regularFile(filepath.Join(zapretRoot, "init.d", "openrc", "functions")) {
			return false
		}
	}
	return true
}

func (openrcProfile) ServiceScriptPath(unit string, _ paths.Paths) string {
	return initDir + "/" + unit
}

func (p openrcProfile) ControlCmd(unit, action string, _ paths.Paths) CmdSpec {
	if p.active {
		return CmdSpec{Name: "rc-service", Args: []string{unit, action}}
	}
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{action}}
}

func (p openrcProfile) QueryCmd(unit string, _ paths.Paths) CmdSpec {
	if p.active {
		return CmdSpec{Name: "rc-service", Args: []string{unit, "status"}}
	}
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{"status"}}
}

func (p openrcProfile) EnableOps(unit string, _ paths.Paths) []CommandOp {
	if !p.active {
		return nil
	}
	return []CommandOp{
		{Primary: CmdSpec{Name: "rc-update", Args: []string{"add", unit, "default"}}},
	}
}

func (p openrcProfile) DisableOps(unit string, _ paths.Paths) []CommandOp {
	if !p.active {
		return []CommandOp{
			{Primary: CmdSpec{Name: initDir + "/" + unit, Args: []string{"stop"}}},
		}
	}
	return []CommandOp{
		{Primary: CmdSpec{Name: "rc-service", Args: []string{unit, "stop"}}},
		{Primary: CmdSpec{Name: "rc-update", Args: []string{"del", unit, "default"}}, BestEffort: true},
	}
}

func (openrcProfile) PostUninstallOps(_ string, _ paths.Paths) []CommandOp { return nil }

func (p openrcProfile) FirewallReloadCmd(pa paths.Paths, root string) (CmdSpec, bool) {
	cands := []string{filepath.Join(pa.ZapretRoot, "init.d", "sysv", unitZapret2)}
	if !p.active {
		cands = append(cands, sysPath(root, initDir+"/"+unitZapret2))
	}
	return firstExistingCmd(cands, "restart-fw")
}

func (openrcProfile) CustomDFlavors(zapretRoot string) []string {
	openrcCustom := filepath.Join(zapretRoot, "init.d", "openrc", "custom.d")
	if st, err := os.Lstat(openrcCustom); err == nil && st.Mode()&os.ModeSymlink == 0 && st.IsDir() {
		return []string{"sysv", "openrc"}
	}
	return []string{"sysv"}
}

func (openrcProfile) PkgManagerOrder() []string { return []string{"apk", "apt-get"} }

func (openrcProfile) PkgUpdateCmd(_, _ string) (CmdSpec, bool) { return CmdSpec{}, false }

func (openrcProfile) PkgInstallCmd(mgr, binPath string, pkgs []string) CmdSpec {
	return linuxPkgInstallCmd(mgr, binPath, pkgs)
}

func (openrcProfile) RequiredDeps(fw platform.FWType) DepsSpec { return vpsDeps(fw) }

func (openrcProfile) ModuleLoadCmds(modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	return moduleLoadCmds(true, modName, kernelRel, root, findBin)
}

// ---------------------------------------------------------------- procd (OpenWrt)

type procdProfile struct{}

func (procdProfile) Name() string                   { return "procd" }
func (procdProfile) InitSystem() platform.InitSystem { return platform.InitProcd }
func (procdProfile) OpenRCActive() bool             { return false }

func (procdProfile) NativeZapret(_ paths.Paths) NativeZapretSpec {
	return NativeZapretSpec{
		UpstreamRel: "init.d/openwrt/zapret2",
		SystemPath:  initDir + "/" + unitZapret2,
		Mode:        InitModeSymlink,
	}
}

func (procdProfile) ValidateUpstreamZapret(zapretRoot string) bool {
	if !regularFile(filepath.Join(zapretRoot, "init.d", "openwrt", unitZapret2)) {
		return false
	}
	return regularFile(filepath.Join(zapretRoot, "init.d", "openwrt", "functions")) ||
		regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "functions"))
}

func (procdProfile) ServiceScriptPath(unit string, _ paths.Paths) string {
	return initDir + "/" + unit
}

func (procdProfile) ControlCmd(unit, action string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{action}}
}

func (procdProfile) QueryCmd(unit string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{"running"}}
}

func (procdProfile) EnableOps(unit string, _ paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: initDir + "/" + unit, Args: []string{"enable"}}},
	}
}

func (procdProfile) DisableOps(unit string, _ paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: initDir + "/" + unit, Args: []string{"stop"}}},
		{Primary: CmdSpec{Name: initDir + "/" + unit, Args: []string{"disable"}}},
	}
}

func (procdProfile) PostUninstallOps(_ string, _ paths.Paths) []CommandOp { return nil }

func (procdProfile) FirewallReloadCmd(p paths.Paths, root string) (CmdSpec, bool) {
	return firstExistingCmd([]string{
		sysPath(root, initDir+"/"+unitZapret2),
		filepath.Join(p.ZapretRoot, "init.d", "openwrt", unitZapret2),
	}, "restart-fw")
}

func (procdProfile) CustomDFlavors(_ string) []string { return []string{"openwrt"} }

func (procdProfile) PkgManagerOrder() []string { return []string{"opkg", "apk"} }

func (procdProfile) PkgUpdateCmd(mgr, binPath string) (CmdSpec, bool) {
	if mgr == "apk" {
		return CmdSpec{}, false
	}
	return CmdSpec{Name: binPath, Args: []string{"update"}}, true
}

func (procdProfile) PkgInstallCmd(mgr, binPath string, pkgs []string) CmdSpec {
	if mgr == "apk" {
		return linuxPkgInstallCmd(mgr, binPath, pkgs)
	}
	return CmdSpec{Name: binPath, Args: append([]string{"install"}, pkgs...)}
}

func (procdProfile) RequiredDeps(fw platform.FWType) DepsSpec {
	bins := make([]DepCheck, 0, 3)
	if fw == platform.FWNftables {
		bins = append(bins, DepCheck{Name: "nft", Critical: true})
	}
	bins = append(bins,
		DepCheck{Name: "iptables", Critical: fw != platform.FWNftables},
		DepCheck{Name: "ipset", Critical: fw != platform.FWNftables},
	)
	pkgs := []string{"ipset", "iptables-mod-conntrack-extra", "kmod-ipt-conntrack-extra", "kmod-ipt-ipset"}
	mods := make([]DepCheck, 0, 4)
	if fw == platform.FWNftables {
		pkgs = append(pkgs, "nftables", "kmod-nfnetlink-queue", "kmod-nft-queue")
		mods = append(mods,
			DepCheck{Name: "nfnetlink_queue", Critical: true},
			DepCheck{Name: "nft_queue", Critical: true},
		)
	} else {
		pkgs = append(pkgs, "iptables-mod-nfqueue", "kmod-ipt-nfqueue", "iptables-zz-legacy")
		mods = append(mods, DepCheck{Name: "xt_NFQUEUE", Critical: true})
	}
	mods = append(mods,
		DepCheck{Name: "xt_connbytes", Critical: true},
		DepCheck{Name: "ip_set_bitmap_port", Critical: false},
	)
	return DepsSpec{
		Binaries:       bins,
		Modules:        mods,
		Packages:       pkgs,
		PreferModprobe: true,
	}
}

func (procdProfile) ModuleLoadCmds(modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	return moduleLoadCmds(true, modName, kernelRel, root, findBin)
}

// ---------------------------------------------------------------- Entware (Keenetic / Merlin / Netcraze)

type entwareProfile struct{}

func (entwareProfile) Name() string                   { return "entware" }
func (entwareProfile) InitSystem() platform.InitSystem { return platform.InitEntware }
func (entwareProfile) OpenRCActive() bool             { return false }

func (entwareProfile) NativeZapret(_ paths.Paths) NativeZapretSpec {
	return NativeZapretSpec{
		UpstreamRel: "init.d/sysv/zapret2",
		SystemPath:  entwareInitDir + "/S90-" + unitZapret2,
		Mode:        InitModeInPlace,
	}
}

func (entwareProfile) ValidateUpstreamZapret(zapretRoot string) bool {
	return regularFile(filepath.Join(zapretRoot, "init.d", "sysv", unitZapret2)) &&
		regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "functions"))
}

func (entwareProfile) ServiceScriptPath(unit string, p paths.Paths) string {
	if unit == unitZapret2 {
		return filepath.Join(p.ZapretRoot, "init.d", "sysv", unitZapret2)
	}
	return entwareInitDir + "/S92" + unit
}

func (e entwareProfile) ControlCmd(unit, action string, p paths.Paths) CmdSpec {
	return CmdSpec{Name: filepath.ToSlash(e.ServiceScriptPath(unit, p)), Args: []string{action}}
}

func (e entwareProfile) QueryCmd(unit string, p paths.Paths) CmdSpec {
	return CmdSpec{Name: filepath.ToSlash(e.ServiceScriptPath(unit, p)), Args: []string{"status"}}
}

func (entwareProfile) EnableOps(_ string, _ paths.Paths) []CommandOp { return nil }

func (e entwareProfile) DisableOps(unit string, p paths.Paths) []CommandOp {
	return []CommandOp{
		{Primary: CmdSpec{Name: filepath.ToSlash(e.ServiceScriptPath(unit, p)), Args: []string{"stop"}}},
	}
}

func (entwareProfile) PostUninstallOps(_ string, _ paths.Paths) []CommandOp { return nil }

func (entwareProfile) FirewallReloadCmd(p paths.Paths, root string) (CmdSpec, bool) {
	return firstExistingCmd([]string{
		filepath.Join(p.ZapretRoot, "init.d", "sysv", unitZapret2),
		sysPath(root, entwareInitDir+"/S90-"+unitZapret2),
	}, "restart-fw")
}

func (entwareProfile) CustomDFlavors(_ string) []string { return []string{"sysv"} }

func (entwareProfile) PkgManagerOrder() []string { return []string{"opkg"} }

func (entwareProfile) PkgUpdateCmd(_, binPath string) (CmdSpec, bool) {
	return CmdSpec{Name: binPath, Args: []string{"update"}}, true
}

func (entwareProfile) PkgInstallCmd(_, binPath string, pkgs []string) CmdSpec {
	return CmdSpec{Name: binPath, Args: append([]string{"install"}, pkgs...)}
}

func (entwareProfile) RequiredDeps(_ platform.FWType) DepsSpec {
	return DepsSpec{
		RequiredPkgManager: "opkg",
		Binaries: []DepCheck{
			{Name: "iptables", Critical: true},
			{Name: "ipset", Critical: true},
			{Name: "ip6tables", Critical: false},
			{Name: "insmod", Critical: false},
		},
		Modules: []DepCheck{
			{Name: "xt_NFQUEUE", Critical: true},
			{Name: "xt_connbytes", Critical: true},
			{Name: "xt_multiport", Critical: false},
			{Name: "xt_set", Critical: false},
			{Name: "ip_set", Critical: false},
			{Name: "ip_set_bitmap_port", Critical: true},
			{Name: "ip_set_hash_ip", Critical: false},
			{Name: "ip_set_hash_net", Critical: false},
			{Name: "ip_set_hash_ipport", Critical: false},
		},
		Packages:       []string{"iptables", "ipset"},
		PreferModprobe: false,
	}
}

func (entwareProfile) ModuleLoadCmds(modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	return moduleLoadCmds(false, modName, kernelRel, root, findBin)
}

// ---------------------------------------------------------------- SysV

type sysvProfile struct{}

func (sysvProfile) Name() string                   { return "sysv" }
func (sysvProfile) InitSystem() platform.InitSystem { return platform.InitSysV }
func (sysvProfile) OpenRCActive() bool             { return false }

func (sysvProfile) NativeZapret(_ paths.Paths) NativeZapretSpec {
	return NativeZapretSpec{
		UpstreamRel: "init.d/sysv/zapret2",
		SystemPath:  initDir + "/" + unitZapret2,
		Mode:        InitModeSymlink,
	}
}

func (sysvProfile) ValidateUpstreamZapret(zapretRoot string) bool {
	return regularFile(filepath.Join(zapretRoot, "init.d", "sysv", unitZapret2)) &&
		regularFile(filepath.Join(zapretRoot, "init.d", "sysv", "functions"))
}

func (sysvProfile) ServiceScriptPath(unit string, _ paths.Paths) string {
	return initDir + "/" + unit
}

func (sysvProfile) ControlCmd(unit, action string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{action}}
}

func (sysvProfile) QueryCmd(unit string, _ paths.Paths) CmdSpec {
	return CmdSpec{Name: initDir + "/" + unit, Args: []string{"status"}}
}

func (sysvProfile) EnableOps(unit string, _ paths.Paths) []CommandOp {
	fb := CmdSpec{Name: "chkconfig", Args: []string{"--add", unit}}
	return []CommandOp{
		{
			Primary:    CmdSpec{Name: "update-rc.d", Args: []string{unit, "defaults"}},
			Fallback:   &fb,
			BestEffort: true,
		},
	}
}

func (sysvProfile) DisableOps(unit string, _ paths.Paths) []CommandOp {
	fb := CmdSpec{Name: "chkconfig", Args: []string{"--del", unit}}
	return []CommandOp{
		{Primary: CmdSpec{Name: initDir + "/" + unit, Args: []string{"stop"}}},
		{
			Primary:        CmdSpec{Name: "update-rc.d", Args: []string{"-f", unit, "remove"}},
			Fallback:       &fb,
			IgnoreNotFound: true,
		},
	}
}

func (sysvProfile) PostUninstallOps(_ string, _ paths.Paths) []CommandOp { return nil }

func (sysvProfile) FirewallReloadCmd(p paths.Paths, root string) (CmdSpec, bool) {
	return firstExistingCmd([]string{
		filepath.Join(p.ZapretRoot, "init.d", "sysv", unitZapret2),
		sysPath(root, initDir+"/"+unitZapret2),
	}, "restart-fw")
}

func (sysvProfile) CustomDFlavors(_ string) []string { return []string{"sysv"} }

func (sysvProfile) PkgManagerOrder() []string { return []string{"apt-get", "dnf", "yum", "pacman", "apk"} }

func (sysvProfile) PkgUpdateCmd(_, _ string) (CmdSpec, bool) { return CmdSpec{}, false }

func (sysvProfile) PkgInstallCmd(mgr, binPath string, pkgs []string) CmdSpec {
	return linuxPkgInstallCmd(mgr, binPath, pkgs)
}

func (sysvProfile) RequiredDeps(fw platform.FWType) DepsSpec { return vpsDeps(fw) }

func (sysvProfile) ModuleLoadCmds(modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	return moduleLoadCmds(true, modName, kernelRel, root, findBin)
}

// ---------------------------------------------------------------- общие хелперы

func vpsDeps(fw platform.FWType) DepsSpec {
	if fw == platform.FWNftables {
		return DepsSpec{
			Binaries: []DepCheck{{Name: "nft", Critical: true}},
			Modules: []DepCheck{
				{Name: "nfnetlink_queue", Critical: true},
				{Name: "nft_queue", Critical: true},
				{Name: "xt_connbytes", Critical: false},
			},
			Packages:       []string{"nftables"},
			PreferModprobe: true,
		}
	}
	return DepsSpec{
		Binaries: []DepCheck{
			{Name: "iptables", Critical: true},
			{Name: "ipset", Critical: true},
		},
		Modules: []DepCheck{
			{Name: "xt_NFQUEUE", Critical: true},
			{Name: "xt_connbytes", Critical: false},
			{Name: "ip_set_bitmap_port", Critical: false},
		},
		Packages:       []string{"iptables", "ipset"},
		PreferModprobe: true,
	}
}

func linuxPkgInstallCmd(mgr, binPath string, pkgs []string) CmdSpec {
	switch mgr {
	case "apk":
		args := make([]string, 0, len(pkgs)+2)
		args = append(args, "add", "--no-cache")
		args = append(args, pkgs...)
		return CmdSpec{Name: binPath, Args: args}
	case "pacman":
		args := make([]string, 0, len(pkgs)+3)
		args = append(args, "-S", "--noconfirm", "--needed")
		args = append(args, pkgs...)
		return CmdSpec{Name: binPath, Args: args}
	default:
		args := make([]string, 0, len(pkgs)+2)
		args = append(args, "install", "-y")
		args = append(args, pkgs...)
		return CmdSpec{Name: binPath, Args: args}
	}
}

func moduleLoadCmds(preferModprobe bool, modName, kernelRel, root string, findBin func(string) string) []CmdSpec {
	if root == "" {
		root = "/"
	}
	var cmds []CmdSpec
	if preferModprobe && findBin != nil {
		if mp := findBin("modprobe"); mp != "" {
			cmds = append(cmds, CmdSpec{Name: mp, Args: []string{modName}})
		}
	}
	if kernelRel != "" {
		ko := filepath.Join(root, "lib", "modules", kernelRel, modName+".ko")
		if regularFile(ko) {
			insmod := ""
			if findBin != nil {
				insmod = findBin("insmod")
			}
			if insmod == "" {
				insmod = "insmod"
			}
			cmds = append(cmds, CmdSpec{Name: insmod, Args: []string{ko}})
		}
	}
	return cmds
}

func firstExistingCmd(candidates []string, action string) (CmdSpec, bool) {
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if regularFile(p) {
			return CmdSpec{Name: p, Args: []string{action}}, true
		}
	}
	return CmdSpec{}, false
}

func sysPath(root, abs string) string {
	if root == "" || root == "/" {
		return filepath.FromSlash(abs)
	}
	return filepath.Join(root, filepath.FromSlash(abs))
}

func regularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
