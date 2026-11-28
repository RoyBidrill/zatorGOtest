//go:build linux

package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/AloofLibra/zator/internal/paths"
)

// PreflightReport reports available memory and storage before an update.
type PreflightReport struct {
	RAMAvailable            int64 `json:"ram_available"`
	TmpAvailable            int64 `json:"tmp_available"`
	FlashAvailable          int64 `json:"flash_available"`
	ZapretFlashAvailable    int64 `json:"zapret_flash_available"`
	TmpRequired             int64 `json:"tmp_required"`
	TmpBaseRequired         int64 `json:"tmp_base_required"`
	BackupRequired          int64 `json:"backup_required"`
	FlashRequired           int64 `json:"flash_required"`
	ZapretFlashRequired     int64 `json:"zapret_flash_required"`
	CanRollback             bool  `json:"can_rollback"`
	CanProceedWithoutBackup bool  `json:"can_proceed_without_backup"`
	CanUpdate               bool  `json:"can_update"`
}

func fsAvailable(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func memAvailable() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				n, _ := strconv.ParseInt(fields[1], 10, 64)
				return n * 1024
			}
		}
	}
	return 0
}

func treeBytes(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// CheckPreflight estimates temp space for archive, extraction and binary rollback.
// The estimate uses the latest manifest sizes when available and remains conservative
// for older schema-1 releases that only publish the full archive.
func CheckPreflight(p paths.Paths, latest *Latest, mode string) (PreflightReport, error) {
	if mode == "" {
		mode = "full"
	}
	if mode != "app" && mode != "config" && mode != "full" {
		return PreflightReport{}, fmt.Errorf("неизвестный режим обновления %q", mode)
	}
	if err := os.MkdirAll("/tmp", 0o755); err != nil {
		return PreflightReport{}, err
	}
	root := p.ZatorRoot
	for {
		if _, err := os.Stat(root); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			return PreflightReport{}, fmt.Errorf("не найден flash-раздел для %s", p.ZatorRoot)
		}
		root = parent
	}
	tmpFree, err := fsAvailable("/tmp")
	if err != nil {
		return PreflightReport{}, err
	}
	flashFree, err := fsAvailable(root)
	if err != nil {
		return PreflightReport{}, err
	}
	zapretRoot := p.ZapretRoot
	for {
		if _, err := os.Stat(zapretRoot); err == nil {
			break
		}
		parent := filepath.Dir(zapretRoot)
		if parent == zapretRoot {
			return PreflightReport{}, fmt.Errorf("не найден flash-раздел для %s", p.ZapretRoot)
		}
		zapretRoot = parent
	}
	zapretFree, err := fsAvailable(zapretRoot)
	if err != nil {
		return PreflightReport{}, err
	}
	var archive, expanded, binary int64
	if latest != nil {
		packages := []string{mode}
		if mode == ModeFull {
			packages = []string{VariantApp, VariantConfig}
		}
		for _, name := range packages {
			if a, ok := latest.Assets[name]; ok {
				archive += a.Size
				expanded += a.UnpackedSize
			}
		}
	}
	if archive == 0 {
		archive = 8 << 20
	}
	if expanded == 0 {
		expanded = 32 << 20
	}
	userBackup := treeBytes(p.ConfigDir) + treeBytes(p.ListsDir) + treeBytes(p.StateOrchestraDir())
	if st, e := os.Stat(p.ZapretConfig); e == nil && st.Mode().IsRegular() {
		userBackup += st.Size()
	}
	if st, e := os.Stat(filepath.Join(p.BinDir, "zator")); e == nil {
		binary = st.Size()
	}
	zapretRequired := int64(0)
	if mode != ModeApp {
		zapretRequired = 1 << 20
	}
	r := PreflightReport{RAMAvailable: memAvailable(), TmpAvailable: tmpFree, FlashAvailable: flashFree, ZapretFlashAvailable: zapretFree,
		TmpBaseRequired: archive + expanded + 2<<20,
		BackupRequired:  binary + userBackup,
		FlashRequired: expanded + (func() int64 {
			if mode != ModeConfig {
				return binary
			}
			return 0
		})() + 4<<20, ZapretFlashRequired: zapretRequired}
	r.TmpRequired = r.TmpBaseRequired + r.BackupRequired
	// Resource archives are staged in tmpfs; flash requirement covers replacement
	// headroom and filesystem metadata, not the pre-update binary backup.
	r.CanProceedWithoutBackup = tmpFree >= r.TmpBaseRequired && (r.RAMAvailable == 0 || r.RAMAvailable >= r.TmpBaseRequired)
	r.CanRollback = r.CanProceedWithoutBackup && (r.RAMAvailable == 0 || r.RAMAvailable >= r.TmpRequired)
	r.CanUpdate = flashFree >= r.FlashRequired && zapretFree >= r.ZapretFlashRequired
	return r, nil
}

// CheckZapretSpace проверяет достаточность свободного места на разделе zapretRoot
// с учётом того, поместится ли скачиваемый архив в /tmp.
func CheckZapretSpace(zapretRoot string, embedded bool) (freeBytes, requiredBytes int64, ok bool, err error) {
	ancestor := zapretRoot
	if ancestor == "" {
		ancestor = "/opt/zapret2"
	}
	for {
		if _, serr := os.Stat(ancestor); serr == nil {
			break
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return 0, 0, false, fmt.Errorf("не найден flash-раздел для %s", zapretRoot)
		}
		ancestor = parent
	}
	freeBytes, err = fsAvailable(ancestor)
	if err != nil {
		return 0, 0, false, err
	}
	tmpNeed := int64(24 << 20)
	if embedded {
		tmpNeed = 12 << 20
	}
	if tmpFree, terr := fsAvailable("/tmp"); terr == nil && tmpFree >= tmpNeed {
		if embedded {
			requiredBytes = 4 << 20
		} else {
			requiredBytes = 8 << 20
		}
	} else {
		if embedded {
			requiredBytes = 10 << 20
		} else {
			requiredBytes = 24 << 20
		}
	}
	return freeBytes, requiredBytes, freeBytes >= requiredBytes, nil
}
