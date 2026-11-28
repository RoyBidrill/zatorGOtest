//go:build !linux

package deploy

import (
	"fmt"
	"github.com/AloofLibra/zator/internal/paths"
)

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

func CheckPreflight(paths.Paths, *Latest, string) (PreflightReport, error) {
	return PreflightReport{}, fmt.Errorf("предварительная проверка памяти поддерживается только на Linux")
}

// CheckZapretSpace на не-Linux платформах возвращает ok=true.
func CheckZapretSpace(string, bool) (freeBytes, requiredBytes int64, ok bool, err error) {
	return 0, 0, true, nil
}
