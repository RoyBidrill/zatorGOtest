package customstrats

import (
	"fmt"
	"os"
	"strings"

	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/fsutil"
	"github.com/AloofLibra/zator/internal/orchestra"
)

// ApplyResult отражает итоги инъекции стратегий в конфиг и ремапа локов.
type ApplyResult struct {
	Changed bool `json:"changed"`
	Moved   int  `json:"moved"`
	Dropped int  `json:"dropped"`
}

func formatCustomLines(spec string, num int) string {
	groups := strings.Split(spec, " --lua-desync=")
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = fmt.Sprintf("--lua-desync=%s:strategy=%d", g, num)
	}
	return strings.Join(out, " ")
}

func autoLockedKeyForBlock(block string) string {
	switch block {
	case BlockTPL:
		return "tls"
	case BlockP5:
		return "quic"
	default:
		return ""
	}
}

// Apply идемпотентно инъектирует включённые стратегии в маркерные секции конфига,
// обновляет колонку assigned в TSV и переназначает локи в orchestra/auto_locked.
func (s *Store) Apply(cfg *config.Config) (ApplyResult, error) {
	var res ApplyResult
	if cfg == nil {
		return res, fmt.Errorf("%w: config is nil", ErrInvalid)
	}

	var (
		remapRules   []orchestra.LockRemapRule
		maxRules     []orchestra.LockMaxRule
		autoRules    []orchestra.AutoLockRemapRule
		autoMaxRules []orchestra.AutoLockMaxRule
	)

	err := fsutil.WithDirLock(s.tsvPath, 0, 0, func() error {
		entries, err := s.readUnlocked()
		if err != nil {
			return err
		}
		tsvExists := len(entries) > 0
		if !tsvExists {
			if _, statErr := os.Stat(s.tsvPath); statErr == nil {
				tsvExists = true
			}
		}

		if err := cfg.EnsureCustomStrategyMarkers(); err != nil {
			return err
		}
		before := cfg.String()
		tsvChanged := false

		for _, blk := range allBlocks {
			mb, me, ok := config.CustomBlockMarkers(blk.Block)
			if !ok {
				continue
			}
			if _, hasMarkers := cfg.ReadMarkerSection(mb, me); !hasMarkers {
				continue
			}
			stockMax, err := cfg.BlockStockMaxStrategy(blk.Block)
			if err != nil {
				return err
			}

			askey := autoLockedKeyForBlock(blk.Block)
			enabledCount := 0
			var ins []string

			for i := range entries {
				if entries[i].Block != blk.Block {
					continue
				}
				oldAssigned := entries[i].Assigned
				newNum := 0
				if entries[i].Enabled {
					enabledCount++
					newNum = stockMax + enabledCount
					ins = append(ins, formatCustomLines(entries[i].Spec, newNum))
				}
				if entries[i].Assigned != newNum {
					entries[i].Assigned = newNum
					tsvChanged = true
				}

				if oldAssigned > 0 && oldAssigned != newNum {
					for _, prof := range blk.Profiles {
						for _, proto := range blk.ProtosFor(prof) {
							remapRules = append(remapRules, orchestra.LockRemapRule{
								Profile:     prof,
								Proto:       proto,
								OldStrategy: oldAssigned,
								NewStrategy: newNum,
							})
						}
					}
					if askey != "" {
						autoRules = append(autoRules, orchestra.AutoLockRemapRule{
							Key:         askey,
							OldStrategy: oldAssigned,
							NewStrategy: newNum,
						})
					}
				}
			}

			if err := cfg.ReplaceMarkerSection(mb, me, ins); err != nil {
				return err
			}

			newMax := stockMax + enabledCount
			for _, prof := range blk.Profiles {
				for _, proto := range blk.ProtosFor(prof) {
					maxRules = append(maxRules, orchestra.LockMaxRule{
						Profile:     prof,
						Proto:       proto,
						MaxStrategy: newMax,
					})
				}
			}
			if askey != "" {
				autoMaxRules = append(autoMaxRules, orchestra.AutoLockMaxRule{
					Key:         askey,
					MaxStrategy: newMax,
				})
			}
		}

		if tsvExists && tsvChanged {
			if err := s.writeUnlocked(entries); err != nil {
				return err
			}
		}
		res.Changed = cfg.String() != before
		return nil
	})
	if err != nil {
		return res, err
	}

	if s.orch != nil && (len(remapRules) > 0 || len(maxRules) > 0 || len(autoRules) > 0 || len(autoMaxRules) > 0) {
		moved, dropped, rErr := s.orch.RemapLocks(remapRules, maxRules, autoRules, autoMaxRules, s.autoLockedPaths...)
		res.Moved = moved
		res.Dropped = dropped
		if rErr != nil {
			return res, rErr
		}
	}
	return res, nil
}

// ApplyFile загружает файл конфига под блокировкой, применяет пользовательские стратегии и сохраняет при изменениях.
func (s *Store) ApplyFile(cfgPath string) (ApplyResult, error) {
	var res ApplyResult
	err := fsutil.WithDirLock(cfgPath, 0, 0, func() error {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		res, err = s.Apply(cfg)
		if err != nil || !res.Changed {
			return err
		}
		if err := fsutil.AtomicWriteFile(cfgPath, []byte(cfg.String()), 0); err != nil {
			return fmt.Errorf("config: save %s: %w", cfgPath, err)
		}
		return nil
	})
	return res, err
}
