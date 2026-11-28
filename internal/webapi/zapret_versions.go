package webapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AloofLibra/zator/internal/deploy"
	"github.com/AloofLibra/zator/internal/platform"
	"github.com/AloofLibra/zator/internal/service"
	"github.com/AloofLibra/zator/internal/zapret"
)

const zapretReleasesCacheTTL = 10 * time.Minute

var zapretSpaceCheckFn = deploy.CheckZapretSpace

type zapretReleasesCache struct {
	embedded  bool
	fork      []zapret.Release
	official  []zapret.Release
	errors    map[string]string
	fetchedAt time.Time
}

func (s *Server) zapretReleasesGet(ctx context.Context, refresh bool) map[string]any {
	if ctx == nil {
		ctx = context.Background()
	}
	embedded := s.app != nil && s.app.Platform.Kind == platform.KindOpenWRT
	platformArch := ""
	if s.app != nil {
		platformArch = string(s.app.Platform.Arch)
	}

	detCtx, detCancel := context.WithTimeout(ctx, 2*time.Second)
	in, _ := zapret.DetectInstalled(detCtx, s.paths.ZapretRoot)
	detCancel()

	installed := map[string]any{
		"version": in.Version,
		"source":  string(in.Source),
		"arch":    in.ArchDir,
	}

	s.zapretRelMu.Lock()
	cachedEntry := s.zapretRelCache
	s.zapretRelMu.Unlock()

	if !refresh && cachedEntry != nil && cachedEntry.embedded == embedded && s.now().Sub(cachedEntry.fetchedAt) < zapretReleasesCacheTTL {
		return map[string]any{
			"installed":      installed,
			"platform_arch":  platformArch,
			"embedded":       embedded,
			"default_source": string(zapret.DefaultSource),
			"fork":           append([]zapret.Release(nil), cachedEntry.fork...),
			"official":       append([]zapret.Release(nil), cachedEntry.official...),
			"errors":         copyStringMap(cachedEntry.errors),
			"checked_at":     cachedEntry.fetchedAt.UTC().Format(time.RFC3339),
			"cached":         true,
		}
	}

	fetchCtx, fetchCancel := context.WithTimeout(ctx, 20*time.Second)
	fork, official, errs := zapret.ListAllReleases(fetchCtx, embedded, s.zapretHTTP)
	fetchCancel()

	errMap := make(map[string]string, len(errs))
	for src, msg := range errs {
		errMap[string(src)] = msg
	}
	checkedAt := s.now()
	if len(fork) > 0 || len(official) > 0 {
		s.zapretRelMu.Lock()
		s.zapretRelCache = &zapretReleasesCache{
			embedded:  embedded,
			fork:      append([]zapret.Release(nil), fork...),
			official:  append([]zapret.Release(nil), official...),
			errors:    copyStringMap(errMap),
			fetchedAt: checkedAt,
		}
		s.zapretRelMu.Unlock()
	}

	return map[string]any{
		"installed":      installed,
		"platform_arch":  platformArch,
		"embedded":       embedded,
		"default_source": string(zapret.DefaultSource),
		"fork":           fork,
		"official":       official,
		"errors":         errMap,
		"checked_at":     checkedAt.UTC().Format(time.RFC3339),
		"cached":         false,
	}
}

func (s *Server) postZapretVersion(r *http.Request, p params) (map[string]any, error) {
	rawSource := strings.TrimSpace(p.Get("source"))
	if rawSource == "" {
		return nil, errf(http.StatusBadRequest, "Укажите ветку zapret2 (fork или official)")
	}
	src, err := zapret.ParseSource(rawSource)
	if err != nil {
		return nil, errf(http.StatusBadRequest, err.Error())
	}
	rawVer := strings.TrimSpace(p.Get("version"))
	if rawVer == "" {
		return nil, errf(http.StatusBadRequest, "Укажите версию zapret2")
	}
	ver, err := zapret.NormalizeVersion(src, rawVer)
	if err != nil {
		return nil, errf(http.StatusBadRequest, err.Error())
	}

	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()

	if s.sweepRunningLocked() {
		return nil, errf(http.StatusConflict, "Нельзя менять версию zapret2 во время суперавтопрогона")
	}

	force := p.Get("force") == "1"
	if !force {
		if _, readErr := zapret.ReadInstalled(s.paths.ZapretRoot); readErr != nil {
			// Если роутер ставился без zator-zapret.version (например z2r.sh), гарантируем чистую переустановку с записью маркера.
			force = true
		}
	}

	var (
		mirror string
		plat   platform.Platform
	)
	if s.app != nil {
		mirror = s.app.Config.Mirror
		plat = s.app.Platform
	}
	embedded := plat.Kind == platform.KindOpenWRT
	if zapretSpaceCheckFn != nil {
		if freeB, reqB, ok, serr := zapretSpaceCheckFn(s.paths.ZapretRoot, embedded); serr == nil && !ok {
			return nil, errf(http.StatusInsufficientStorage,
				fmt.Sprintf("Недостаточно свободного места для установки zapret2: свободно %.1f МБ, требуется минимум %.1f МБ",
					float64(freeB)/(1<<20), float64(reqB)/(1<<20)))
		}
	}
	zopts := zapret.Options{
		Root:       s.paths.ZapretRoot,
		Arch:       plat.Arch,
		Source:     src,
		Version:    ver,
		Force:      force,
		IncludeLua: true,
		MirrorBase: mirror,
	}

	installCtx, installCancel := context.WithTimeout(r.Context(), 3*time.Minute)
	var res *zapret.Result
	if s.zapretInstall != nil {
		res, err = s.zapretInstall(installCtx, zopts)
	} else {
		res, err = zapret.Install(installCtx, s.paths, plat, zopts)
	}
	installCancel()
	if err != nil {
		return nil, errf(http.StatusBadGateway, "Не удалось установить zapret2 "+ver+": "+err.Error())
	}

	if s.app != nil && s.app.Config.ZapretSource != string(src) {
		s.app.Config.ZapretSource = string(src)
		_ = s.app.Save()
	}

	restarted := false
	if p.Get("restart") != "0" && s.svc != nil {
		restartCtx, restartCancel := context.WithTimeout(context.Background(), 60*time.Second)
		var rerr error
		if s.app != nil {
			rerr = s.app.RestartZapretTransactional(restartCtx, func(ctx context.Context) error {
				return s.svc.Restart(ctx, service.UnitZapret2)
			})
			if rerr == nil {
				s.app.ClearServiceWarnings()
			}
		} else {
			rerr = s.svc.Restart(restartCtx, service.UnitZapret2)
		}
		restartCancel()
		if rerr != nil {
			return nil, errf(http.StatusInternalServerError,
				fmt.Sprintf("zapret2 v%s установлен, но перезапуск службы не удался: %v", res.Version, rerr))
		}
		restarted = true
	}

	return map[string]any{
		"ok":        true,
		"version":   res.Version,
		"source":    string(res.Source),
		"arch":      res.ArchDir,
		"skipped":   res.Skipped,
		"restarted": restarted,
	}, nil
}

func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
