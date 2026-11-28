// Package webapi реализует HTTP API Web UI zator: порт CGI-скриптов
// webui/cgi-bin/*.cgi (см. docs/API.md) поверх пакетов config, orchestra,
// service, netcheck и sweep, плюс раздачу статических файлов Web UI.
//
// Каждый эндпоинт доступен по двум путям: /cgi-bin/<name>.cgi (совместимость с
// фронтендом) и /api/<name> (чистый алиас). Ответы — всегда JSON
// `application/json; charset=utf-8`; ошибки имеют вид {"error":"текст"}.
//
// # Авторизация
//
// Если auth_enabled=true, API требует сессию. Статика SPA (index/js/css) открыта
// без cookie — вход только через Vue / POST /api/login. auth_enabled=false —
// открытый доступ (-no-auth / `zator auth disable`):
//
//   - cookie zator_session = session_token;
//   - Authorization: Bearer <session_token>;
//   - HTTP Basic (пароль Web UI).
//
// Пароль — только bcrypt (password_hash).
package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/AloofLibra/zator/internal/app"
	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/netcheck"
	"github.com/AloofLibra/zator/internal/orchestra"
	"github.com/AloofLibra/zator/internal/paths"
	"github.com/AloofLibra/zator/internal/provider"
	"github.com/AloofLibra/zator/internal/service"
	"github.com/AloofLibra/zator/internal/sweep"
	"github.com/AloofLibra/zator/internal/uiembed"
	"github.com/AloofLibra/zator/internal/zapret"
)

// CookieName — имя cookie сессии после login.
const CookieName = "zator_session"

// Ограничения запросов.
const (
	maxFormBytes   = 4 << 20  // тело application/x-www-form-urlencoded
	maxUploadBytes = 32 << 20 // загрузка архива бэкапа
)

// NetChecker — проверки доступности (реализует *netcheck.Checker).
type NetChecker interface {
	Check(ctx context.Context) netcheck.CheckResponse
	CheckProfile(ctx context.Context, profile int) netcheck.CheckResponse
	CheckProfileOpts(ctx context.Context, profile int, opts netcheck.ProfileCheckOptions) netcheck.CheckResponse
	CheckTarget(ctx context.Context, label, rawURL string) netcheck.TargetResult
}

// Sweeper — суперавтопрогон (реализует *sweep.Coordinator).
type Sweeper interface {
	Start(ctx context.Context, p sweep.Params) error
	Cancel() error
	Report() (sweep.Report, error)
	Running() bool
}

var (
	_ NetChecker = (*netcheck.Checker)(nil)
	_ Sweeper    = (*sweep.Coordinator)(nil)
)

// Options — зависимости сервера. Нулевые поля заменяются реальными
// реализациями (в тестах подставляются заглушки).
type Options struct {
	// App задаёт пути и платформу; обязателен.
	App *app.App
	// Static — файловая система Web UI. По умолчанию: WebUIDir, если там есть
	// index.html, иначе встроенный Web UI.
	Static fs.FS
	// Service управляет службой zapret2. По умолчанию service.New по платформе.
	Service service.Manager
	// Checker — сетевые проверки. По умолчанию netcheck.NewChecker(DefaultOptions()).
	Checker NetChecker
	// Sweeper — координатор суперавтопрогона. По умолчанию создаётся лениво.
	Sweeper Sweeper
	// Provider — детектор провайдера. По умолчанию provider.New(paths).
	Provider *provider.Detector
	// CheckTimeout ограничивает один запрос check.cgi (по умолчанию 2 минуты).
	CheckTimeout time.Duration
	// Now подменяет время (тесты).
	Now func() time.Time
}

// Server — HTTP-сервер API и статики Web UI.
type Server struct {
	app      *app.App
	paths    paths.Paths
	static   fs.FS
	store    *orchestra.Store
	svc      service.Manager
	svcErr   error
	checker  NetChecker
	provider *provider.Detector
	timeout  time.Duration
	now      func() time.Time

	cfgMu  sync.Mutex // сериализует изменения config
	listMu sync.Mutex // сериализует изменения списков доменов

	// runtimeMu сериализует start/stop/restart zapret2 и supersweep start/cancel,
	// чтобы не гонять службу во время прогона и наоборот.
	runtimeMu sync.Mutex

	sweepMu         sync.Mutex
	sweeper         Sweeper
	sweeperInjected bool

	zapretRelMu    sync.Mutex
	zapretRelCache *zapretReleasesCache
	zapretHTTP     *http.Client
	zapretInstall  func(ctx context.Context, opts zapret.Options) (*zapret.Result, error)
}

// New создаёт сервер.
func New(opts Options) (*Server, error) {
	if opts.App == nil {
		return nil, errors.New("webapi: не задан App")
	}
	s := &Server{
		app:      opts.App,
		paths:    opts.App.Paths,
		static:   opts.Static,
		svc:      opts.Service,
		checker:  opts.Checker,
		provider: opts.Provider,
		timeout:         opts.CheckTimeout,
		now:             opts.Now,
		sweeper:         opts.Sweeper,
		sweeperInjected: opts.Sweeper != nil,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.timeout <= 0 {
		s.timeout = 2 * time.Minute
	}
	if s.checker == nil {
		ch := netcheck.NewChecker(netcheck.DefaultOptions())
		ch.Paths = s.paths
		s.checker = ch
	}
	if s.provider == nil {
		s.provider = provider.New(s.paths)
	}
	if s.static == nil {
		s.static = s.defaultStatic()
	}
	if s.svc == nil {
		ctl, err := service.New(service.Config{Platform: opts.App.Platform, Paths: opts.App.Paths})
		if err != nil {
			s.svcErr = err
		} else {
			s.svc = ctl
		}
	}
	s.store = orchestra.NewStore(s.paths.StateOrchestraDir())
	s.store.MaxStrategy = s.maxStrategy
	return s, nil
}

// Store возвращает хранилище orchestra, которое использует сервер.
func (s *Server) Store() *orchestra.Store { return s.store }

func (s *Server) defaultStatic() fs.FS {
	if st, err := os.Stat(filepath.Join(s.paths.WebUIDir, "index.html")); err == nil && !st.IsDir() {
		return os.DirFS(s.paths.WebUIDir)
	}
	return uiembed.WebUIAt(s.paths)
}

// endpoint — обработчик одного CGI-эндпоинта.
type endpoint func(s *Server, w http.ResponseWriter, r *http.Request, p params)

var endpoints = map[string]endpoint{
	"status":        (*Server).handleStatus,
	"state":         (*Server).handleState,
	"set-lock":      (*Server).handleSetLock,
	"clear-lock":    (*Server).handleClearLock,
	"service":       (*Server).handleService,
	"check":         (*Server).handleCheck,
	"domains":       (*Server).handleDomains,
	"client-scopes": (*Server).handleClientScopes,
	"backups":       (*Server).handleBackups,
	"scopes":        (*Server).handleScopes,
	"settings":      (*Server).handleSettings,
	"blob-upload":   (*Server).handleBlobUpload,
	"custom":        (*Server).handleCustom,
	"blobs":         (*Server).handleBlobs,
	"login":         (*Server).handleLogin,
	"logout":        (*Server).handleLogout,
}

// Handler возвращает корневой http.Handler (авторизация + API + статика).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for name, h := range endpoints {
		h := h
		fn := func(w http.ResponseWriter, r *http.Request) {
			p, err := parseParams(w, r)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Некорректные параметры запроса")
				return
			}
			h(s, w, r, p)
		}
		mux.HandleFunc("/cgi-bin/"+name+".cgi", fn)
		mux.HandleFunc("/api/"+name, fn)
	}
	notFound := func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "Не найдено")
	}
	mux.HandleFunc("/cgi-bin/", notFound)
	mux.HandleFunc("/api/", notFound)
	mux.Handle("/", s.staticHandler())
	return recoverMiddleware(s.authMiddleware(mux))
}

// recoverMiddleware ловит panic в handlers, чтобы Web UI не падал целиком.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("webapi panic: %v\n%s", rec, debug.Stack())
				if w.Header().Get("Content-Type") == "" {
					writeError(w, http.StatusInternalServerError, fmt.Sprintf("внутренняя ошибка: %v", rec))
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- статика ---

func (s *Server) staticHandler() http.Handler {
	files := http.FileServer(http.FS(s.static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "Метод не поддерживается")
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		st, err := fs.Stat(s.static, name)
		switch {
		case err == nil && st.IsDir() && name != ".":
			http.NotFound(w, r)
			return
		case err != nil && !strings.Contains(path.Base(name), "."):
			// История маршрутов SPA: неизвестный путь без расширения -> index.html.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// --- параметры ---

// params — параметры запроса (GET query + тело POST x-www-form-urlencoded),
// как parse_params() в _lib.sh: первое значение ключа.
type params url.Values

// Get возвращает значение ключа без внешних пробелов.
func (p params) Get(key string) string { return strings.TrimSpace(url.Values(p).Get(key)) }

// Raw возвращает значение ключа без обрезки (многострочные списки).
func (p params) Raw(key string) string { return url.Values(p).Get(key) }

// Has сообщает, присутствовал ли ключ в запросе или форме.
func (p params) Has(key string) bool { _, ok := url.Values(p)[key]; return ok }

func parseParams(w http.ResponseWriter, r *http.Request) (params, error) {
	q := r.URL.Query()
	upload := q.Get("action") == "upload" ||
		strings.HasSuffix(r.URL.Path, "blob-upload.cgi") ||
		strings.HasSuffix(r.URL.Path, "/blob-upload")
	if r.Method == http.MethodPost && !upload && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			return params(q), err
		}
		merged := url.Values{}
		for k, v := range q {
			merged[k] = v
		}
		for k, v := range r.PostForm { // тело приоритетнее строки запроса
			merged[k] = v
		}
		return params(merged), nil
	}
	return params(q), nil
}

// --- ответы ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// apiError — ошибка с HTTP-статусом.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return e.Msg }

func errf(status int, msg string) *apiError { return &apiError{Status: status, Msg: msg} }

// writeErr отвечает ошибкой; не-apiError превращается в 500.
func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeError(w, ae.Status, ae.Msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

// requireMethod допускает только перечисленные методы (иначе 405).
func requireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "Метод не поддерживается")
	return false
}

// --- конфиг ---

// errNotInstalled — живой config zapret2 отсутствует.
func (s *Server) notInstalledErr() *apiError {
	return &apiError{Status: http.StatusServiceUnavailable,
		Msg: "zapret2 не установлен: нет файла " + s.paths.ZapretConfig}
}

// readConfig возвращает config для чтения: живой config zapret2, иначе
// config.default из каталога zator, иначе встроенный шаблон; installed
// сообщает, что использован живой config.
func (s *Server) readConfig() (c *config.Config, installed bool) {
	if c, err := config.Load(s.paths.ZapretConfig); err == nil {
		return c, true
	}
	if c, err := config.Load(s.defaultConfigPath()); err == nil {
		return c, false
	}
	if data, err := uiembed.ConfigDefaultAt(s.paths); err == nil {
		return config.Parse(string(data)), false
	}
	return config.Parse(""), false
}

func (s *Server) defaultConfigPath() string {
	return filepath.Join(s.paths.ConfigDir, "config.default")
}

// maxStrategy — число стратегий профиля по текущему config (для orchestra.Store).
func (s *Server) maxStrategy(id int) int {
	c, _ := s.readConfig()
	return c.ProfileMaxStrategyOrDefault(id)
}

// editConfigs применяет fn к живому config zapret2 и (по возможности) к
// config.default; запись выполняется только если fn не вернула ошибку.
func (s *Server) editConfigs(fn func(*config.Config) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	live, err := config.Load(s.paths.ZapretConfig)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.notInstalledErr()
		}
		return err
	}
	if err := fn(live); err != nil {
		return err
	}
	if err := live.Save(); err != nil {
		return err
	}
	if def, err := config.Load(s.defaultConfigPath()); err == nil {
		if fn(def) == nil {
			_ = def.Save()
		}
	}
	return nil
}

// --- служба ---

func (s *Server) zapretRunning(ctx context.Context) bool {
	if s.svc == nil {
		return service.IsNfqws2Running()
	}
	st, err := s.svc.Status(ctx, service.UnitZapret2)
	return err == nil && st.Running
}

// restartIfRunning перезапускает zapret2, если он запущен; restarted — рестарт выполнен.
// Использует transactional restart (Apply-gate + snapshot/rollback).
// Если рестарт нельзя (supersweep) — всё равно ApplyZapretRuntime, чтобы nfqws2.args
// совпадал с уже записанным config (иначе UI «ok» при рассинхроне).
func (s *Server) restartIfRunning(ctx context.Context) bool {
	if s.svc == nil || !s.zapretRunning(ctx) {
		return false
	}
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.sweepRunningLocked() {
		if s.app != nil {
			if _, err := s.app.ApplyZapretRuntime(); err != nil {
				s.app.WriteServiceWarnings([]string{"apply (supersweep): " + err.Error()})
			} else {
				s.app.WriteServiceWarnings([]string{"рестарт отложен: идёт supersweep (config/args уже применены)"})
			}
		}
		return false
	}
	if s.app != nil {
		err := s.app.RestartZapretTransactional(ctx, func(ctx context.Context) error {
			return s.svc.Restart(ctx, service.UnitZapret2)
		})
		if err != nil {
			s.app.WriteServiceWarnings([]string{err.Error()})
			return false
		}
		var warns []string
		if st, d := s.app.FwEnsureStatus(); st == "fail" && d != "" {
			warns = append(warns, "fw ensure: "+d)
		}
		s.app.StartNfqwsWatchdog()
		s.app.StartWebUIWatchdog()
		if len(warns) > 0 {
			s.app.WriteServiceWarnings(warns)
		} else {
			s.app.ClearServiceWarnings()
		}
		return true
	}
	return s.svc.Restart(ctx, service.UnitZapret2) == nil
}

// maybeRestart учитывает параметр restart=0 (отложить рестарт).
func (s *Server) maybeRestart(ctx context.Context, p params) bool {
	if p.Get("restart") == "0" {
		return false
	}
	return s.restartIfRunning(ctx)
}

// Close stops an active SuperSweep run and waits briefly for probe cleanup
// before daemon shutdown.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.sweepMu.Lock()
	sw := s.sweeper
	s.sweepMu.Unlock()
	if sw == nil || !sw.Running() {
		return
	}
	_ = sw.Cancel()
	if waiter, ok := sw.(interface{ Wait() (sweep.Report, error) }); ok {
		done := make(chan struct{})
		go func() {
			_, _ = waiter.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2500 * time.Millisecond):
		}
	}
}
