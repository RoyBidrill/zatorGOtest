package sweep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/fsutil"
	"github.com/AloofLibra/zator/internal/googlevideo"
	"github.com/AloofLibra/zator/internal/netcheck"
	"github.com/AloofLibra/zator/internal/orchestra"
	"github.com/AloofLibra/zator/internal/paths"
)

// Ошибки изолированной пробы.
var (
	// ErrProbe — изолированный пробник не запустился или не восстановился.
	ErrProbe = errors.New("sweep: изолированный пробник недоступен")
	// ErrIsolationLost — изоляция проб нарушена повторно; прогон остановлен.
	ErrIsolationLost = errors.New("sweep: изоляция проб нарушена")
)

// Config — конфигурация координатора.
type Config struct {
	// Dir — каталог прогресса (по умолчанию DefaultDir = /tmp/z2r-supersweep).
	Dir string
	// ArchiveDir — каталог с last-report.tsv (пусто — отчёт не сохраняется).
	ArchiveDir string

	// Store — рабочее хранилище, куда применяются выбранные победители.
	Store Locker
	// ProbeStore — отдельное приватное хранилище для всех пробных локов.
	ProbeStore Locker
	// Checker — проверка цели (обычно *netcheck.Checker).
	Checker TargetChecker
	// ResolveMedia prepares signed YouTube audio/video URLs before the isolated
	// nfqws2 probe is started; URLs stay in memory for this run only.
	ResolveMedia func(context.Context) (netcheck.YouTubeMedia, error)
	// Probe — изолированный nfqws2; по умолчанию NoopProbe.
	Probe Probe

	// MaxStrategy возвращает число стратегий профиля; по умолчанию
	// config.DefaultMaxStrategy. Обычно cfg.ProfileMaxStrategyOrDefault.
	MaxStrategy func(profile int) int
	// GVURL возвращает URL проверки googlevideo (кластер пользователя);
	// по умолчанию https://rr2---sn-4g5ednly.googlevideo.com/.
	GVURL func(ctx context.Context) string
	// Gate — необязательная предпроверка DNS (например (&netcheck.SpoofGate{}).Check);
	// при подмене прогон не начинается (ErrDNSSpoofed).
	Gate func(ctx context.Context) netcheck.GateResult

	// Sleep и Now подменяются в тестах.
	Sleep SleepFunc
	Now   func() time.Time
	// CancelPoll — период опроса cancel-файла (по умолчанию 200 мс).
	CancelPoll time.Duration
	// Logf — необязательный журнал (строки консоли прогона).
	Logf func(format string, args ...any)
	// OnComplete уведомляет владельца после сохранения итогового отчёта.
	OnComplete func(Report, error)

	// Paths используется для поиска h3-curl при подборе Профиля 5 (QUIC).
	Paths paths.Paths
	// QUICProbe подменяет вызов h3-curl при тестировании Профиля 5.
	QUICProbe func(ctx context.Context, strategy int, rounds int) netcheck.TargetResult
	// QUICSettleDelay задаёт паузу устаканивания лока П5 в живом режиме (по умолчанию >=3s).
	QUICSettleDelay time.Duration
}

// Params — параметры одного суперавтопрогона.
type Params struct {
	// QuickProfile selects one profile for a short strategy search (1, 2, 3, 4, or 5).
	// Zero keeps the full SuperSweep workflow.
	QuickProfile int
	// QuickAddress overrides the selected profile's default test URL.
	QuickAddress string
	// IncludeQUIC включает живую фазу Профиля 5 (HTTP/3 QUIC) в конец полного прогона.
	IncludeQUIC bool
	// QUICRounds задаёт число раундов QUIC-проверки на стратегию (1..5, по умолчанию 1).
	QUICRounds int
	// Scope — область локов ("" = default).
	Scope string
	// TLSPref — требование к версиям TLS: any|12|13|both.
	TLSPref netcheck.TLSPref
	// Pause — пауза между проверками YouTube/Googlevideo (включает Settle);
	// DSPause — для Discord (не меньше Pause); RKNPause — для РКН.
	Pause, DSPause, RKNPause time.Duration
	// GreenPause — пауза после зелёной стратегии с обеими TLS (0 — выключена).
	GreenPause time.Duration
	// PhasePause — пауза между фазами.
	PhasePause time.Duration
	// Settle — ожидание после записи лока (TTL кеша Lua).
	Settle time.Duration
	// RKNPar — параллельность РКН (хранится в статусе; проход домены по одному).
	RKNPar int
	// Domains — домены РКН; «example.com» или URL.
	Domains []string
	// MediaStatus — статус подготовки YouTube media URLs. "ready" означает,
	// что URLs доступны в памяти координатора; любая другая непустая строка
	// помечает результаты Googlevideo как unknown и не даёт выбрать победителя.
	MediaStatus string
}

// DefaultParams возвращает значения по умолчанию из supersweep.sh.
func DefaultParams() Params {
	return Params{
		Scope:      orchestra.ScopeDefault,
		TLSPref:    netcheck.PrefAny,
		Pause:      DefaultPause,
		DSPause:    3 * DefaultPause,
		RKNPause:   DefaultRKNPause,
		GreenPause: DefaultGreenPause,
		PhasePause: DefaultPhasePause,
		Settle:     DefaultSettle,
		RKNPar:     DefaultRKNPar,
		Domains:    append([]string(nil), DefaultRKNDomains...),
	}
}

// Normalize приводит параметры к допустимым: пауза Discord не меньше общей,
// RKNPar >= 1, TLSPref и Scope — каноничны, отрицательные паузы обнуляются.
func (p Params) Normalize() Params {
	for _, d := range []*time.Duration{&p.Pause, &p.DSPause, &p.RKNPause, &p.GreenPause, &p.PhasePause, &p.Settle} {
		if *d < 0 {
			*d = 0
		}
	}
	if p.DSPause < p.Pause {
		p.DSPause = p.Pause
	}
	if p.RKNPar < 1 {
		p.RKNPar = DefaultRKNPar
	}
	p.TLSPref = netcheck.ParseTLSPref(string(p.TLSPref))
	if p.Scope == "" {
		p.Scope = orchestra.ScopeDefault
	}
	if p.QUICRounds < 0 {
		p.QUICRounds = 0
	}
	if p.QUICRounds > 5 {
		p.QUICRounds = 5
	}
	return p
}

// EstimateTotal — ориентировочное время прогона (худший случай, без GreenPause):
// проба ≈ 6 с + пауза на каждую стратегию и межфазовые паузы.
func EstimateTotal(max1, max2, max4, max3, domains int, p Params) time.Duration {
	const probe = 6 * time.Second
	return time.Duration(max1)*(probe+p.Pause) + time.Duration(max2)*(probe+p.Pause) +
		time.Duration(max4)*(probe+p.DSPause) + time.Duration(domains*max3)*(probe+p.RKNPause) +
		3*p.PhasePause
}

type workerSpec struct {
	name    string
	profile int
	protos  []string
	label   string
	url     string
	max     int
	pause   time.Duration
}

// Coordinator — координатор суперавтопрогона: один прогон на каталог Dir.
type Coordinator struct {
	cfg Config

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	final   Report
	err     error
}

// New создаёт координатор.
func New(cfg Config) (*Coordinator, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: не задан Store", ErrConfig)
	}
	if cfg.ProbeStore == nil {
		return nil, fmt.Errorf("%w: не задан ProbeStore", ErrConfig)
	}
	if cfg.Checker == nil {
		return nil, fmt.Errorf("%w: не задан Checker", ErrConfig)
	}
	if cfg.Dir == "" {
		cfg.Dir = DefaultDir
	}
	cfg.Dir = filepath.Clean(cfg.Dir)
	if cfg.MaxStrategy == nil {
		cfg.MaxStrategy = config.DefaultMaxStrategy
	}
	if cfg.Probe == nil {
		cfg.Probe = NoopProbe{}
	}
	if cfg.CancelPoll <= 0 {
		cfg.CancelPoll = 200 * time.Millisecond
	}
	return &Coordinator{cfg: cfg}, nil
}

// Dir возвращает каталог прогресса.
func (c *Coordinator) Dir() string { return c.cfg.Dir }

func (c *Coordinator) lockDir() string { return c.cfg.Dir + ".lock" }

// Running сообщает, что прогон выполняется в этом процессе.
func (c *Coordinator) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Report возвращает отчёт по файлам каталога прогона (можно вызывать в любой момент).
func (c *Coordinator) Report() (Report, error) {
	return ReadReport(c.cfg.Dir, ReportOptions{ArchiveDir: c.cfg.ArchiveDir})
}

// Cancel просит активный прогон остановиться: создаёт файл cancel; воркеры
// остановятся на безопасном шаге, откат выполнит координатор. ErrNotRunning —
// если нет живого прогона.
func (c *Coordinator) Cancel() error {
	c.mu.Lock()
	running, cancel := c.running, c.cancel
	c.mu.Unlock()
	if !running {
		// Прогон мог идти в другом процессе.
		rep, err := c.Report()
		if err != nil || !rep.Active {
			return ErrNotRunning
		}
	}
	if err := os.WriteFile(filepath.Join(c.cfg.Dir, fileCancel), nil, 0o644); err != nil {
		return err
	}
	if cancel != nil {
		cancel()
	}
	return nil
}

// Wait блокируется до конца прогона, начатого Start, и возвращает итоговый отчёт.
func (c *Coordinator) Wait() (Report, error) {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done == nil {
		return Report{}, ErrNotRunning
	}
	<-done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.final, c.err
}

// Run выполняет суперавтопрогон и блокируется до конца. Возвращает итоговый
// отчёт. Отмена (ctx или cancel-файл) — не ошибка: state=cancelled. Ошибка —
// при невалидных параметрах, занятом lock, подмене DNS (до начала прогона)
// либо сбое записи пробного лока/пробника (прогон остановлен и откачен).
func (c *Coordinator) Run(ctx context.Context, p Params) (Report, error) {
	if err := c.Start(ctx, p); err != nil {
		return Report{}, err
	}
	return c.Wait()
}

// Start подготавливает прогон синхронно (проверки, lock, каталог, статус
// starting) и запускает его в горутине; Wait дожидается результата.
func (c *Coordinator) Start(ctx context.Context, p Params) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrBusy
	}
	c.running = true
	c.mu.Unlock()

	r, err := c.prepare(ctx, p)
	if err != nil {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.mu.Lock()
	c.cancel, c.done, c.final, c.err = cancel, done, Report{}, nil
	c.mu.Unlock()

	go func() {
		defer close(done)
		defer cancel()
		rep, err := r.execute(runCtx)
		c.mu.Lock()
		c.final, c.err, c.running, c.cancel = rep, err, false, nil
		c.mu.Unlock()
		if c.cfg.OnComplete != nil {
			c.cfg.OnComplete(rep, err)
		}
	}()
	return nil
}

// run — состояние одного прогона.
type run struct {
	c              *Coordinator
	p              Params
	targets        []DomainTarget
	maxes          map[int]int
	started        time.Time
	state          State
	alive          string
	mediaURLs      *netcheck.YouTubeMedia
	profileResults map[string]ProfileSweepResult
	rknResult      *RKNSweepResult

	errMu  sync.Mutex
	err    error
	cancel context.CancelFunc
}

func (c *Coordinator) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}

func (c *Coordinator) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

func (c *Coordinator) prepare(ctx context.Context, p Params) (*run, error) {
	p = p.Normalize()
	if p.QuickProfile < 0 || p.QuickProfile > 5 {
		return nil, fmt.Errorf("sweep: некорректный профиль быстрого подбора %d", p.QuickProfile)
	}
	domains := p.Domains
	if p.QuickProfile != 0 {
		domains = nil
		if strings.TrimSpace(p.QuickAddress) != "" {
			domains = []string{p.QuickAddress}
		}
	}
	targets, dropped := SanitizeDomains(domains)
	for _, d := range dropped {
		c.logf("Отброшен некорректный домен: %s", d)
	}
	if p.QuickProfile != 0 && strings.TrimSpace(p.QuickAddress) != "" && len(targets) == 0 {
		return nil, fmt.Errorf("sweep: некорректный адрес быстрого подбора")
	}
	if p.QuickProfile == 3 && len(targets) == 0 || p.QuickProfile == 0 && len(targets) == 0 {
		return nil, ErrNoDomains
	}
	maxes := map[int]int{}
	var reqProfiles []int
	switch {
	case p.QuickProfile == 5:
		reqProfiles = []int{5}
	case p.QuickProfile == 0 && p.IncludeQUIC:
		reqProfiles = []int{1, 2, 4, 3, 5}
	default:
		reqProfiles = []int{1, 2, 4, 3}
	}
	for _, prof := range reqProfiles {
		n := c.cfg.MaxStrategy(prof)
		if n < 1 {
			return nil, fmt.Errorf("%w: профиль %d", ErrNoStrategies, prof)
		}
		maxes[prof] = n
	}
	if c.cfg.Gate != nil {
		if g := c.cfg.Gate(ctx); g.Spoofed() {
			return nil, fmt.Errorf("%w: %s", ErrDNSSpoofed, g.Message)
		}
	}
	if err := c.acquireLock(); err != nil {
		return nil, err
	}
	r := &run{c: c, p: p, targets: targets, maxes: maxes, started: c.now(), state: StateIdle}
	if err := os.RemoveAll(c.cfg.Dir); err != nil {
		c.releaseLock()
		return nil, err
	}
	if err := os.MkdirAll(c.cfg.Dir, 0o755); err != nil {
		c.releaseLock()
		return nil, err
	}
	if err := r.setState(StateStarting); err != nil {
		c.releaseLock()
		return nil, err
	}
	return r, nil
}

// --- lock-каталог ---

func (c *Coordinator) acquireLock() error {
	lock := c.lockDir()
	if err := os.MkdirAll(filepath.Dir(lock), 0o755); err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		err := os.Mkdir(lock, 0o700)
		if err == nil {
			return os.WriteFile(filepath.Join(lock, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		pid, perr := strconv.Atoi(readFirstLine(filepath.Join(lock, "pid")))
		if perr == nil && pidAlive(pid) {
			return ErrBusy
		}
		if perr != nil {
			// pid ещё не записан соперником — не трогаем свежий lock.
			if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) < 2*time.Second {
				return ErrBusy
			}
		}
		// Остался после аварии: процесс мёртв.
		_ = os.RemoveAll(lock)
	}
	return ErrBusy
}

func (c *Coordinator) releaseLock() {
	lock := c.lockDir()
	removeIfExists(filepath.Join(lock, "pid"))
	_ = os.Remove(lock)
}

// ProbeGooglevideoCandidates проверяет ограниченный список стратегий для
// одного Googlevideo hostkey через изолированную profile-2 очередь. ProbeStore
// обязателен и отделён от рабочего Store; общий lock не даёт пересечься с
// SuperSweep. Проверенной считается только стратегия с успешными TLS 1.2/1.3
// и 64-КБ загрузкой без повторной попытки.
func (c *Coordinator) ProbeGooglevideoCandidates(ctx context.Context, fqdn string, candidates []int, media netcheck.YouTubeMedia, onTry func(int)) (selected int, detail string, retErr error) {
	if c.cfg.ProbeStore == nil {
		return 0, "", fmt.Errorf("%w: для Googlevideo probe нужен private ProbeStore", ErrConfig)
	}
	targets, dropped := SanitizeDomains([]string{fqdn})
	if len(dropped) != 0 || len(targets) != 1 || targets[0].Domain != strings.ToLower(strings.TrimSuffix(fqdn, ".")) {
		return 0, "", fmt.Errorf("%w: некорректный Googlevideo hostkey", ErrConfig)
	}
	if len(candidates) == 0 {
		return 0, "", fmt.Errorf("%w: пустой список стратегий", ErrConfig)
	}
	targetHostKey, ok := googlevideo.SNIHostKey(fqdn)
	if !ok {
		return 0, "", fmt.Errorf("%w: некорректный Googlevideo hostkey", ErrConfig)
	}
	videoHostKey, _ := googlevideo.SNIHostKey(media.VideoHost)
	audioHostKey, _ := googlevideo.SNIHostKey(media.AudioHost)
	if targetHostKey != videoHostKey && targetHostKey != audioHostKey {
		return 0, fmt.Sprintf("media_hostkey_mismatch: target=%s audio=%s video=%s", targetHostKey, audioHostKey, videoHostKey), nil
	}
	mediaChecker, ok := c.cfg.Checker.(MediaTargetCheckerWithTLS)
	if !ok {
		return 0, "", fmt.Errorf("%w: media checker unavailable", ErrConfig)
	}
	const profileGooglevideo = 2
	maxStrategy := c.cfg.MaxStrategy(profileGooglevideo)
	seen := make(map[int]bool, len(candidates))
	for _, strategy := range candidates {
		if strategy < 1 || strategy > maxStrategy || seen[strategy] {
			return 0, "", fmt.Errorf("%w: некорректная стратегия Googlevideo %d", ErrConfig, strategy)
		}
		seen[strategy] = true
	}
	if err := ctx.Err(); err != nil {
		return 0, "", err
	}
	if err := c.acquireLock(); err != nil {
		return 0, "", err
	}
	defer c.releaseLock()

	if err := c.cfg.Probe.Start(ctx, profileGooglevideo); err != nil {
		return 0, "", fmt.Errorf("%w: Googlevideo profile-2: %v", ErrProbe, err)
	}
	defer func() {
		if err := c.cfg.Probe.Stop(); err != nil && retErr == nil {
			selected = 0
			retErr = fmt.Errorf("%w: очистка Googlevideo probe: %v", ErrProbe, err)
		}
	}()

	for _, strategy := range candidates {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		if onTry != nil {
			onTry(strategy)
		}
		if err := c.cfg.ProbeStore.SetLock(orchestra.ScopeDefault, "2", "tls", orchestra.Strategy(strategy)); err != nil {
			return 0, "", fmt.Errorf("запись private Googlevideo lock %d: %w", strategy, err)
		}
		var err error
		if c.cfg.Sleep != nil {
			err = c.cfg.Sleep(ctx, DefaultSettle)
		} else {
			err = sleepCtx(ctx, DefaultSettle)
		}
		if err != nil {
			return 0, "", err
		}
		if !c.cfg.Probe.Healthy(ctx) {
			return 0, "", fmt.Errorf("%w: Googlevideo profile-2", ErrIsolationLost)
		}
		result := mediaChecker.CheckGooglevideoMediaURLsWithTLS(ctx, targets[0].URL, media, netcheck.PrefBoth)
		if !c.cfg.Probe.Healthy(ctx) {
			return 0, "", fmt.Errorf("%w: Googlevideo profile-2", ErrIsolationLost)
		}
		if result.TLS12Detail.CodeOK() && result.TLS13Detail.CodeOK() && result.Media != nil && result.Media.Class == netcheck.MediaPlay && result.Download != nil && result.Download.State == netcheck.DLOK && !result.Download.Retry {
			return strategy, result.Text, nil
		}
		mediaClass := netcheck.MediaUnknown
		if result.Media != nil {
			mediaClass = result.Media.Class
		}
		detail = fmt.Sprintf("strategy %d: TLS12=%d TLS13=%d media=%s download=%s", strategy, result.TLS12Detail.Code, result.TLS13Detail.Code, mediaClass, downloadState(result.Download))
	}
	return 0, detail, nil
}

func downloadState(download *netcheck.Download) string {
	if download == nil {
		return "missing"
	}
	return download.State
}

// --- состояние и статус ---

func (r *run) path(name string) string { return filepath.Join(r.c.cfg.Dir, name) }

func (r *run) setState(to State) error {
	if !CanTransition(r.state, to) {
		return fmt.Errorf("%w: %s -> %s", ErrBadTransition, r.state, to)
	}
	r.state = to
	return r.writeStatus()
}

func (r *run) writeStatus() error {
	var urls []string
	for _, t := range r.targets {
		urls = append(urls, t.URL)
	}
	return writeKV(r.path(fileStatus), kv{
		{"state", string(r.state)},
		{"scope", r.p.Scope},
		{"started", strconv.FormatInt(r.started.Unix(), 10)},
		{"updated", strconv.FormatInt(r.c.now().Unix(), 10)},
		{"tls_pref", string(r.p.TLSPref)},
		{"pause", strconv.Itoa(int(r.p.Pause.Seconds()))},
		{"settle", strconv.Itoa(int(r.p.Settle.Seconds()))},
		{"rkn_par", strconv.Itoa(r.p.RKNPar)},
		{"alive", r.alive},
		{"domains", strings.Join(urls, " ")},
		{"error", sanitizeReportError(r.firstErr())},
	})
}

var reportURLQueryRe = regexp.MustCompile(`(https?://[^\s?"'<>]+)\?[^\s"'<>]*`)

func sanitizeReportError(err error) string {
	if err == nil {
		return ""
	}
	s := reportURLQueryRe.ReplaceAllString(err.Error(), "$1")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > 300 {
		runes := []rune(s)
		s = string(runes[:297]) + "..."
	}
	return s
}

// fail запоминает первую ошибку и останавливает прогон.
func (r *run) fail(err error) {
	r.errMu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.errMu.Unlock()
	if msg := sanitizeReportError(err); msg != "" {
		r.c.logf("Прогон остановлен: %s", msg)
	}
	_ = r.writeStatus()
	_ = os.WriteFile(r.path(fileCancel), nil, 0o644)
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *run) firstErr() error {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

// --- выполнение ---

func (r *run) specs(gvURL string) []workerSpec {
	return []workerSpec{
		{WorkerYT, 1, []string{"tls", "http"}, netcheck.LabelYouTube, netcheck.URLYouTube, r.maxes[1], r.p.Pause},
		{WorkerGV, 2, []string{"tls"}, netcheck.LabelGooglevideo, gvURL, r.maxes[2], r.p.Pause},
		{WorkerDS, 4, []string{"tls"}, netcheck.LabelDiscord, netcheck.URLDiscord, r.maxes[4], r.p.DSPause},
	}
}

func (r *run) execute(ctx context.Context) (Report, error) {
	c := r.c
	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	defer cancel()

	// Наблюдатель cancel-файла: внешний процесс (WebUI) может остановить прогон.
	watchDone := make(chan struct{})
	go func() {
		t := time.NewTicker(c.cfg.CancelPoll)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if fileExists(r.path(fileCancel)) {
					cancel()
					return
				}
			case <-watchDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	defer close(watchDone)

	defer func() {
		_ = c.cfg.Probe.Stop()
		rep, _ := ReadReport(c.cfg.Dir, ReportOptions{Final: true})
		if c.cfg.ArchiveDir != "" && rep.Available {
			if err := fsutil.AtomicWriteFile(filepath.Join(c.cfg.ArchiveDir, LastReportFile), []byte(rep.TSV()), 0o644); err != nil {
				c.logf("Не удалось сохранить последний отчёт суперавтопрогона: %v", err)
			}
		}
		c.releaseLock()
	}()

	specs, phases := r.prepareWorkers(ctx)
	if ctx.Err() == nil {
		r.alive = strings.Join(phases, ",")
		if err := r.setState(StateRunning); err != nil {
			return Report{}, err
		}
	}

	cancelled := ctx.Err() != nil
	for i, phase := range phases {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		r.alive = phase
		_ = r.writeStatus()
		if err := r.runPhase(ctx, phase, specs); err != nil {
			r.fail(err)
		}
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		r.settleWorker(phase)
		if r.p.QuickProfile == 0 && phase != WorkerRKN && i < len(phases)-1 {
			c.logf("Пауза между фазами: %s", r.p.PhasePause)
			if err := r.sleep(ctx, r.p.PhasePause); err != nil {
				cancelled = true
				break
			}
		}
	}

	// До конца отката глушим отмену: откат и сводка не должны прерываться.
	r.alive = ""
	if cancelled {
		_ = r.setState(StateCancelled)
	} else {
		_ = r.setState(StateApplying)
		_ = r.setState(StateDone)
	}

	rep, _ := ReadReport(c.cfg.Dir, ReportOptions{Final: true})
	return rep, r.firstErr()
}

func (r *run) prepareWorkers(ctx context.Context) ([]workerSpec, []string) {
	c := r.c
	gvURL := "https://" + netcheck.FallbackClusterDomain + "/"
	needMedia := r.p.QuickProfile == 2 || r.p.QuickProfile == 5 || r.p.QuickProfile == 0
	if c.cfg.ResolveMedia != nil && needMedia && ctx.Err() == nil {
		media, err := c.cfg.ResolveMedia(ctx)
		if err != nil {
			r.p.MediaStatus = err.Error()
			c.logf("YouTube media probe: UNKNOWN (%s)", r.p.MediaStatus)
		} else {
			r.mediaURLs = &media
			r.p.MediaStatus = "ready"
			c.logf("YouTube media URLs готовы: audio=%s video=%s", media.AudioHost, media.VideoHost)
		}
	}
	if c.cfg.GVURL != nil {
		if u := c.cfg.GVURL(ctx); u != "" {
			gvURL = u
		}
	}
	specs := r.specs(gvURL)
	phases := append([]string(nil), Phases...)
	if r.p.QuickProfile == 0 && r.p.IncludeQUIC {
		specs = append(specs, workerSpec{WorkerQUIC, 5, []string{"udp"}, workerLabels[WorkerQUIC], "quic://googlevideo.com", r.maxes[5], r.p.Pause})
		phases = append(phases, WorkerQUIC)
	}
	if r.p.QuickProfile != 0 {
		switch r.p.QuickProfile {
		case 3:
			specs = nil
			phases = []string{WorkerRKN}
		case 5:
			specs = []workerSpec{{WorkerQUIC, 5, []string{"udp"}, workerLabels[WorkerQUIC], "quic://googlevideo.com", r.maxes[5], r.p.Pause}}
			phases = []string{WorkerQUIC}
		default:
			name := profileWorkers[r.p.QuickProfile]
			var selected []workerSpec
			for _, spec := range specs {
				if spec.name != name {
					continue
				}
				if r.p.QuickAddress != "" && len(r.targets) > 0 {
					spec.url = r.targets[0].URL
				}
				selected = append(selected, spec)
			}
			specs = selected
			phases = []string{name}
		}
	}
	r.writeRegistry(specs)
	r.collectPrev()
	if r.p.MediaStatus != "" {
		_ = fsutil.AtomicWriteFile(r.path(fileMediaStatus), []byte(r.p.MediaStatus+"\n"), 0o644)
	}

	return specs, phases
}

func (r *run) sleep(ctx context.Context, d time.Duration) error {
	if r.c.cfg.Sleep != nil {
		return r.c.cfg.Sleep(ctx, d)
	}
	return sleepCtx(ctx, d)
}

func (r *run) writeRegistry(specs []workerSpec) {
	var b strings.Builder
	for _, s := range specs {
		fmt.Fprintf(&b, "%s\t%s\tprofile\t%d\t%s\t%d\n", s.name, s.label, s.profile, s.url, s.max)
	}
	if r.p.QuickProfile != 0 && r.p.QuickProfile != 3 {
		_ = fsutil.AtomicWriteFile(r.path(fileWorkers), []byte(b.String()), 0o644)
		return
	}
	var doms []string
	for _, t := range r.targets {
		doms = append(doms, t.Domain)
	}
	fmt.Fprintf(&b, "%s\t%s\trkn\t3\t%s\t%d\n", WorkerRKN, workerLabels[WorkerRKN], strings.Join(doms, ","), r.maxes[3])
	_ = fsutil.AtomicWriteFile(r.path(fileWorkers), []byte(b.String()), 0o644)
}

// collectPrev сохраняет рабочие локи для сравнения в отчёте.
func (r *run) collectPrev() {
	type previous struct {
		kind, key, proto string
		value            orchestra.Strategy
	}
	var prev []previous
	add := func(kind, key, proto string) {
		v := orchestra.Strategy(orchestra.StrategyAuto)
		if s, err := r.c.cfg.Store.GetLock(r.p.Scope, key, proto); err == nil {
			v = s
		}
		prev = append(prev, previous{kind, key, proto, v})
	}
	add("profile", "1", "tls")
	add("profile", "1", "http")
	add("profile", "2", "tls")
	add("profile", "4", "tls")
	add("profile", "3", "tls")
	if r.p.IncludeQUIC || r.p.QuickProfile == 5 {
		add("profile", "5", "udp")
	}
	for _, t := range r.targets {
		add("domain", t.Domain, "tls")
	}
	var b strings.Builder
	for _, p := range prev {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", p.kind, p.key, p.proto, p.value)
	}
	_ = fsutil.AtomicWriteFile(r.path(filePrev), []byte(b.String()), 0o644)
}

// guarded проверяет здоровье изолированного пробника до и после пробы;
// потеря изоляции делает ответ недостоверным — проба повторяется один раз.
type guarded struct {
	r       *run
	inner   TargetChecker
	profile int
}

type probeReinstaller interface {
	Reinstall(context.Context) error
}

type sniPoolPinner interface {
	RefreshSNIPin()
}

func (g guarded) CheckTarget(ctx context.Context, label, url string) netcheck.TargetResult {
	return g.withProbe(ctx, label, url, func() netcheck.TargetResult {
		return g.inner.CheckTarget(ctx, label, url)
	})
}

func (g guarded) CheckGooglevideoMediaURLs(ctx context.Context, targetURL string, media netcheck.YouTubeMedia) netcheck.TargetResult {
	return g.CheckGooglevideoMediaURLsWithTLS(ctx, targetURL, media, netcheck.PrefBoth)
}

func (g guarded) CheckGooglevideoMediaURLsWithTLS(ctx context.Context, targetURL string, media netcheck.YouTubeMedia, pref netcheck.TLSPref) netcheck.TargetResult {
	checker, ok := g.inner.(MediaTargetChecker)
	withTLS, tlsOK := g.inner.(MediaTargetCheckerWithTLS)
	if !ok && !tlsOK {
		return unknownMediaTarget(targetURL, media.VideoID, "media_checker_unavailable")
	}
	return g.withProbe(ctx, netcheck.LabelGooglevideo, targetURL, func() netcheck.TargetResult {
		if tlsOK {
			return withTLS.CheckGooglevideoMediaURLsWithTLS(ctx, targetURL, media, pref)
		}
		return checker.CheckGooglevideoMediaURLs(ctx, targetURL, media)
	})
}

func unknownMediaTarget(targetURL, videoID, reason string) netcheck.TargetResult {
	m := &netcheck.MediaProbe{Class: netcheck.MediaUnknown, Text: "Медиапоток не подтверждён: " + reason,
		VideoID: videoID, ResolverStatus: reason}
	return netcheck.TargetResult{Label: netcheck.LabelGooglevideo, Target: targetURL, Verdict: netcheck.VerdictUnknown, Text: m.Text, Media: m}
}

func (g guarded) withProbe(ctx context.Context, label, url string, check func() netcheck.TargetResult) netcheck.TargetResult {
	if pinner, ok := g.r.c.cfg.Probe.(sniPoolPinner); ok {
		pinner.RefreshSNIPin()
	}
	var recoveryErr error
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := g.ensureHealthy(ctx); err != nil {
			if ctx.Err() == nil {
				g.r.fail(fmt.Errorf("%w: профиль %d: %v", ErrProbe, g.profile, err))
			}
			return netcheck.TargetResult{Label: label, Target: url}
		}
		res := check()
		recovered, err := g.ensureHealthy(ctx)
		if err == nil && !recovered {
			return res
		}
		recoveryErr = err
		if ctx.Err() != nil {
			return netcheck.TargetResult{Label: label, Target: url}
		}
	}
	if recoveryErr != nil {
		g.r.fail(fmt.Errorf("%w: профиль %d: %v", ErrIsolationLost, g.profile, recoveryErr))
	} else {
		g.r.fail(fmt.Errorf("%w: профиль %d", ErrIsolationLost, g.profile))
	}
	return netcheck.TargetResult{Label: label, Target: url}
}

// ensureHealthy mirrors the classic Zator recovery for Keenetic ndm: tolerate
// transient iptables contention, then reinstall probe transport before aborting.
func (g guarded) ensureHealthy(ctx context.Context) (bool, error) {
	probe := g.r.c.cfg.Probe
	var lastErr error
	sawUnhealthy := false
	for attempt := 0; attempt < 3; attempt++ {
		if probe.Healthy(ctx) {
			return sawUnhealthy, nil
		}
		sawUnhealthy = true
		if err := ctx.Err(); err != nil {
			return false, err
		}
		lastErr = ErrIsolationLost
		if attempt < 2 {
			if err := g.r.sleep(ctx, time.Second); err != nil {
				return false, err
			}
		}
	}
	if recoverer, ok := probe.(probeReinstaller); ok {
		lastErr = recoverer.Reinstall(ctx)
		if lastErr == nil && probe.Healthy(ctx) {
			return true, nil
		}
		if lastErr == nil {
			lastErr = ErrIsolationLost
		}
	}
	// Full restart remains a fallback for dead nfqws2 processes and nftables,
	// whose transport cannot be reinstalled independently.
	if startErr := probe.Start(ctx, g.profile); startErr == nil && probe.Healthy(ctx) {
		return true, nil
	} else if startErr != nil {
		lastErr = startErr
	}
	return false, fmt.Errorf("пробник не восстановлен после переустановки транспорта: %w", lastErr)
}

func (r *run) env(profile int) *Env {
	return &Env{
		Locks:   r.c.cfg.ProbeStore,
		Checker: guarded{r: r, inner: r.c.cfg.Checker, profile: profile},
		Scope:   r.p.Scope,
		Settle:  r.p.Settle,
		Sleep:   r.c.cfg.Sleep,
		Now:     r.c.cfg.Now,
	}
}

func (r *run) runPhase(ctx context.Context, phase string, specs []workerSpec) error {
	if phase == WorkerQUIC {
		var spec workerSpec
		for _, s := range specs {
			if s.name == WorkerQUIC {
				spec = s
			}
		}
		r.c.logf("=== Фаза %s (профиль 5, живой режим) ===", phase)
		return r.runQUIC(ctx, spec)
	}
	probeProfile := workerProfiles[phase]
	if err := r.c.cfg.Probe.Start(ctx, probeProfile); err != nil {
		return fmt.Errorf("%w: профиль %d: %v", ErrProbe, probeProfile, err)
	}
	defer func() {
		var last error
		for i := 0; i < 5; i++ {
			last = r.c.cfg.Probe.Stop()
			if last == nil {
				return
			}
			r.c.logf("probe Stop retry %d: %v", i+1, last)
			time.Sleep(200 * time.Millisecond)
		}
		if last != nil {
			r.c.logf("probe Stop incomplete: %v", last)
			_ = fsutil.AtomicWriteFile(r.path("cleanup_incomplete"), []byte(last.Error()+"\n"), 0o644)
		}
	}()
	r.c.logf("=== Фаза %s (профиль %d) ===", phase, probeProfile)

	if phase == WorkerRKN {
		return r.runRKN(ctx)
	}
	var spec workerSpec
	for _, s := range specs {
		if s.name == phase {
			spec = s
		}
	}
	return r.runProfile(ctx, spec)
}

func (r *run) runProfile(ctx context.Context, s workerSpec) error {
	env := r.env(s.profile)
	var mediaURLs *netcheck.YouTubeMedia
	if s.name == WorkerGV {
		mediaURLs = r.mediaURLs
	}
	res, err := env.AutoSweepProfile(ctx, ProfileSweepConfig{
		Name: s.name, Profile: s.profile, Protos: s.protos, Label: s.label, URL: s.url,
		Max: s.max, TLSPref: r.p.TLSPref, Pause: s.pause, GreenPause: r.p.GreenPause,
		MarkUnknown: s.name == WorkerGV && r.p.MediaStatus != "" && r.p.MediaStatus != "ready",
		MediaURLs:   mediaURLs,
		OnTry: func(n int) {
			_ = fsutil.AtomicWriteFile(r.path(currentFile(s.name)), []byte(s.url+"\t"+strconv.Itoa(n)+"\n"), 0o644)
		},
		OnRow: func(row ProgressRow) {
			_ = appendLine(r.path(progressFile(s.name)), row.TSV())
			_ = r.writeStatus()
		},
		OnPacing: func(n int, d time.Duration) {
			_ = appendLine(r.path(filePacing), fmt.Sprintf("%s\t%d\t%d", s.name, n, int(d.Seconds())))
		},
	})
	if r.profileResults == nil {
		r.profileResults = make(map[string]ProfileSweepResult)
	}
	r.profileResults[s.name] = res
	bestKind := res.BestKind
	_ = writeKV(r.path(bestFile(s.name)), kv{
		{"best", numOrEmpty(res.Best)},
		{"best_kind", bestKind},
		{"best_short", res.BestShort},
		{"greens", joinInts(res.Greens)},
		{"fulls", joinInts(res.Fulls)},
		{"warns", joinInts(res.Warns)},
		{"n_ok", strconv.Itoa(res.NOK)},
		{"n_warn", strconv.Itoa(res.NWarn)},
		{"n_fail", strconv.Itoa(res.NFail)},
		{"n_unknown", strconv.Itoa(res.NUnknown)},
		{"interrupted", b2s(res.Interrupted)},
	})
	_ = os.WriteFile(r.path(doneFile(s.name)), nil, 0o644)
	removeIfExists(r.path(currentFile(s.name)))
	return err
}

func (r *run) runQUIC(ctx context.Context, s workerSpec) error {
	c := r.c
	rounds := r.p.QUICRounds
	if rounds < 1 {
		rounds = 1
	}

	var probeFn func(ctx context.Context, strategy int, rounds int) netcheck.TargetResult
	if c.cfg.QUICProbe != nil {
		probeFn = c.cfg.QUICProbe
	} else {
		st := netcheck.DetectH3Curl(c.cfg.Paths)
		if !st.Found || r.mediaURLs == nil {
			reason := "h3-curl не установлен"
			if st.Found && r.mediaURLs == nil {
				reason = "не получен видеопоток YouTube"
			}
			c.logf("QUIC (профиль 5) пропущен: %s", reason)
			_ = writeKV(r.path(bestFile(s.name)), kv{
				{"best", ""},
				{"best_kind", ""},
				{"best_short", reason},
				{"interrupted", "0"},
			})
			_ = os.WriteFile(r.path(doneFile(s.name)), nil, 0o644)
			return nil
		}
		nc := netcheck.NewChecker(netcheck.DefaultOptions())
		if base, ok := c.cfg.Checker.(*netcheck.Checker); ok {
			nc = base
		}
		media := *r.mediaURLs
		curlPath := st.Path
		probeFn = func(pCtx context.Context, _ int, rnd int) netcheck.TargetResult {
			return nc.CheckQUICMedia(pCtx, curlPath, media, rnd)
		}
	}

	prevStrat, prevErr := c.cfg.Store.GetLock(r.p.Scope, "5", "udp")
	res := ProfileSweepResult{}
	restoreNeeded := true
	defer func() {
		if !restoreNeeded {
			return
		}
		// Независимое восстановление исходного лока П5 при отмене или отсутствии победителя.
		_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if prevErr == nil && prevStrat > 0 {
			if err := c.cfg.Store.SetLock(r.p.Scope, "5", "udp", prevStrat); err != nil {
				c.logf("Профиль 5: не удалось восстановить прежний лок %d: %v", prevStrat, err)
			}
		} else {
			if err := c.cfg.Store.ClearLock(r.p.Scope, "5", "udp"); err != nil {
				c.logf("Профиль 5: не удалось сбросить лок в auto: %v", err)
			}
		}
	}()

	settleDur := c.cfg.QUICSettleDelay
	if settleDur <= 0 {
		settleDur = r.p.Settle
		if c.cfg.QUICProbe == nil && settleDur < 3*time.Second {
			settleDur = 3 * time.Second
		}
	}

	for n := 1; n <= s.max; n++ {
		if ctx.Err() != nil {
			res.Interrupted = true
			break
		}
		_ = fsutil.AtomicWriteFile(r.path(currentFile(s.name)), []byte(s.url+"\t"+strconv.Itoa(n)+"\n"), 0o644)
		if err := c.cfg.Store.SetLock(r.p.Scope, "5", "udp", orchestra.Strategy(n)); err != nil {
			res.Interrupted = true
			return err
		}
		if settleDur > 0 {
			if err := r.sleep(ctx, settleDur); err != nil {
				res.Interrupted = true
				break
			}
		}
		tr := probeFn(ctx, n, rounds)
		if ctx.Err() != nil {
			res.Interrupted = true
			break
		}

		var tok, dlBytes, dlTime string
		switch tr.Verdict {
		case netcheck.VerdictOK:
			tok = TokenOK
			res.NOK++
			res.Greens = append(res.Greens, n)
			if res.Best == 0 || res.BestKind == BestKindWarn {
				res.Best = n
				res.BestKind = BestKindBest
				res.BestShort = tr.Text
			}
		case netcheck.VerdictWarn:
			tok = TokenWarn
			res.NWarn++
			res.Warns = append(res.Warns, n)
			if res.Best == 0 {
				res.Best = n
				res.BestKind = BestKindWarn
				res.BestShort = tr.Text
			}
		case netcheck.VerdictUnknown:
			tok = TokenUnknown
			res.NUnknown++
		default:
			tok = TokenFail
			res.NFail++
		}
		if tr.Download != nil {
			dlBytes = strconv.Itoa(tr.Download.Size)
			dlTime = tr.Download.Time
		}
		row := ProgressRow{
			Epoch:    c.now().Unix(),
			Target:   strconv.Itoa(s.profile),
			Strategy: n,
			Token:    tok,
			TLS12:    "h3",
			TLS13:    "-",
			DLBytes:  dlBytes,
			DLTime:   dlTime,
			Short:    tr.Text,
		}
		res.Rows = append(res.Rows, row)
		_ = appendLine(r.path(progressFile(s.name)), row.TSV())
		_ = r.writeStatus()

		if n < s.max && s.pause > 0 {
			_ = appendLine(r.path(filePacing), fmt.Sprintf("%s\t%d\t%d", s.name, n, int(s.pause.Seconds())))
			if err := r.sleep(ctx, s.pause); err != nil {
				res.Interrupted = true
				break
			}
		}
	}

	if !res.Interrupted && res.Best > 0 && res.BestKind == BestKindBest {
		// Есть зелёный победитель — оставляем его и не откатываем к сломанному исходному локу.
		restoreNeeded = false
	}

	if r.profileResults == nil {
		r.profileResults = make(map[string]ProfileSweepResult)
	}
	r.profileResults[s.name] = res
	_ = writeKV(r.path(bestFile(s.name)), kv{
		{"best", numOrEmpty(res.Best)},
		{"best_kind", res.BestKind},
		{"best_short", res.BestShort},
		{"greens", joinInts(res.Greens)},
		{"fulls", joinInts(res.Fulls)},
		{"warns", joinInts(res.Warns)},
		{"n_ok", strconv.Itoa(res.NOK)},
		{"n_warn", strconv.Itoa(res.NWarn)},
		{"n_fail", strconv.Itoa(res.NFail)},
		{"n_unknown", strconv.Itoa(res.NUnknown)},
		{"interrupted", b2s(res.Interrupted)},
	})
	_ = os.WriteFile(r.path(doneFile(s.name)), nil, 0o644)
	removeIfExists(r.path(currentFile(s.name)))
	return nil
}

func (r *run) runRKN(ctx context.Context) error {
	yt := map[int]string{}
	for _, row := range readTSV(r.path(progressFile(WorkerYT))) {
		if len(row) >= 4 && isPositiveInt(row[2]) {
			n, _ := strconv.Atoi(row[2])
			yt[n] = row[3]
		}
	}
	env := r.env(3)
	res, err := env.SweepRKN(ctx, RKNSweepConfig{
		Targets: r.targets, Max: r.maxes[3], Order: OrderStrategies(r.maxes[3], yt),
		TLSPref: r.p.TLSPref, Pause: r.p.RKNPause, GreenPause: r.p.GreenPause,
		OnTry: func(domain string, n int) {
			_ = fsutil.AtomicWriteFile(r.path(currentFile(WorkerRKN)), []byte(domain+"\t"+strconv.Itoa(n)+"\n"), 0o644)
		},
		OnRow: func(row ProgressRow, cov CoverageRow) {
			_ = appendLine(r.path(fileCoverage), cov.TSV())
			_ = appendLine(r.path(progressFile(WorkerRKN)), row.TSV())
			_ = r.writeStatus()
		},
		OnPacing: func(n int, d time.Duration) {
			_ = appendLine(r.path(filePacing), fmt.Sprintf("%s\t%d\t%d", WorkerRKN, n, int(d.Seconds())))
		},
	})
	r.rknResult = &res
	w := res.Winner
	_ = writeKV(r.path(bestFile(WorkerRKN)), kv{
		{"winner", numOrEmpty(w.OK)},
		{"winner_cover", strconv.Itoa(w.OKCover)},
		{"winner_total", strconv.Itoa(w.Total)},
		{"warn_winner", numOrEmpty(w.Warn)},
		{"warn_winner_cover", strconv.Itoa(w.WarnCover)},
		{"reference", res.Reference},
		{"interrupted", b2s(res.Interrupted)},
	})
	_ = os.WriteFile(r.path(doneFile(WorkerRKN)), nil, 0o644)
	removeIfExists(r.path(currentFile(WorkerRKN)))
	return err
}

func numOrEmpty(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// --- применение результатов ---

func (r *run) setLocks(profile string, protos []string, strategy int) error {
	for _, p := range protos {
		if err := r.c.cfg.Store.SetLock(r.p.Scope, profile, p, orchestra.Strategy(strategy)); err != nil {
			return err
		}
	}
	return nil
}

func (r *run) noteApplied(kind, target string, strategy int) {
	_ = appendLine(r.path(fileApplied), fmt.Sprintf("%s\t%s\t%d", kind, target, strategy))
}

// settleWorker применяет результат завершённой фазы через orchestra.Store:
// зелёная лучшая стратегия профиля; для РКН — зелёные победители доменов и
// профиль 3. Жёлтые результаты автоматически не применяются. Неполный проход
// не применяется, рабочие локи остаются без изменений.
func (r *run) settleWorker(name string) {
	if !fileExists(r.path(doneFile(name))) || fileExists(r.path(appliedDoneFile(name))) {
		return
	}
	pkey := workerProfiles[name]
	profile, hasProfile := r.profileResults[name]
	best := map[string]string{}
	if name == WorkerRKN {
		if r.rknResult == nil {
			best = readKV(r.path(bestFile(name)))
		}
	} else if !hasProfile {
		best = readKV(r.path(bestFile(name)))
	}
	marker := "none"
	finish := func() {
		_ = fsutil.AtomicWriteFile(r.path(appliedDoneFile(name)), []byte(marker+"\n"), 0o644)
	}

	interrupted := best["interrupted"] == "1"
	if name == WorkerRKN && r.rknResult != nil {
		interrupted = r.rknResult.Interrupted
	} else if hasProfile {
		interrupted = profile.Interrupted
	}
	if interrupted {
		finish()
		return
	}

	var winner int
	if name == WorkerRKN {
		if r.rknResult != nil {
			winner = r.rknResult.Winner.OK
		} else {
			winner = atoi(best["winner"])
		}
		var coverage []CoverageRow
		if r.rknResult != nil {
			coverage = r.rknResult.Coverage
		} else {
			coverage = parseCoverage(readTSV(r.path(fileCoverage)))
		}
		for _, d := range DomainWinners(coverage) {
			if d.Rank != 0 {
				continue
			}
			if err := r.setLocks(d.Domain, []string{"tls"}, d.Strategy); err != nil {
				r.c.logf("РКН: не удалось применить %s=%d: %v", d.Domain, d.Strategy, err)
				continue
			}
			r.noteApplied("domain", d.Domain, d.Strategy)
			r.c.logf("РКН: домен %s — применена стратегия %d", d.Domain, d.Strategy)
		}
		marker = "domains"
	} else if hasProfile {
		if profile.BestKind != BestKindWarn {
			winner = profile.Best
		}
	} else if best["best_kind"] != BestKindWarn {
		winner = atoi(best["best"])
	}

	protos := config.ProfileProtos(pkey)
	if name == WorkerYT {
		protos = []string{"tls", "http"}
	}
	switch {
	case winner > 0:
		if err := r.setLocks(strconv.Itoa(pkey), protos, winner); err != nil {
			r.c.logf("Профиль %d: не удалось применить стратегию %d: %v", pkey, winner, err)
			if name != WorkerRKN {
				marker = "error"
			}
		} else {
			if name != WorkerRKN {
				marker = strconv.Itoa(winner)
			}
			r.noteApplied("profile", strconv.Itoa(pkey), winner)
			r.c.logf("Профиль %d: применена стратегия %d", pkey, winner)
		}
	case name == WorkerRKN:
		r.c.logf("РКН: зелёного покрытия нет — профильная строка не менялась")
	}
	finish()
}
