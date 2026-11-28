package sweep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AloofLibra/zator/internal/netcheck"
	"github.com/AloofLibra/zator/internal/orchestra"
)

const gvTestURL = "https://gv.test/"

type coordEnv struct {
	t       *testing.T
	st      *orchestra.Store // рабочее хранилище
	probeSt *orchestra.Store // приватное хранилище проб (изолированный режим), иначе nil
	chk     *scripted
	dir     string
	archive string
	probe   *recordingProbe
	c       *Coordinator
}

func fullMax(profile int) int {
	switch profile {
	case 3:
		return 3
	default:
		return 4
	}
}

func tinyMax(int) int { return 1 }

// fullScenario: профиль 1 — лучшая 3, профиль 2 — 1, профиль 4 — только жёлтая,
// РКН — победитель 2, a.com → 3, b.org → 2 (при TLSPref=both).
func fullScenario(key string, s int) netcheck.TargetResult {
	switch key {
	case "1":
		switch s {
		case 2:
			return resGood("2.0")
		case 3:
			return resGood("0.5")
		case 4:
			return resOnly12()
		}
	case "2":
		if s == 1 {
			return resGood("1.0")
		}
	case "4":
		if s == 2 {
			return resOnly12()
		}
	case "a.com":
		switch s {
		case 2:
			return resGood("1.0")
		case 3:
			return resGood("0.5")
		}
	case "b.org":
		if s == 2 {
			return resGood("1.0")
		}
	}
	return resFail()
}

func newCoordEnv(t *testing.T, decide func(string, int) netcheck.TargetResult, mod func(*Config)) *coordEnv {
	t.Helper()
	e := &coordEnv{t: t, st: newStore(t), probe: &recordingProbe{}}
	e.dir = filepath.Join(t.TempDir(), "supersweep")
	e.archive = t.TempDir()
	keyFor := map[string]string{
		netcheck.URLYouTube: "1", gvTestURL: "2", netcheck.URLDiscord: "4",
		"https://a.com/": "a.com", "https://b.org/": "b.org",
	}
	e.probeSt = newStore(t)
	e.chk = newScripted(e.probeSt, keyFor, decide)
	cfg := Config{
		Dir: e.dir, ArchiveDir: e.archive, Store: e.st, Checker: e.chk, Probe: e.probe,
		MaxStrategy: fullMax,
		GVURL:       func(context.Context) string { return gvTestURL },
		Sleep:       (&sleepRec{}).sleep,
		CancelPoll:  5 * time.Millisecond,
	}
	cfg.ProbeStore = e.probeSt
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	return e
}

func fastParams() Params {
	return Params{TLSPref: netcheck.PrefBoth, Domains: []string{"a.com", "b.org"}, RKNPar: 1}
}

func (e *coordEnv) setPrev() {
	e.t.Helper()
	mustSet(e.t, e.st, "1", "tls", 9)
	mustSet(e.t, e.st, "1", "http", 9)
	mustSet(e.t, e.st, "4", "tls", 11)
	mustSet(e.t, e.st, "a.com", "tls", 1)
}

func (e *coordEnv) lock(profile, proto string) orchestra.Strategy {
	e.t.Helper()
	return mustGet(e.t, e.st, profile, proto)
}

func (e *coordEnv) wantLock(profile, proto string, want int) {
	e.t.Helper()
	if got := e.lock(profile, proto); got != orchestra.Strategy(want) {
		e.t.Errorf("lock %s/%s = %v, want %d", profile, proto, got, want)
	}
}

func (e *coordEnv) wantUnset(profile, proto string) {
	e.t.Helper()
	if got := e.lock(profile, proto); !got.IsAuto() {
		e.t.Errorf("lock %s/%s = %v, want unset", profile, proto, got)
	}
}

func (e *coordEnv) lockDirGone() {
	e.t.Helper()
	if _, err := os.Stat(e.dir + ".lock"); !os.IsNotExist(err) {
		e.t.Errorf("lock dir must be removed (err=%v)", err)
	}
}

func worker(t *testing.T, rep Report, name string) WorkerReport {
	t.Helper()
	for _, w := range rep.Workers {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("worker %s not found in %+v", name, rep.Workers)
	return WorkerReport{}
}

func TestCoordinator_FullRun(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()

	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.State != StateDone || rep.Active || rep.Phase != "" || !rep.Available || rep.Source != SourceLive {
		t.Fatalf("report: %+v", rep)
	}
	if rep.Completed != 18 || rep.Total != 18 {
		t.Errorf("progress %d/%d, want 18/18", rep.Completed, rep.Total)
	}

	// Применённые и откаченные локи.
	e.wantLock("1", "tls", 3)
	e.wantLock("1", "http", 3)
	e.wantLock("2", "tls", 1)
	e.wantLock("4", "tls", 11) // жёлтая автоматически не применяется — прежний лок
	e.wantLock("3", "tls", 2)
	e.wantLock("a.com", "tls", 3)
	e.wantLock("b.org", "tls", 2)

	yt, gv, ds, rkn := worker(t, rep, "yt"), worker(t, rep, "gv"), worker(t, rep, "ds"), worker(t, rep, "rkn")
	if yt.OK != 2 || yt.Warn != 1 || yt.Fail != 1 || yt.Greens != "2 3" || yt.Warns != "4" || yt.Applied != "3" || yt.Completed != 4 {
		t.Errorf("yt = %+v", yt)
	}
	if gv.OK != 1 || gv.Fail != 3 || gv.Applied != "1" {
		t.Errorf("gv = %+v", gv)
	}
	if ds.Warn != 1 || ds.Warns != "2" || ds.Applied != "" {
		t.Errorf("ds = %+v", ds)
	}
	if rkn.Completed != 6 || rkn.Total != 6 || rkn.Applied != "2" {
		t.Errorf("rkn = %+v", rkn)
	}
	if len(rep.Applied) != 5 {
		t.Errorf("applied = %+v", rep.Applied)
	}
	if len(rep.Domains) != 2 || rep.Domains[0].Applied == nil || *rep.Domains[0].Applied != 3 ||
		rep.Domains[1].Applied == nil || *rep.Domains[1].Applied != 2 {
		t.Errorf("domains = %+v", rep.Domains)
	}

	// Файлы прогресса.
	for _, f := range []string{"status", "workers.tsv", "prev.tsv", "coverage.tsv", "applied.tsv", "pacing.tsv",
		"progress.yt.tsv", "progress.gv.tsv", "progress.ds.tsv", "progress.rkn.tsv",
		"best.yt", "best.rkn", "done.yt", "done.rkn", "applied.done.yt", "applied.done.rkn"} {
		if !fileExists(filepath.Join(e.dir, f)) {
			t.Errorf("missing %s", f)
		}
	}
	for _, f := range []string{"current.yt", "current.gv", "current.rkn", "cancel"} {
		if fileExists(filepath.Join(e.dir, f)) {
			t.Errorf("%s must not exist after a clean run", f)
		}
	}
	if marker := readFirstLine(filepath.Join(e.dir, "applied.done.yt")); marker != "3" {
		t.Errorf("applied.done.yt = %q", marker)
	}
	if marker := readFirstLine(filepath.Join(e.dir, "applied.done.ds")); marker != "none" {
		t.Errorf("applied.done.ds = %q", marker)
	}
	prev := string(mustRead(t, filepath.Join(e.dir, "prev.tsv")))
	for _, want := range []string{"profile\t1\ttls\t9", "profile\t4\ttls\t11", "profile\t2\ttls\tauto", "domain\ta.com\ttls\t1", "domain\tb.org\ttls\tauto"} {
		if !strings.Contains(prev, want) {
			t.Errorf("prev.tsv missing %q:\n%s", want, prev)
		}
	}
	status := readKV(filepath.Join(e.dir, "status"))
	if status["state"] != "done" || status["tls_pref"] != "both" || status["alive"] != "" || status["domains"] != "https://a.com/ https://b.org/" {
		t.Errorf("status = %v", status)
	}

	// Сохранённый отчёт и освобождение lock.
	saved := string(mustRead(t, filepath.Join(e.archive, LastReportFile)))
	if !strings.HasPrefix(saved, "R\tdone\t0\t") || !strings.Contains(saved, "\nA\tprofile\t1\t3\n") {
		t.Errorf("last-report.tsv:\n%s", saved)
	}
	e.lockDirGone()
	if e.c.Running() {
		t.Error("Running must be false after Run")
	}

	// Пробы шли в порядке фаз yt, gv, ds, rkn и каждая фаза останавливала пробник.
	if got := e.probe.startList(); len(got) != 4 || got[0] != 1 || got[1] != 2 || got[2] != 4 || got[3] != 3 {
		t.Errorf("probe starts = %v", got)
	}
	if e.probe.stops < 4 {
		t.Errorf("probe stops = %d", e.probe.stops)
	}
	// РКН идёт в порядке «зелёные YouTube сначала»: 2,3 затем красная 1.
	var rknOrder []string
	for _, l := range e.chk.callLog() {
		if strings.HasPrefix(l, "a.com:") {
			rknOrder = append(rknOrder, l)
		}
	}
	if strings.Join(rknOrder, ",") != "a.com:2,a.com:3,a.com:1" {
		t.Errorf("rkn order = %v", rknOrder)
	}
}

func TestCoordinator_PollDuringRun(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	var seen Report
	var polled bool
	e.chk.hook = func(call int, key string, s int, _ context.Context) {
		if call != 6 { // yt: 4 проверки, gv: первая завершена, идёт вторая
			return
		}
		polled = true
		seen, _ = e.c.Report()
	}
	if _, err := e.c.Run(context.Background(), fastParams()); err != nil {
		t.Fatal(err)
	}
	if !polled {
		t.Fatal("hook not reached")
	}
	if !seen.Active || seen.State != StateRunning || seen.Phase != "gv" {
		t.Fatalf("live report: %+v", seen)
	}
	yt, gv := worker(t, seen, "yt"), worker(t, seen, "gv")
	if yt.Completed != 4 || yt.Applied != "3" {
		t.Errorf("yt live = %+v", yt)
	}
	if gv.Completed != 1 || gv.CurrentStrategy == nil || *gv.CurrentStrategy != 2 || gv.CurrentTarget != gvTestURL {
		t.Errorf("gv live = %+v", gv)
	}
	if seen.Completed != 5 || seen.Total != 18 {
		t.Errorf("live progress %d/%d", seen.Completed, seen.Total)
	}
	if len(seen.Applied) != 1 || seen.Applied[0] != (AppliedRow{"profile", "1", 3}) {
		t.Errorf("live applied = %+v", seen.Applied)
	}
}

func TestCoordinator_QuickProfileAppliesOnlySelectedWinner(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	address := "https://custom.youtube.com/watch"
	e.chk.keyFor[address] = "1"
	p := Params{QuickProfile: 1, QuickAddress: address, TLSPref: netcheck.PrefBoth}
	rep, err := e.c.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 4 || len(rep.Workers) != 1 || rep.Workers[0].Name != WorkerYT || rep.Workers[0].Total != 4 {
		t.Fatalf("quick report = %+v", rep)
	}
	if got := e.lock("1", "tls"); got != 3 {
		t.Errorf("quick winner lock = %s, want 3", got)
	}
	if got := e.lock("4", "tls"); got != 11 {
		t.Errorf("unselected profile lock changed: %s", got)
	}
	if starts := e.probe.startList(); len(starts) != 1 || starts[0] != 1 {
		t.Errorf("quick probe phases = %v", starts)
	}
}

func TestCoordinator_CancelKeepsPrev(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	e.chk.hook = func(call int, _ string, _ int, _ context.Context) {
		if call == 3 {
			if err := e.c.Cancel(); err != nil {
				t.Errorf("Cancel: %v", err)
			}
		}
	}
	if err := e.c.Start(context.Background(), fastParams()); err != nil {
		t.Fatal(err)
	}
	rep, err := e.c.Wait()
	if err != nil {
		t.Fatalf("cancel is not an error: %v", err)
	}
	if rep.State != StateCancelled || rep.Active {
		t.Fatalf("report: %+v", rep)
	}
	if rep.Error != "" {
		t.Errorf("cancel must not set report error: %q", rep.Error)
	}
	e.wantLock("1", "tls", 9)
	e.wantLock("1", "http", 9)
	e.wantLock("4", "tls", 11)
	e.wantLock("a.com", "tls", 1)
	e.wantUnset("2", "tls")
	if len(rep.Applied) != 0 {
		t.Errorf("nothing must be applied: %+v", rep.Applied)
	}
	if !fileExists(filepath.Join(e.dir, "cancel")) {
		t.Error("cancel file must exist")
	}
	if yt := worker(t, rep, "yt"); yt.Completed != 2 {
		t.Errorf("yt completed = %d, want 2 (third probe was cancelled)", yt.Completed)
	}
	saved := string(mustRead(t, filepath.Join(e.archive, LastReportFile)))
	if !strings.HasPrefix(saved, "R\tcancelled\t") {
		t.Errorf("saved:\n%s", saved)
	}
	e.lockDirGone()
	if err := e.c.Cancel(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Cancel after finish: %v", err)
	}
	// Повторный запуск после отмены допустим и очищает каталог.
	e.chk.hook = nil
	rep, err = e.c.Run(context.Background(), fastParams())
	if err != nil || rep.State != StateDone {
		t.Fatalf("re-run: %v %+v", err, rep)
	}
	if fileExists(filepath.Join(e.dir, "cancel")) {
		t.Error("cancel file must be wiped by the next run")
	}
}

func TestCoordinator_CancelFileFromAnotherProcess(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	// yt и gv применяются, затем cancel-файл (как от WebUI) останавливает фазу ds.
	e.setPrev()
	mustSet(t, e.st, "2", "tls", 8)
	e.chk.hook = func(call int, key string, s int, ctx context.Context) {
		if key != "4" || s != 2 {
			return
		}
		if err := os.WriteFile(filepath.Join(e.dir, "cancel"), nil, 0o644); err != nil {
			t.Error(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("cancel file watcher did not stop the run")
		}
	}
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateCancelled {
		t.Fatalf("state = %s", rep.State)
	}
	// Уже применённые фазы сохраняются.
	e.wantLock("1", "tls", 3)
	e.wantLock("1", "http", 3)
	e.wantLock("2", "tls", 1)
	// Прерванная фаза не меняет рабочие локи.
	e.wantLock("4", "tls", 11)
	e.wantLock("a.com", "tls", 1)
	e.wantUnset("b.org", "tls")
	if worker(t, rep, "yt").Applied != "3" || worker(t, rep, "gv").Applied != "1" {
		t.Errorf("workers: %+v", rep.Workers)
	}
}

func TestCoordinator_ContextCancel(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	ctx, cancel := context.WithCancel(context.Background())
	e.chk.hook = func(call int, _ string, _ int, _ context.Context) {
		if call == 2 {
			cancel()
		}
	}
	rep, err := e.c.Run(ctx, fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateCancelled {
		t.Errorf("state = %s", rep.State)
	}
	if rep.Error != "" {
		t.Errorf("context cancel must not set report error: %q", rep.Error)
	}
	e.wantLock("1", "tls", 9)
	e.lockDirGone()
}

func TestCoordinator_Busy(t *testing.T) {
	release := make(chan struct{})
	e := newCoordEnv(t, fullScenario, nil)
	entered := make(chan struct{})
	var once bool
	e.chk.hook = func(call int, _ string, _ int, ctx context.Context) {
		if call == 1 && !once {
			once = true
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}
	if err := e.c.Start(context.Background(), fastParams()); err != nil {
		t.Fatal(err)
	}
	<-entered
	if !e.c.Running() {
		t.Error("Running must be true")
	}
	if err := e.c.Start(context.Background(), fastParams()); !errors.Is(err, ErrBusy) {
		t.Errorf("second Start in same coordinator: %v", err)
	}
	// Другой координатор на тот же каталог (другой «процесс» с живым pid).
	other, err := New(Config{Dir: e.dir, Store: e.st, ProbeStore: e.probeSt, Checker: e.chk})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Start(context.Background(), fastParams()); !errors.Is(err, ErrBusy) {
		t.Errorf("foreign coordinator: %v", err)
	}
	if _, err := other.Wait(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Wait without Start: %v", err)
	}
	// Состояние ещё читается, пока прогон идёт.
	if rep, _ := other.Report(); !rep.Active || rep.State != StateRunning {
		t.Errorf("report from the other coordinator: %+v", rep)
	}
	close(release)
	rep, err := e.c.Wait()
	if err != nil || rep.State != StateDone {
		t.Fatalf("Wait: %v %+v", err, rep)
	}
	e.lockDirGone()
}

func TestCoordinator_StaleAndFreshLockDir(t *testing.T) {
	e := newCoordEnv(t, fullScenario, func(c *Config) { c.MaxStrategy = tinyMax })
	// Lock от умершего процесса снимается.
	writeFile(t, filepath.Join(e.dir+".lock", "pid"), "999999999\n")
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil || rep.State != StateDone {
		t.Fatalf("stale lock must be reclaimed: %v %+v", err, rep)
	}
	e.lockDirGone()

	// Свежий lock без pid — соперник только что создал каталог.
	if err := os.MkdirAll(e.dir+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Run(context.Background(), fastParams()); !errors.Is(err, ErrBusy) {
		t.Errorf("fresh lock without pid: %v", err)
	}
	if e.c.Running() {
		t.Error("Running must be reset after failed start")
	}
}

func TestCoordinator_DNSGate(t *testing.T) {
	spoofed := netcheck.GateResult{Code: netcheck.GateSpoofed, Verdict: netcheck.GateVerdictSpoofed, Message: "DNS подменён"}
	e := newCoordEnv(t, fullScenario, func(c *Config) {
		c.MaxStrategy = tinyMax
		c.Gate = func(context.Context) netcheck.GateResult { return spoofed }
	})
	_, err := e.c.Run(context.Background(), fastParams())
	if !errors.Is(err, ErrDNSSpoofed) || !strings.Contains(err.Error(), "DNS подменён") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(e.dir); !os.IsNotExist(serr) {
		t.Error("progress dir must not be created when the gate fails")
	}
	e.lockDirGone()
	if rep, _ := e.c.Report(); rep.State != StateIdle {
		t.Errorf("report after refused start: %+v", rep)
	}
	if len(e.chk.callLog()) != 0 {
		t.Error("no probes may run")
	}

	// Неопределённый вердикт не блокирует прогон.
	e2 := newCoordEnv(t, fullScenario, func(c *Config) {
		c.MaxStrategy = tinyMax
		c.Gate = func(context.Context) netcheck.GateResult {
			return netcheck.GateResult{Code: netcheck.GateUnknown, Verdict: netcheck.GateVerdictUnknown}
		}
	})
	if rep, err := e2.c.Run(context.Background(), fastParams()); err != nil || rep.State != StateDone {
		t.Errorf("unknown gate: %v %+v", err, rep)
	}
}

func TestCoordinator_ParamValidation(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	if _, err := e.c.Run(context.Background(), Params{QuickProfile: 6}); err == nil {
		t.Error("invalid quick profile must be rejected")
	}
	if _, err := e.c.Run(context.Background(), Params{QuickProfile: 1, QuickAddress: "not a URL"}); err == nil {
		t.Error("invalid quick address must be rejected")
	}
	p := fastParams()
	p.Domains = []string{"bad", "1", ""}
	if _, err := e.c.Run(context.Background(), p); !errors.Is(err, ErrNoDomains) {
		t.Errorf("no valid domains: %v", err)
	}
	e2 := newCoordEnv(t, fullScenario, func(c *Config) {
		c.MaxStrategy = func(p int) int {
			if p == 4 {
				return 0
			}
			return 2
		}
	})
	if _, err := e2.c.Run(context.Background(), fastParams()); !errors.Is(err, ErrNoStrategies) {
		t.Errorf("no strategies: %v", err)
	}
	e2.lockDirGone()

	if _, err := New(Config{Checker: e.chk}); !errors.Is(err, ErrConfig) {
		t.Errorf("nil store: %v", err)
	}
	if _, err := New(Config{Store: e.st}); !errors.Is(err, ErrConfig) {
		t.Errorf("nil checker: %v", err)
	}
	if err := e.c.Cancel(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Cancel when idle: %v", err)
	}
	if _, err := e.c.Wait(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Wait before Start: %v", err)
	}
	if c, _ := New(Config{Store: e.st, ProbeStore: e.probeSt, Checker: e.chk}); c.Dir() != filepath.Clean(DefaultDir) {
		t.Errorf("default dir = %q", c.Dir())
	}
}

func TestCoordinator_DomainsSanitizedInReport(t *testing.T) {
	e := newCoordEnv(t, fullScenario, func(c *Config) { c.MaxStrategy = tinyMax })
	var logs []string
	e.c.cfg.Logf = func(f string, a ...any) { logs = append(logs, f) }
	p := fastParams()
	p.Domains = []string{"A.com", "junk", "https://b.org/"}
	rep, err := e.c.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Domains) != 2 || rep.Domains[0].Domain != "a.com" {
		t.Errorf("domains = %+v", rep.Domains)
	}
	var dropped bool
	for _, l := range logs {
		if strings.Contains(l, "Отброшен") {
			dropped = true
		}
	}
	if !dropped {
		t.Error("dropped domain must be logged")
	}
}

func TestCoordinator_MediaStatusMakesGoogleVideoUnknown(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	mustSet(t, e.st, "2", "tls", 6)
	p := fastParams()
	p.MediaStatus = "resolver_unavailable"
	rep, err := e.c.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	gv := worker(t, rep, "gv")
	if gv.Warn != 1 || gv.OK != 0 || gv.Applied != "" {
		t.Errorf("gv = %+v", gv)
	}
	if !strings.Contains(gv.Label, "Media UNKNOWN: resolver_unavailable") {
		t.Errorf("label = %q", gv.Label)
	}
	// unknown без победителя: прежний лок профиля остаётся.
	e.wantLock("2", "tls", 6)
	if got := strings.TrimSpace(string(mustRead(t, filepath.Join(e.dir, "media-status")))); got != "resolver_unavailable" {
		t.Errorf("media-status = %q", got)
	}

	// Готовая медиапроверка: gv остаётся обычным, метка — [media TCP].
	e2 := newCoordEnv(t, fullScenario, nil)
	p.MediaStatus = "ready"
	rep, err = e2.c.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if gv := worker(t, rep, "gv"); gv.OK != 1 || !strings.Contains(gv.Label, "[media TCP]") || gv.Applied != "1" {
		t.Errorf("ready gv = %+v", gv)
	}
}

func TestCoordinatorResolvesMediaBeforeIsolatedGVPhase(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.c.cfg.ResolveMedia = func(context.Context) (netcheck.YouTubeMedia, error) {
		if len(e.probe.startList()) != 0 {
			t.Fatal("Innertube URLs must be prepared before the isolated probe starts")
		}
		return netcheck.YouTubeMedia{VideoID: netcheck.DefaultYouTubeVideoID,
			AudioURL:  "https://rr1---sn-a.googlevideo.com/videoplayback?sig=a&expire=1999999999",
			VideoURL:  "https://rr2---sn-b.googlevideo.com/videoplayback?sig=b&expire=1999999999",
			AudioHost: "rr1---sn-a.googlevideo.com", VideoHost: "rr2---sn-b.googlevideo.com"}, nil
	}
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil {
		t.Fatal(err)
	}
	gv := worker(t, rep, WorkerGV)
	if gv.OK != 1 || gv.Applied != "1" || !strings.Contains(gv.Label, "[media TCP]") {
		t.Fatalf("media-backed GV result = %+v", gv)
	}
	if got := strings.TrimSpace(string(mustRead(t, filepath.Join(e.dir, fileMediaStatus)))); got != "ready" {
		t.Fatalf("media status = %q", got)
	}
}

func TestCoordinator_NoGreenKeepsPrevLocks(t *testing.T) {
	e := newCoordEnv(t, func(string, int) netcheck.TargetResult { return resFail() }, nil)
	e.setPrev()
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateDone || len(rep.Applied) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	e.wantLock("1", "tls", 9)
	e.wantLock("1", "http", 9)
	e.wantLock("4", "tls", 11)
	e.wantLock("a.com", "tls", 1)
	e.wantUnset("2", "tls")
	e.wantUnset("3", "tls")
	e.wantUnset("b.org", "tls")
	for _, d := range rep.Domains {
		if d.Verdict != TokenFail || d.BestStrategy != nil || d.Applied != nil {
			t.Errorf("domain = %+v", d)
		}
	}
}

// --- изолированный режим и пробник ---

func TestCoordinator_IsolatedModeDoesNotTouchStoreUntilApply(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateDone {
		t.Fatalf("state = %s", rep.State)
	}
	// Победители применены в рабочее хранилище.
	e.wantLock("1", "tls", 3)
	e.wantLock("2", "tls", 1)
	e.wantLock("3", "tls", 2)
	e.wantLock("a.com", "tls", 3)
	// Прежние локи без победителя не тронуты (в том числе не откатывались).
	e.wantLock("4", "tls", 11)
	// Пробные локи жили в приватном хранилище.
	if got := mustGet(t, e.probeSt, "4", "tls"); got.IsAuto() {
		t.Error("probe store must contain trial locks")
	}
}

func TestCoordinator_IsolatedCancelLeavesStoreUntouched(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	e.chk.hook = func(call int, _ string, _ int, _ context.Context) {
		if call == 3 {
			_ = e.c.Cancel()
		}
	}
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil || rep.State != StateCancelled {
		t.Fatalf("%v %+v", err, rep)
	}
	e.wantLock("1", "tls", 9)
	e.wantLock("a.com", "tls", 1)
	e.wantUnset("2", "tls")
}

func TestCoordinator_ProbeStartFailureStopsRun(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	e.probe.startErr = map[int]error{2: errors.New("boom")}
	rep, err := e.c.Run(context.Background(), fastParams())
	if !errors.Is(err, ErrProbe) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if rep.State != StateCancelled {
		t.Errorf("state = %s", rep.State)
	}
	if !strings.Contains(rep.Error, "boom") {
		t.Errorf("expected error in report, got %q", rep.Error)
	}
	if liveRep, rerr := e.c.Report(); rerr != nil || !strings.Contains(liveRep.Error, "boom") {
		t.Errorf("Report() error = %q (%v)", liveRep.Error, rerr)
	}
	savedRep, serr := ReadReport(filepath.Join(t.TempDir(), "absent"), ReportOptions{ArchiveDir: e.archive})
	if serr != nil || !strings.Contains(savedRep.Error, "boom") {
		t.Errorf("saved Report() error = %q (%v)", savedRep.Error, serr)
	}
	// Первая фаза уже применена и сохраняется, дальнейшие не стартовали.
	e.wantLock("1", "tls", 3)
	e.wantLock("4", "tls", 11)
	e.wantUnset("2", "tls")
	if got := e.probe.startList(); len(got) != 2 {
		t.Errorf("starts = %v", got)
	}
	e.lockDirGone()
}

func TestCoordinator_UnhealthyProbe(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	e.probe.healthy = func(int) bool { return false }
	_, err := e.c.Run(context.Background(), fastParams())
	if !errors.Is(err, ErrProbe) {
		t.Fatalf("err = %v", err)
	}
	e.wantLock("1", "tls", 9) // откат
	if len(e.chk.callLog()) != 0 {
		t.Error("no checks must run without a healthy probe")
	}
}

func TestSanitizeReportErrorRedactsURLQuery(t *testing.T) {
	err := errors.New("probe failed for https://rr2---sn-4g5ednly.googlevideo.com/videoplayback?expire=1700&sig=SECRET_TOKEN\nsecond line")
	got := sanitizeReportError(err)
	if strings.Contains(got, "SECRET_TOKEN") || strings.Contains(got, "?") || strings.Contains(got, "\n") {
		t.Fatalf("unsanitized error: %q", got)
	}
	if !strings.Contains(got, "https://rr2---sn-4g5ednly.googlevideo.com/videoplayback") {
		t.Fatalf("missing path prefix: %q", got)
	}
}

type recoveringProbe struct {
	reinstalls int
	healthy    bool
}

func (p *recoveringProbe) Start(context.Context, int) error { return nil }
func (p *recoveringProbe) Healthy(context.Context) bool     { return p.healthy }
func (p *recoveringProbe) Stop() error                      { return nil }
func (p *recoveringProbe) Reinstall(context.Context) error {
	p.reinstalls++
	p.healthy = true
	return nil
}

func TestGuardedProbeRecoveryReinstallsTransport(t *testing.T) {
	probe := &recoveringProbe{}
	c := &Coordinator{cfg: Config{
		Probe: probe,
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	}}
	g := guarded{r: &run{c: c}, profile: 1}
	recovered, err := g.ensureHealthy(context.Background())
	if err != nil || !recovered || probe.reinstalls != 1 || !probe.healthy {
		t.Fatalf("recovery = %t, err = %v, probe = %+v", recovered, err, probe)
	}
}

func TestCoordinator_IsolationLostTwice(t *testing.T) {
	e := newCoordEnv(t, fullScenario, nil)
	e.setPrev()
	e.probe.healthy = func(call int) bool { return call%2 == 1 } // до пробы здорова, после — нет
	_, err := e.c.Run(context.Background(), fastParams())
	if !errors.Is(err, ErrIsolationLost) {
		t.Fatalf("err = %v", err)
	}
	e.wantLock("1", "tls", 9)
	if n := len(e.chk.callLog()); n != 2 {
		t.Errorf("probe repeated once: %d checks", n)
	}
}

func TestCoordinator_IsolationLostOnceIsRetried(t *testing.T) {
	e := newCoordEnv(t, fullScenario, func(c *Config) { c.MaxStrategy = tinyMax })
	e.probe.healthy = func(call int) bool { return call != 2 }
	rep, err := e.c.Run(context.Background(), fastParams())
	if err != nil || rep.State != StateDone {
		t.Fatalf("%v %+v", err, rep)
	}
	// 4 фазы + РКН на 2 домена = 5 проверок + 1 повтор потерянной изоляции.
	if n := len(e.chk.callLog()); n != 6 {
		t.Errorf("checks = %d, want 6", n)
	}
}

func TestCoordinator_WorkerPausesAreRequested(t *testing.T) {
	rec := &sleepRec{}
	e := newCoordEnv(t, fullScenario, func(c *Config) { c.Sleep = rec.sleep })
	p := fastParams()
	p.Pause, p.DSPause, p.RKNPause, p.PhasePause, p.GreenPause, p.Settle = 4*time.Second, 7*time.Second, 11*time.Second, 13*time.Second, 0, 0
	if _, err := e.c.Run(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	count := map[time.Duration]int{}
	for _, d := range rec.list() {
		count[d]++
	}
	if count[13*time.Second] != 3 {
		t.Errorf("phase pauses = %d, want 3", count[13*time.Second])
	}
	// yt 3 + gv 3 пауз (между 4 стратегиями).
	if count[4*time.Second] != 6 {
		t.Errorf("pause = %d, want 6", count[4*time.Second])
	}
	if count[7*time.Second] != 3 {
		t.Errorf("ds pause = %d, want 3", count[7*time.Second])
	}
	// РКН: 6 проверок, после последней паузы нет.
	if count[11*time.Second] != 5 {
		t.Errorf("rkn pause = %d, want 5", count[11*time.Second])
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
