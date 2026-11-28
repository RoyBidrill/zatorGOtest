package sweep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureDir создаёт каталог прогона с YouTube в процессе и тремя доменами.
func fixtureDir(t *testing.T, state string, alive bool) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ss")
	writeFile(t, filepath.Join(dir, "status"),
		"state="+state+"\nscope=default\nstarted=1700000000\nupdated=1700000100\nalive=yt,gv\n")
	writeFile(t, filepath.Join(dir, "workers.tsv"),
		"yt\tYouTube\tprofile\t1\thttps://www.youtube.com/\t4\n"+
			"gv\tGooglevideo\tprofile\t2\thttps://gv/\t3\n"+
			"rkn\tРКН\trkn\t3\ta.com,b.org\t2\n")
	writeFile(t, filepath.Join(dir, "progress.yt.tsv"),
		"1\t1\t1\tfail\ttls\ttls\t-\t-\tне идёт\n"+
			"2\t1\t2\tok\tok\tok\t65536\t0.5\tданные\n"+
			"3\t1\t3\twarn\tok\ttls\t65536\t1.0\tтолько TLS 1.2\n"+
			"broken line\n")
	writeFile(t, filepath.Join(dir, "best.yt"), "best=2\nbest_kind=best\ngreens=2\nwarns=3\n")
	writeFile(t, filepath.Join(dir, "progress.gv.tsv"), "1\t2\t1\tunknown\tok\tok\t-\t-\tTLS/CDN\n")
	writeFile(t, filepath.Join(dir, "current.gv"), "https://gv/\t2\n")
	writeFile(t, filepath.Join(dir, "media-status"), "resolver_unavailable\n")
	writeFile(t, filepath.Join(dir, "coverage.tsv"),
		"1\ta.com\t1\tok\t65536\t100\n1\ta.com\t2\tfail\t-\t0\n1\tb.org\t2\twarn\t100\t5\n1\tb.org\t3\tfail\t-\t0\n")
	writeFile(t, filepath.Join(dir, "applied.tsv"), "profile\t1\t2\ndomain\ta.com\t1\nprofile\t1\t2\n")
	if alive {
		writeFile(t, filepath.Join(dir+".lock", "pid"), strconv.Itoa(os.Getpid())+"\n")
	}
	return dir
}

func TestReadReport_Idle(t *testing.T) {
	rep, err := ReadReport(filepath.Join(t.TempDir(), "none"), ReportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Available || rep.State != StateIdle || rep.Source != SourceNone || rep.Active || rep.Scope != "default" {
		t.Errorf("idle = %+v", rep)
	}
	b, _ := rep.JSON()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"workers", "applied", "domains"} {
		arr, ok := m[k].([]any)
		if !ok || len(arr) != 0 {
			t.Errorf("%s must be an empty array, got %v", k, m[k])
		}
	}
}

func TestReadReport_Live(t *testing.T) {
	dir := fixtureDir(t, "running", true)
	rep, err := ReadReport(dir, ReportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Available || !rep.Active || rep.State != StateRunning || rep.Source != SourceLive || rep.Phase != "yt" {
		t.Fatalf("header: %+v", rep)
	}
	if rep.Started != 1700000000 || rep.Updated != 1700000100 || rep.Scope != "default" {
		t.Errorf("times/scope: %+v", rep)
	}
	if len(rep.Workers) != 3 {
		t.Fatalf("workers = %+v", rep.Workers)
	}
	yt, gv, rkn := rep.Workers[0], rep.Workers[1], rep.Workers[2]
	if yt.Name != "yt" || yt.Label != "YouTube" || yt.Profile != 1 || yt.Total != 4 || yt.Completed != 3 ||
		yt.OK != 1 || yt.Warn != 1 || yt.Fail != 1 || yt.Greens != "2" || yt.Warns != "3" || yt.Applied != "2" {
		t.Errorf("yt = %+v", yt)
	}
	// Текущая стратегия показывается только у активной фазы (yt), у yt файла current нет.
	if yt.CurrentStrategy != nil || gv.CurrentStrategy != nil {
		t.Errorf("current strategies: %v %v", yt.CurrentStrategy, gv.CurrentStrategy)
	}
	if !strings.Contains(gv.Label, "Media UNKNOWN: resolver_unavailable") || gv.Warn != 1 {
		t.Errorf("gv = %+v", gv)
	}
	if rkn.Profile != 3 || rkn.Total != 4 || rkn.Completed != 0 {
		t.Errorf("rkn = %+v", rkn)
	}
	if rep.Completed != 4 || rep.Total != 4+3+4 {
		t.Errorf("totals %d/%d", rep.Completed, rep.Total)
	}
	if len(rep.Applied) != 2 || rep.Applied[0] != (AppliedRow{"profile", "1", 2}) || rep.Applied[1] != (AppliedRow{"domain", "a.com", 1}) {
		t.Errorf("applied = %+v", rep.Applied)
	}
	if len(rep.Domains) != 2 {
		t.Fatalf("domains = %+v", rep.Domains)
	}
	a, b := rep.Domains[0], rep.Domains[1]
	if a.Domain != "a.com" || a.Verdict != TokenOK || a.BestStrategy == nil || *a.BestStrategy != 1 || a.Applied == nil || *a.Applied != 1 {
		t.Errorf("a.com = %+v", a)
	}
	if b.Domain != "b.org" || b.Verdict != TokenWarn || b.BestStrategy == nil || *b.BestStrategy != 2 || b.Applied != nil {
		t.Errorf("b.org = %+v", b)
	}
}

func TestReadReport_CurrentStrategyOfActivePhase(t *testing.T) {
	dir := fixtureDir(t, "running", true)
	writeFile(t, filepath.Join(dir, "status"), "state=running\nscope=default\nstarted=1\nupdated=2\nalive=gv\n")
	rep, _ := ReadReport(dir, ReportOptions{})
	if rep.Phase != "gv" {
		t.Fatalf("phase = %q", rep.Phase)
	}
	gv := rep.Workers[1]
	if gv.CurrentStrategy == nil || *gv.CurrentStrategy != 2 || gv.CurrentTarget != "https://gv/" {
		t.Errorf("gv current = %+v", gv)
	}
}

func TestReadReport_DeadOwnerIsInterrupted(t *testing.T) {
	dir := fixtureDir(t, "running", false)
	rep, _ := ReadReport(dir, ReportOptions{})
	if rep.State != StateInterrupted || rep.Active || rep.Phase != "" {
		t.Errorf("dead owner: %+v", rep)
	}
	// Завершённые состояния не меняются.
	dir = fixtureDir(t, "done", false)
	if rep, _ := ReadReport(dir, ReportOptions{}); rep.State != StateDone || rep.Active {
		t.Errorf("done: %+v", rep)
	}
	// Мусорное состояние — interrupted.
	dir = fixtureDir(t, "garbage", true)
	if rep, _ := ReadReport(dir, ReportOptions{}); rep.State != StateInterrupted || rep.Active {
		t.Errorf("garbage: %+v", rep)
	}
}

func TestReadReport_FinalIgnoresOwner(t *testing.T) {
	dir := fixtureDir(t, "applying", true)
	rep, _ := ReadReport(dir, ReportOptions{Final: true})
	if rep.Active || rep.State != StateInterrupted {
		t.Errorf("final with in-progress state: %+v", rep)
	}
}

func TestReadReport_StaleLockPidIgnored(t *testing.T) {
	dir := fixtureDir(t, "running", false)
	writeFile(t, filepath.Join(dir+".lock", "pid"), "not-a-pid\n")
	if rep, _ := ReadReport(dir, ReportOptions{}); rep.Active {
		t.Error("garbage pid must not count as alive")
	}
}

func TestReport_JSONShape(t *testing.T) {
	dir := fixtureDir(t, "running", true)
	rep, _ := ReadReport(dir, ReportOptions{})
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"available", "state", "active", "source", "started", "updated", "scope", "phase", "completed", "total", "workers", "applied", "domains"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing JSON key %q", k)
		}
	}
	w := m["workers"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "label", "profile", "completed", "total", "ok", "warn", "fail", "current_strategy", "current_target", "greens", "warns", "applied"} {
		if _, ok := w[k]; !ok {
			t.Errorf("missing worker key %q", k)
		}
	}
	if w["current_strategy"] != nil {
		t.Errorf("current_strategy must be null, got %v", w["current_strategy"])
	}
	d := m["domains"].([]any)[1].(map[string]any)
	if d["applied"] != nil || d["best_strategy"].(float64) != 2 {
		t.Errorf("domain json: %v", d)
	}
}

func TestReport_TSVRoundTripAndSaved(t *testing.T) {
	dir := fixtureDir(t, "running", false)
	rep, _ := ReadReport(dir, ReportOptions{Final: true})
	archive := t.TempDir()
	writeFile(t, filepath.Join(archive, LastReportFile), rep.TSV())

	saved, err := ReadReport(filepath.Join(t.TempDir(), "gone"), ReportOptions{ArchiveDir: archive})
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Available || saved.Source != SourceSaved || saved.Active || saved.Phase != "" {
		t.Fatalf("saved header: %+v", saved)
	}
	// running в сохранённом отчёте превращается в interrupted.
	if saved.State != StateInterrupted {
		t.Errorf("state = %s", saved.State)
	}
	if len(saved.Workers) != len(rep.Workers) || saved.Workers[0].Greens != "2" || saved.Workers[0].Applied != "2" {
		t.Errorf("saved workers = %+v", saved.Workers)
	}
	if saved.Completed != rep.Completed || saved.Total != rep.Total || saved.Started != rep.Started {
		t.Errorf("saved totals: %+v", saved)
	}
	if len(saved.Applied) != 2 || len(saved.Domains) != 2 {
		t.Fatalf("saved applied/domains: %+v %+v", saved.Applied, saved.Domains)
	}
	if saved.Domains[0].Applied == nil || *saved.Domains[0].Applied != 1 || saved.Domains[1].Applied != nil {
		t.Errorf("saved domain applied: %+v", saved.Domains)
	}
	if saved.Domains[1].BestStrategy == nil || *saved.Domains[1].BestStrategy != 2 {
		t.Errorf("saved best: %+v", saved.Domains[1])
	}

	// Живой каталог приоритетнее сохранённого.
	live, _ := ReadReport(dir, ReportOptions{ArchiveDir: archive, Final: true})
	if live.Source != SourceLive {
		t.Errorf("source = %s", live.Source)
	}
}

func TestReadSavedReport_Invalid(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readSavedReport(filepath.Join(dir, "missing")); ok {
		t.Error("missing file")
	}
	writeFile(t, filepath.Join(dir, "no-r"), "W\tyt\tYouTube\t1\t1\t1\t1\t0\t0\t-\t-\t-\t-\t-\n")
	if _, ok := readSavedReport(filepath.Join(dir, "no-r")); ok {
		t.Error("report without R line must be rejected")
	}
	writeFile(t, filepath.Join(dir, "short"), "R\tdone\n")
	if _, ok := readSavedReport(filepath.Join(dir, "short")); ok {
		t.Error("short R line")
	}
	writeFile(t, filepath.Join(dir, "idle"), "R\tidle\t0\t0\t0\tdefault\t-\t0\t0\tnone\n")
	if rep, ok := readSavedReport(filepath.Join(dir, "idle")); !ok || rep.State != StateInterrupted {
		t.Errorf("idle saved → interrupted: %+v %v", rep, ok)
	}
	writeFile(t, filepath.Join(dir, "done"), "R\tdone\t0\t5\t6\tdefault\t-\t3\t3\tlive\n")
	if rep, ok := readSavedReport(filepath.Join(dir, "done")); !ok || rep.State != StateDone || rep.Completed != 3 {
		t.Errorf("done saved: %+v %v", rep, ok)
	}
}

func TestReport_CLI(t *testing.T) {
	dir := fixtureDir(t, "running", true)
	rep, _ := ReadReport(dir, ReportOptions{})
	out := rep.CLI()
	for _, want := range []string{
		"выполняется", "Текущая фаза: yt", "YouTube (профиль 1): 3/4", "Зелёные стратегии: 2",
		"Жёлтые стратегии: 3", "Применено: профиль 1, стратегия 2", "Применено: домен a.com, стратегия 1",
		"РКН b.org: warn, кандидат 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CLI output missing %q:\n%s", want, out)
		}
	}
	idle := IdleReport().CLI()
	if !strings.Contains(idle, "ещё не запускался") {
		t.Errorf("idle CLI: %s", idle)
	}
}

func TestReadApplied_DedupAndFilter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "applied.tsv")
	writeFile(t, p, "profile\t1\t2\nprofile\t1\t5\nbogus\tx\t1\nprofile\t2\tx\ndomain\ta.com\t3\nprofile\t9\t4\n")
	rows, winners := readApplied(p)
	if len(rows) != 3 || rows[0].Strategy != 5 || rows[2].Target != "9" {
		t.Errorf("rows = %+v", rows)
	}
	if winners["yt"] != 5 || len(winners) != 1 {
		t.Errorf("winners = %v", winners)
	}
}

func TestKVRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kv")
	if err := writeKV(p, kv{{"a", "1"}, {"b", "x\ny"}, {"c", ""}}); err != nil {
		t.Fatal(err)
	}
	m := readKV(p)
	if m["a"] != "1" || m["b"] != "x y" || m["c"] != "" {
		t.Errorf("kv = %v", m)
	}
	if len(readKV(filepath.Join(t.TempDir(), "none"))) != 0 {
		t.Error("missing kv must be empty")
	}
}

func TestAppendLineAndReadTSV(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "f.tsv")
	for _, l := range []string{"a\tb", "c\td\te"} {
		if err := appendLine(p, l); err != nil {
			t.Fatal(err)
		}
	}
	rows := readTSV(p)
	if len(rows) != 2 || len(rows[1]) != 3 || rows[0][1] != "b" {
		t.Errorf("rows = %v", rows)
	}
	if readTSV(filepath.Join(t.TempDir(), "none")) != nil {
		t.Error("missing file must give nil")
	}
}

func TestReport_ErrorRoundTripJSONTSVAndCLI(t *testing.T) {
	dir := fixtureDir(t, "cancelled", false)
	writeFile(t, filepath.Join(dir, "status"),
		"state=cancelled\nscope=default\nstarted=1700000000\nupdated=1700000100\nalive=\nerror=nfqws2 busy on qnum 65535\n")
	rep, err := ReadReport(dir, ReportOptions{Final: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Error != "nfqws2 busy on qnum 65535" {
		t.Fatalf("rep.Error = %q", rep.Error)
	}
	raw, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"error":"nfqws2 busy on qnum 65535"`) {
		t.Fatalf("JSON missing error field: %s", raw)
	}
	if !strings.Contains(rep.CLI(), "Ошибка: nfqws2 busy on qnum 65535") {
		t.Fatalf("CLI missing error line:\n%s", rep.CLI())
	}

	archive := t.TempDir()
	writeFile(t, filepath.Join(archive, LastReportFile), rep.TSV())
	saved, err := ReadReport(filepath.Join(t.TempDir(), "missing"), ReportOptions{ArchiveDir: archive})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Error != "nfqws2 busy on qnum 65535" {
		t.Fatalf("saved.Error = %q", saved.Error)
	}

	cleanRaw, err := IdleReport().JSON()
	if err != nil || strings.Contains(string(cleanRaw), `"error"`) {
		t.Fatalf("empty error must be omitted from JSON: %s (%v)", cleanRaw, err)
	}
}
