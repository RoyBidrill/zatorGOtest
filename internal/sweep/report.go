package sweep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Источники отчёта.
const (
	SourceNone  = "none"  // прогонов не было
	SourceLive  = "live"  // файлы каталога прогона (в том числе завершённого)
	SourceSaved = "saved" // last-report.tsv после утраты каталога прогона
)

// WorkerReport — прогресс воркера (workers[] отчёта).
type WorkerReport struct {
	Name            string `json:"name"`
	Label           string `json:"label"`
	Profile         int    `json:"profile"`
	Completed       int    `json:"completed"`
	Total           int    `json:"total"`
	OK              int    `json:"ok"`
	Warn            int    `json:"warn"`
	Fail            int    `json:"fail"`
	CurrentStrategy *int   `json:"current_strategy"`
	CurrentTarget   string `json:"current_target"`
	Greens          string `json:"greens"` // номера через пробел
	Warns           string `json:"warns"`
	Applied         string `json:"applied"` // применённая стратегия профиля или пусто
}

// AppliedRow — реально зафиксированное применение (applied[]).
type AppliedRow struct {
	Kind     string `json:"kind"` // profile|domain
	Target   string `json:"target"`
	Strategy int    `json:"strategy"`
}

// DomainReport — наблюдавшийся домен РКН (domains[]).
type DomainReport struct {
	Domain       string `json:"domain"`
	BestStrategy *int   `json:"best_strategy"`
	Verdict      string `json:"verdict"`
	Applied      *int   `json:"applied"`
}

// Report — снимок прогресса для WebUI (GET settings.cgi?setting=supersweep).
// Формат совпадает с docs/API.md.
type Report struct {
	Available bool           `json:"available"`
	State     State          `json:"state"`
	Active    bool           `json:"active"`
	Source    string         `json:"source"`
	Started   int64          `json:"started"`
	Updated   int64          `json:"updated"`
	Scope     string         `json:"scope"`
	Phase     string         `json:"phase"`
	Completed int            `json:"completed"`
	Total     int            `json:"total"`
	Error     string         `json:"error,omitempty"`
	Workers   []WorkerReport `json:"workers"`
	Applied   []AppliedRow   `json:"applied"`
	Domains   []DomainReport `json:"domains"`
}

// JSON сериализует отчёт.
func (r Report) JSON() ([]byte, error) { return json.Marshal(r.normalized()) }

func (r Report) normalized() Report {
	if r.Workers == nil {
		r.Workers = []WorkerReport{}
	}
	if r.Applied == nil {
		r.Applied = []AppliedRow{}
	}
	if r.Domains == nil {
		r.Domains = []DomainReport{}
	}
	return r
}

// IdleReport — отчёт при отсутствии прогонов.
func IdleReport() Report {
	return Report{State: StateIdle, Source: SourceNone, Scope: "default"}.normalized()
}

var workerLabels = map[string]string{
	WorkerYT: "YouTube", WorkerGV: "Googlevideo", WorkerDS: "Discord", WorkerRKN: "РКН", WorkerQUIC: "YouTube QUIC",
}

var workerProfiles = map[string]int{WorkerYT: 1, WorkerGV: 2, WorkerDS: 4, WorkerRKN: 3, WorkerQUIC: 5}

var profileWorkers = map[int]string{1: WorkerYT, 2: WorkerGV, 4: WorkerDS, 3: WorkerRKN, 5: WorkerQUIC}

// ReportOptions — параметры чтения отчёта.
type ReportOptions struct {
	// ArchiveDir — каталог с last-report.tsv (пусто — сохранённого отчёта нет).
	ArchiveDir string
	// Final — отчёт для сохранения: владелец считается завершившимся.
	Final bool
}

// ReadReport строит отчёт по файлам каталога dir (read-only; сеть и локи не
// трогает). Без файла status берётся сохранённый last-report.tsv либо
// отчёт idle. Оставшийся статус running без живого владельца показывается
// как interrupted, а не как работающий прогон.
func ReadReport(dir string, opts ReportOptions) (Report, error) {
	if st, err := os.Stat(filepath.Join(dir, fileStatus)); err != nil || st.Size() == 0 {
		if opts.ArchiveDir != "" {
			if rep, ok := readSavedReport(filepath.Join(opts.ArchiveDir, LastReportFile)); ok {
				return rep, nil
			}
		}
		return IdleReport(), nil
	}

	alive := false
	if !opts.Final {
		if pid, err := strconv.Atoi(readFirstLine(filepath.Join(dir+".lock", "pid"))); err == nil {
			alive = pidAlive(pid)
		}
	}
	status := readKV(filepath.Join(dir, fileStatus))
	state := State(status["state"])
	if !state.Valid() || state == StateIdle {
		state = StateInterrupted
	}
	if state.InProgress() && !alive {
		state = StateInterrupted
	}
	active := state.InProgress() && alive
	phase := ""
	if active {
		phase = strings.SplitN(status["alive"], ",", 2)[0]
	}
	scope := status["scope"]
	if scope == "" {
		scope = "default"
	}

	rep := Report{
		Available: true, State: state, Active: active, Source: SourceLive,
		Started: int64(atoi(status["started"])), Updated: int64(atoi(status["updated"])),
		Scope: scope, Phase: phase, Error: strings.TrimSpace(status["error"]),
	}

	applied, winners := readApplied(filepath.Join(dir, fileApplied))
	rep.Applied = applied

	media := readFirstLine(filepath.Join(dir, fileMediaStatus))
	for _, row := range readTSV(filepath.Join(dir, fileWorkers)) {
		if len(row) < 6 {
			continue
		}
		name := row[0]
		if _, known := workerLabels[name]; !known {
			continue
		}
		w := WorkerReport{Name: name, Label: workerLabels[name], Profile: workerProfiles[name]}
		if name == WorkerGV && media != "" {
			if media == "ready" {
				w.Label += " [media TCP]"
			} else {
				w.Label += " [Media UNKNOWN: " + cleanField(media) + "]"
			}
		}
		w.Total = atoi(row[5])
		if name == WorkerRKN {
			w.Total *= len(strings.Split(row[4], ","))
		}
		for _, p := range readTSV(filepath.Join(dir, progressFile(name))) {
			if len(p) < 9 || !isPositiveInt(p[2]) {
				continue
			}
			switch p[3] {
			case TokenOK:
				w.OK++
			case TokenWarn, TokenUnknown:
				w.Warn++
			case TokenFail:
				w.Fail++
			default:
				continue
			}
			w.Completed++
		}
		best := readKV(filepath.Join(dir, bestFile(name)))
		w.Greens, w.Warns = best["greens"], best["warns"]
		if s, ok := winners[name]; ok {
			w.Applied = strconv.Itoa(s)
		}
		if active && phase == name {
			if cur := readTSV(filepath.Join(dir, currentFile(name))); len(cur) > 0 && len(cur[0]) >= 2 && isPositiveInt(cur[0][1]) {
				n, _ := strconv.Atoi(cur[0][1])
				w.CurrentStrategy, w.CurrentTarget = &n, cur[0][0]
			}
		}
		rep.Completed += w.Completed
		rep.Total += w.Total
		rep.Workers = append(rep.Workers, w)
	}

	appliedDomain := map[string]int{}
	for _, a := range applied {
		if a.Kind == "domain" {
			appliedDomain[a.Target] = a.Strategy
		}
	}
	for _, d := range DomainWinners(parseCoverage(readTSV(filepath.Join(dir, fileCoverage)))) {
		dr := DomainReport{Domain: d.Domain, Verdict: d.Verdict()}
		if d.Rank != 2 {
			s := d.Strategy
			dr.BestStrategy = &s
		}
		if s, ok := appliedDomain[d.Domain]; ok {
			dr.Applied = &s
		}
		rep.Domains = append(rep.Domains, dr)
	}
	return rep.normalized(), nil
}

// readApplied читает applied.tsv (kind, target, strategy); повторы по
// (kind, target) заменяются последним значением, порядок — по первому появлению.
func readApplied(path string) ([]AppliedRow, map[string]int) {
	var out []AppliedRow
	idx := map[[2]string]int{}
	winners := map[string]int{}
	for _, r := range readTSV(path) {
		if len(r) != 3 || (r[0] != "profile" && r[0] != "domain") || !isPositiveInt(r[2]) {
			continue
		}
		n, _ := strconv.Atoi(r[2])
		key := [2]string{r[0], r[1]}
		if i, ok := idx[key]; ok {
			out[i].Strategy = n
		} else {
			idx[key] = len(out)
			out = append(out, AppliedRow{Kind: r[0], Target: r[1], Strategy: n})
		}
		if r[0] == "profile" {
			if p, err := strconv.Atoi(r[1]); err == nil {
				if w, ok := profileWorkers[p]; ok {
					winners[w] = n
				}
			}
		}
	}
	return out, winners
}

// --- Сохранённый отчёт (last-report.tsv): строки R / W / A / D ---

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return cleanField(s)
}

func undash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// TSV кодирует отчёт построчно: R — сводка, W — воркер, A — применение,
// D — домен РКН.
func (r Report) TSV() string {
	r = r.normalized()
	var b strings.Builder
	fmt.Fprintf(&b, "R\t%s\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\n",
		r.State, b2s(r.Active), r.Started, r.Updated, dash(r.Scope), dash(r.Phase), r.Completed, r.Total, r.Source)
	for _, w := range r.Workers {
		cur := "-"
		if w.CurrentStrategy != nil {
			cur = strconv.Itoa(*w.CurrentStrategy)
		}
		fmt.Fprintf(&b, "W\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			w.Name, cleanField(w.Label), w.Profile, w.Completed, w.Total, w.OK, w.Warn, w.Fail,
			cur, dash(w.CurrentTarget), dash(w.Greens), dash(w.Warns), dash(w.Applied))
	}
	for _, a := range r.Applied {
		fmt.Fprintf(&b, "A\t%s\t%s\t%d\n", a.Kind, cleanField(a.Target), a.Strategy)
	}
	for _, d := range r.Domains {
		best := "-"
		if d.BestStrategy != nil {
			best = strconv.Itoa(*d.BestStrategy)
		}
		fmt.Fprintf(&b, "D\t%s\t%s\t%s\n", cleanField(d.Domain), best, d.Verdict)
	}
	if errText := strings.TrimSpace(cleanField(r.Error)); errText != "" {
		fmt.Fprintf(&b, "E\t%s\n", errText)
	}
	return b.String()
}

func readSavedReport(path string) (Report, bool) {
	rows := readTSV(path)
	if len(rows) == 0 {
		return Report{}, false
	}
	var rep Report
	applied := map[string]int{}
	var haveR bool
	for _, r := range rows {
		switch r[0] {
		case "R":
			if len(r) < 10 {
				continue
			}
			haveR = true
			rep.Available = true
			rep.State = State(r[1])
			rep.Started, rep.Updated = int64(atoi(r[3])), int64(atoi(r[4]))
			rep.Scope = undash(r[5])
			rep.Completed, rep.Total = atoi(r[7]), atoi(r[8])
		case "W":
			if len(r) < 14 {
				continue
			}
			w := WorkerReport{
				Name: r[1], Label: r[2], Profile: atoi(r[3]), Completed: atoi(r[4]), Total: atoi(r[5]),
				OK: atoi(r[6]), Warn: atoi(r[7]), Fail: atoi(r[8]),
				CurrentTarget: undash(r[10]), Greens: undash(r[11]), Warns: undash(r[12]), Applied: undash(r[13]),
			}
			if isPositiveInt(r[9]) {
				n, _ := strconv.Atoi(r[9])
				w.CurrentStrategy = &n
			}
			rep.Workers = append(rep.Workers, w)
		case "A":
			if len(r) >= 4 && isPositiveInt(r[3]) {
				n, _ := strconv.Atoi(r[3])
				rep.Applied = append(rep.Applied, AppliedRow{Kind: r[1], Target: r[2], Strategy: n})
				if r[1] == "domain" {
					applied[r[2]] = n
				}
			}
		case "D":
			if len(r) >= 4 {
				d := DomainReport{Domain: r[1], Verdict: r[3]}
				if isPositiveInt(r[2]) {
					n, _ := strconv.Atoi(r[2])
					d.BestStrategy = &n
				}
				rep.Domains = append(rep.Domains, d)
			}
		case "E":
			if len(r) >= 2 {
				rep.Error = strings.TrimSpace(r[1])
			}
		}
	}
	if !haveR {
		return Report{}, false
	}
	for i := range rep.Domains {
		if n, ok := applied[rep.Domains[i].Domain]; ok {
			rep.Domains[i].Applied = &n
		}
	}
	// Сохранённый отчёт не бывает активным; недозавершённый — interrupted.
	rep.Active, rep.Phase, rep.Source = false, "", SourceSaved
	if !rep.State.Valid() || rep.State == StateIdle || rep.State.InProgress() {
		rep.State = StateInterrupted
	}
	return rep.normalized(), true
}

// CLI форматирует отчёт для консоли (supersweep_report_cli).
func (r Report) CLI() string {
	titles := map[State]string{
		StateIdle: "ещё не запускался", StateStarting: "подготовка", StateRunning: "выполняется",
		StateApplying: "применение результатов", StateDone: "завершён", StateCancelled: "отменён",
		StateInterrupted: "прерван (процесс не работает)",
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Суперавтопрогон: %s\nОбласть: %s\nВсего: %d/%d проверок\n", titles[r.State], r.Scope, r.Completed, r.Total)
	if r.Started != 0 {
		fmt.Fprintf(&b, "Начало: %s\nОбновлено: %s\n",
			time.Unix(r.Started, 0).Format("02.01.2006 15:04:05"), time.Unix(r.Updated, 0).Format("02.01.2006 15:04:05"))
	}
	if r.Phase != "" {
		fmt.Fprintf(&b, "Текущая фаза: %s\n", r.Phase)
	}
	if r.Source == SourceSaved {
		b.WriteString("Показан сохранённый результат последнего прогона.\n")
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "Ошибка: %s\n", r.Error)
	}
	for _, w := range r.Workers {
		fmt.Fprintf(&b, "\n%s (профиль %d): %d/%d; зелёных %d, жёлтых %d, красных %d\n", w.Label, w.Profile, w.Completed, w.Total, w.OK, w.Warn, w.Fail)
		if w.CurrentStrategy != nil {
			fmt.Fprintf(&b, "  Сейчас: стратегия %d, цель %s\n", *w.CurrentStrategy, dash(w.CurrentTarget))
		}
		if w.Greens != "" {
			fmt.Fprintf(&b, "  Зелёные стратегии: %s\n", w.Greens)
		}
		if w.Warns != "" {
			fmt.Fprintf(&b, "  Жёлтые стратегии: %s (не применяются автоматически)\n", w.Warns)
		}
	}
	for _, a := range r.Applied {
		switch a.Kind {
		case "profile":
			fmt.Fprintf(&b, "Применено: профиль %s, стратегия %d\n", a.Target, a.Strategy)
		case "domain":
			fmt.Fprintf(&b, "Применено: домен %s, стратегия %d\n", a.Target, a.Strategy)
		}
	}
	for _, d := range r.Domains {
		cand := "-"
		if d.BestStrategy != nil {
			cand = strconv.Itoa(*d.BestStrategy)
		}
		fmt.Fprintf(&b, "РКН %s: %s, кандидат %s\n", d.Domain, d.Verdict, cand)
	}
	if errText := strings.TrimSpace(cleanField(r.Error)); errText != "" {
		fmt.Fprintf(&b, "E\t%s\n", errText)
	}
	return b.String()
}
