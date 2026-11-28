package googlevideo

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AloofLibra/zator/internal/fsutil"
)

// Имена файлов состояния коллектора (каталог — tmpfs, например /tmp/z2r-googlevideo).
const (
	LocalFileName    = "local.tsv"    // host ip expires observed_at
	PendingFileName  = "pending.tsv"  // ip observed_at host
	ReportedFileName = "reported.tsv" // host ip reported_at
	UploadStampName  = "googlevideo-upload.ts"
	UploadLockName   = "googlevideo-upload.lock"

	// DefaultStateDir — каталог состояния по умолчанию (Z2R_GV_TMPDIR).
	DefaultStateDir = "/tmp/z2r-googlevideo"
)

// Лимиты коллектора.
const (
	// MaxStateRows — лимит строк local.tsv, pending.tsv и reported.tsv: остаются новейшие.
	MaxStateRows = 8192
	// MaxTTLSeconds — верхняя граница TTL DNS-ответа (7 суток).
	MaxTTLSeconds = 604800
	// ReportedRetention — сколько хранится запись об отправленной паре host/ip.
	ReportedRetention = 30 * 24 * time.Hour
	// ObservationMaxAge — старше этого наблюдения не отправляются и отбрасываются.
	ObservationMaxAge = 7 * 24 * time.Hour
	// KernelIPLimit — максимум локальных адресов для набора ядра за раз.
	KernelIPLimit = 128
)

// Причины отклонения наблюдения. Все оборачивают ErrRejected.
var (
	ErrRejected    = errors.New("googlevideo: наблюдение отклонено")
	ErrHostname    = fmt.Errorf("%w: имя вне rrN---sn-….googlevideo.com", ErrRejected)
	ErrRecordType  = fmt.Errorf("%w: тип записи не A", ErrRejected)
	ErrNonPublicIP = fmt.Errorf("%w: адрес не является публичным IPv4", ErrRejected)
	ErrTTL         = fmt.Errorf("%w: некорректный TTL", ErrRejected)
)

// CentralChecker сообщает, входит ли адрес в центральный список (его IP не
// отправляются на сервер и не дублируются в наборе ядра). *CentralList
// реализует интерфейс.
type CentralChecker interface {
	Contains(ip string) bool
}

// CollectorConfig — настройки коллектора.
type CollectorConfig struct {
	// Dir — каталог состояния (по умолчанию DefaultStateDir). Файлы
	// local.tsv/pending.tsv/reported.tsv лежат внутри, если не заданы явно.
	Dir          string
	LocalFile    string
	PendingFile  string
	ReportedFile string
	// HostsFile — необязательный путь к googlevideo-hosts.txt (уникальные FQDN).
	HostsFile string
	// Central — необязательная проверка «IP уже в центральном списке».
	Central CentralChecker
	// Now — источник времени (по умолчанию time.Now).
	Now func() time.Time
	// Logf — необязательный журнал (строки collector.log).
	Logf func(format string, args ...any)
}

// Collector — локальное хранилище DNS-наблюдений googlevideo.
type Collector struct {
	cfg CollectorConfig
	mu  sync.Mutex
}

// NewCollector создаёт коллектор и подставляет пути по умолчанию.
func NewCollector(cfg CollectorConfig) *Collector {
	if cfg.Dir == "" {
		cfg.Dir = DefaultStateDir
	}
	if cfg.LocalFile == "" {
		cfg.LocalFile = filepath.Join(cfg.Dir, LocalFileName)
	}
	if cfg.PendingFile == "" {
		cfg.PendingFile = filepath.Join(cfg.Dir, PendingFileName)
	}
	if cfg.ReportedFile == "" {
		cfg.ReportedFile = filepath.Join(cfg.Dir, ReportedFileName)
	}
	return &Collector{cfg: cfg}
}

// LocalFile, PendingFile и ReportedFile возвращают пути файлов состояния.
func (c *Collector) LocalFile() string    { return c.cfg.LocalFile }
func (c *Collector) PendingFile() string  { return c.cfg.PendingFile }
func (c *Collector) ReportedFile() string { return c.cfg.ReportedFile }

func (c *Collector) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}

func (c *Collector) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

func (c *Collector) central(ip string) bool {
	return c.cfg.Central != nil && c.cfg.Central.Contains(ip)
}

// --- строки файлов ---

// LocalRow — строка local.tsv: host, ip, expires (epoch), observed_at (epoch).
// Observed == 0 у старых трёхколоночных строк.
type LocalRow struct {
	Host     string
	IP       string
	Expires  int64
	Observed int64
}

// TSV форматирует строку без перевода строки.
func (r LocalRow) TSV() string {
	if r.Observed <= 0 {
		return strings.Join([]string{r.Host, r.IP, i64(r.Expires)}, "\t")
	}
	return strings.Join([]string{r.Host, r.IP, i64(r.Expires), i64(r.Observed)}, "\t")
}

// PendingRow — строка pending.tsv: ip, observed_at (epoch), host. Host пуст у
// старых двухколоночных строк (отправляются как «голые» IP).
type PendingRow struct {
	IP       string
	Observed int64
	Host     string
}

// TSV форматирует строку без перевода строки.
func (r PendingRow) TSV() string {
	if r.Host == "" {
		return r.IP + "\t" + i64(r.Observed)
	}
	return strings.Join([]string{r.IP, i64(r.Observed), r.Host}, "\t")
}

// ReportedRow — строка reported.tsv: host, ip, reported_at (epoch).
type ReportedRow struct {
	Host       string
	IP         string
	ReportedAt int64
}

// TSV форматирует строку без перевода строки.
func (r ReportedRow) TSV() string {
	return strings.Join([]string{r.Host, r.IP, i64(r.ReportedAt)}, "\t")
}

func i64(n int64) string { return strconv.FormatInt(n, 10) }

func numField(s string) (int64, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" || len(s) > 18 {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if l := strings.TrimRight(sc.Text(), "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ReadLocalFile читает local.tsv, пропуская повреждённые строки.
func ReadLocalFile(path string) []LocalRow {
	var rows []LocalRow
	for _, l := range readLines(path) {
		f := strings.Split(l, "\t")
		if len(f) < 3 {
			continue
		}
		exp, ok := numField(f[2])
		if !ok {
			continue
		}
		row := LocalRow{Host: f[0], IP: f[1], Expires: exp}
		if len(f) >= 4 {
			if obs, ok := numField(f[3]); ok {
				row.Observed = obs
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// ReadPendingFile читает pending.tsv (и pending.retry.*, .sending.*).
func ReadPendingFile(path string) []PendingRow {
	var rows []PendingRow
	for _, l := range readLines(path) {
		f := strings.Split(l, "\t")
		if len(f) < 2 {
			continue
		}
		obs, ok := numField(f[1])
		if !ok {
			continue
		}
		row := PendingRow{IP: f[0], Observed: obs}
		if len(f) >= 3 {
			row.Host = f[2]
		}
		rows = append(rows, row)
	}
	return rows
}

// ReadReportedFile читает reported.tsv.
func ReadReportedFile(path string) []ReportedRow {
	var rows []ReportedRow
	for _, l := range readLines(path) {
		f := strings.Split(l, "\t")
		if len(f) < 3 {
			continue
		}
		at, ok := numField(f[2])
		if !ok {
			continue
		}
		rows = append(rows, ReportedRow{Host: f[0], IP: f[1], ReportedAt: at})
	}
	return rows
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return fsutil.AtomicWriteFile(path, []byte(b.String()), 0o644)
}

func tail[T any](rows []T, n int) []T {
	if len(rows) > n {
		return rows[len(rows)-n:]
	}
	return rows
}

// --- наблюдения ---

// Observation — разобранный DNS-ответ.
type Observation struct {
	Host string
	IP   string
	// TTL — секунды; 0 недопустим, больше MaxTTLSeconds обрезается.
	TTL int
	// Type — тип записи; пусто означает A.
	Type string
}

// ObserveResult — итог Collector.Observe.
type ObserveResult struct {
	Host     string
	IP       string
	Observed int64
	Expires  int64
	// Central — адрес уже есть в центральном списке (в набор ядра не нужен).
	Central bool
	// Queued — пара добавлена в очередь отправки.
	Queued bool
	// AlreadyReported — пара уже отправлена за последние 30 суток.
	AlreadyReported bool
	// AlreadyQueued — пара уже ждёт отправки (pending/.sending/retry).
	AlreadyQueued bool
}

// ParseTTL разбирает TTL из текста: только цифры; более шести цифр и значения
// выше 7 суток дают MaxTTLSeconds; ноль и мусор — ErrTTL.
func ParseTTL(s string) (int, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, ErrTTL
	}
	if len(s) > 6 {
		return MaxTTLSeconds, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, ErrTTL
	}
	if n > MaxTTLSeconds {
		n = MaxTTLSeconds
	}
	return n, nil
}

// ObserveText — Observe для текстовых полей (вывод сниффера, события ubus).
func (c *Collector) ObserveText(host, ip, ttl, typ string) (ObserveResult, error) {
	n, err := ParseTTL(ttl)
	if err != nil {
		c.logf("observation rejected reason=ttl host=%s ip=%s", host, ip)
		return ObserveResult{}, err
	}
	return c.Observe(Observation{Host: host, IP: ip, TTL: n, Type: typ})
}

func (c *Collector) validateObservation(o Observation) (string, int, error) {
	host, ok := NormalizeHostname(o.Host)
	if !ok {
		c.logf("observation rejected reason=hostname host=%s ip=%s", o.Host, o.IP)
		return "", 0, ErrHostname
	}
	if t := o.Type; t != "" && t != "A" {
		c.logf("observation rejected reason=record_type host=%s ip=%s type=%s", host, o.IP, t)
		return "", 0, ErrRecordType
	}
	if !PublicIPv4(o.IP) {
		c.logf("observation rejected reason=non_public_ip host=%s ip=%s", host, o.IP)
		return "", 0, ErrNonPublicIP
	}
	ttl := o.TTL
	if ttl <= 0 {
		c.logf("observation rejected reason=zero_ttl host=%s ip=%s", host, o.IP)
		return "", 0, ErrTTL
	}
	if ttl > MaxTTLSeconds {
		ttl = MaxTTLSeconds
	}
	return host, ttl, nil
}

// Observe проверяет наблюдение (googlevideo_observe_local) и сохраняет его:
//  1. имя — поддомен googlevideo.com, тип записи A, IP публичный, TTL > 0;
//  2. local.tsv: выброшены истёкшие строки и прежняя пара host+ip, новая
//     строка добавлена, остаются новейшие 8192;
//  3. пара, отправленная за последние 30 суток, в очередь не попадает;
//  4. пара, уже ждущая отправки, не дублируется;
//  5. иначе строка `ip observed host` дописывается в pending.tsv (до 8192).
func (c *Collector) Observe(o Observation) (ObserveResult, error) {
	host, ttl, err := c.validateObservation(o)
	if err != nil {
		return ObserveResult{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().Unix()
	res := ObserveResult{Host: host, IP: o.IP, Observed: now, Expires: now + int64(ttl), Central: c.central(o.IP)}

	if err := c.storeLocal(LocalRow{Host: host, IP: o.IP, Expires: res.Expires, Observed: now}, now); err != nil {
		return res, err
	}
	if c.cfg.HostsFile != "" {
		_, _ = NewHostsFile(c.cfg.HostsFile).Add(host)
	}
	if c.isReported(host, o.IP, now) {
		res.AlreadyReported = true
		c.logf("observation host=%s ip=%s result=already_reported", host, o.IP)
		return res, nil
	}
	if c.isQueued(host, o.IP) {
		res.AlreadyQueued = true
		c.logf("observation host=%s ip=%s result=already_queued", host, o.IP)
		return res, nil
	}
	if err := c.appendPending(PendingRow{IP: o.IP, Observed: now, Host: host}); err != nil {
		c.logf("queue_error host=%s ip=%s reason=append", host, o.IP)
		return res, err
	}
	res.Queued = true
	c.logf("observation host=%s ip=%s result=queued observed_at=%d central_ip=%d", host, o.IP, now, b2i(res.Central))
	return res, nil
}

// ObserveBatch сохраняет пакет наблюдений за одну блокировку с одиночной
// перезаписью local.tsv, pending.tsv и HostsFile. Невалидные элементы пропускаются.
func (c *Collector) ObserveBatch(items []Observation) ([]ObserveResult, error) {
	if len(items) == 0 {
		return nil, nil
	}
	type validObs struct {
		host string
		ip   string
		ttl  int
	}
	valid := make([]validObs, 0, len(items))
	for _, o := range items {
		host, ttl, err := c.validateObservation(o)
		if err != nil {
			continue
		}
		valid = append(valid, validObs{host: host, ip: o.IP, ttl: ttl})
	}
	if len(valid) == 0 {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().Unix()
	replaced := make(map[[2]string]LocalRow, len(valid))
	replaceOrder := make([][2]string, 0, len(valid))
	hostSet := make(map[string]struct{}, len(valid))
	hosts := make([]string, 0, len(valid))
	for _, v := range valid {
		key := [2]string{v.host, v.ip}
		if _, seen := replaced[key]; !seen {
			replaceOrder = append(replaceOrder, key)
		}
		replaced[key] = LocalRow{Host: v.host, IP: v.ip, Expires: now + int64(v.ttl), Observed: now}
		if _, seen := hostSet[v.host]; !seen {
			hostSet[v.host] = struct{}{}
			hosts = append(hosts, v.host)
		}
	}

	var keep []string
	for _, r := range ReadLocalFile(c.cfg.LocalFile) {
		if r.Expires <= now {
			continue
		}
		if _, upd := replaced[[2]string{r.Host, r.IP}]; upd {
			continue
		}
		keep = append(keep, r.TSV())
	}
	for _, key := range replaceOrder {
		keep = append(keep, replaced[key].TSV())
	}
	if err := writeLines(c.cfg.LocalFile, tail(keep, MaxStateRows)); err != nil {
		return nil, err
	}
	if c.cfg.HostsFile != "" && len(hosts) > 0 {
		_, _ = NewHostsFile(c.cfg.HostsFile).MergeFrom(hosts)
	}

	cutoff := now - int64(ReportedRetention/time.Second)
	reported := make(map[[2]string]struct{})
	for _, r := range ReadReportedFile(c.cfg.ReportedFile) {
		if r.ReportedAt >= cutoff {
			reported[[2]string{r.Host, r.IP}] = struct{}{}
		}
	}
	queued := make(map[[2]string]struct{})
	for _, f := range c.spoolFiles() {
		for _, r := range ReadPendingFile(f) {
			queued[[2]string{r.Host, r.IP}] = struct{}{}
		}
	}

	results := make([]ObserveResult, 0, len(valid))
	var pendingBatch []PendingRow
	for _, v := range valid {
		res := ObserveResult{
			Host:     v.host,
			IP:       v.ip,
			Observed: now,
			Expires:  now + int64(v.ttl),
			Central:  c.central(v.ip),
		}
		key := [2]string{v.host, v.ip}
		if _, ok := reported[key]; ok {
			res.AlreadyReported = true
			c.logf("observation host=%s ip=%s result=already_reported", v.host, v.ip)
		} else if _, ok := queued[key]; ok {
			res.AlreadyQueued = true
			c.logf("observation host=%s ip=%s result=already_queued", v.host, v.ip)
		} else {
			queued[key] = struct{}{}
			pendingBatch = append(pendingBatch, PendingRow{IP: v.ip, Observed: now, Host: v.host})
			res.Queued = true
			c.logf("observation host=%s ip=%s result=queued observed_at=%d central_ip=%d", v.host, v.ip, now, b2i(res.Central))
		}
		results = append(results, res)
	}
	if _, err := c.appendPendingBatch(pendingBatch); err != nil {
		return results, err
	}
	return results, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c *Collector) storeLocal(row LocalRow, now int64) error {
	var keep []string
	for _, r := range ReadLocalFile(c.cfg.LocalFile) {
		if r.Expires <= now || (r.Host == row.Host && r.IP == row.IP) {
			continue
		}
		keep = append(keep, r.TSV())
	}
	keep = append(keep, row.TSV())
	return writeLines(c.cfg.LocalFile, tail(keep, MaxStateRows))
}

func (c *Collector) isReported(host, ip string, now int64) bool {
	cutoff := now - int64(ReportedRetention/time.Second)
	for _, r := range ReadReportedFile(c.cfg.ReportedFile) {
		if r.Host == host && r.IP == ip && r.ReportedAt >= cutoff {
			return true
		}
	}
	return false
}

// spoolFiles возвращает pending.tsv, его .sending.* и pending.retry.* из того же каталога.
func (c *Collector) spoolFiles() []string {
	dir := filepath.Dir(c.cfg.PendingFile)
	entries, err := os.ReadDir(dir)
	files := []string{c.cfg.PendingFile}
	if err != nil {
		return files
	}
	var retry, sending []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(name, "pending.retry.") {
			retry = append(retry, filepath.Join(dir, name))
		} else if strings.HasPrefix(name, filepath.Base(c.cfg.PendingFile)+".sending.") {
			sending = append(sending, filepath.Join(dir, name))
		}
	}
	files = append(files, retry...)
	return append(files, sending...)
}

func (c *Collector) retryFiles() []string {
	return globPrefix(filepath.Dir(c.cfg.PendingFile), "pending.retry.")
}

func (c *Collector) sendingFiles() []string {
	return globPrefix(filepath.Dir(c.cfg.PendingFile), filepath.Base(c.cfg.PendingFile)+".sending.")
}

// globPrefix возвращает файлы каталога с данным префиксом имени в алфавитном порядке.
func globPrefix(dir, prefix string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

func (c *Collector) isQueued(host, ip string) bool {
	for _, f := range c.spoolFiles() {
		for _, r := range ReadPendingFile(f) {
			if r.IP == ip && r.Host == host {
				return true
			}
		}
	}
	return false
}

func (c *Collector) appendPending(row PendingRow) error {
	_, err := c.appendPendingBatch([]PendingRow{row})
	return err
}

func (c *Collector) appendPendingBatch(rows []PendingRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.PendingFile), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(c.cfg.PendingFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, row := range rows {
		if _, err := f.WriteString(row.TSV() + "\n"); err != nil {
			_ = f.Close()
			return written, err
		}
		written++
	}
	if err := f.Close(); err != nil {
		return written, err
	}
	lines := readLines(c.cfg.PendingFile)
	if len(lines) > MaxStateRows {
		return written, writeLines(c.cfg.PendingFile, tail(lines, MaxStateRows))
	}
	return written, nil
}

// --- запросы состояния ---

// Local возвращает все строки local.tsv.
func (c *Collector) Local() []LocalRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ReadLocalFile(c.cfg.LocalFile)
}

// Pending возвращает строки pending.tsv и всех retry-файлов.
func (c *Collector) Pending() []PendingRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	var rows []PendingRow
	rows = append(rows, ReadPendingFile(c.cfg.PendingFile)...)
	for _, f := range c.retryFiles() {
		rows = append(rows, ReadPendingFile(f)...)
	}
	return rows
}

// Reported возвращает строки reported.tsv.
func (c *Collector) Reported() []ReportedRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ReadReportedFile(c.cfg.ReportedFile)
}

// HasPending сообщает, что есть непустой pending.tsv или retry-файл
// (googlevideo_local_spool_has_pending).
func (c *Collector) HasPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range append([]string{c.cfg.PendingFile}, c.retryFiles()...) {
		if st, err := os.Stat(f); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

// KernelIPs возвращает до 128 уникальных публичных адресов с неистёкшим TTL,
// которых нет в центральном списке, — для набора ядра (googlevideo_local_kernel_ips).
func (c *Collector) KernelIPs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	set := map[string]struct{}{}
	for _, r := range ReadLocalFile(c.cfg.LocalFile) {
		if r.Expires > now {
			set[r.IP] = struct{}{}
		}
	}
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	// Сначала отбор, потом предел: непубличные и центральные адреса не должны
	// занимать места в 128 слотах.
	out := ips[:0]
	for _, ip := range ips {
		if PublicIPv4(ip) && !c.central(ip) {
			out = append(out, ip)
		}
	}
	if len(out) > KernelIPLimit {
		out = out[:KernelIPLimit]
	}
	return out
}

// LastObservation — последнее наблюдение для статуса.
type LastObservation struct {
	Host     string
	IP       string
	Observed time.Time
	// Age — возраст наблюдения (не отрицательный).
	Age time.Duration
}

// Describe форматирует наблюдение как в WebUI: «host → ip; N с назад».
func (l LastObservation) Describe() string {
	return fmt.Sprintf("%s → %s; %d с назад", l.Host, l.IP, int64(l.Age/time.Second))
}

// LastObservation возвращает строку local.tsv с наибольшим observed_at
// (googlevideo_local_last_observation). ok=false — наблюдений нет.
func (c *Collector) LastObservation() (LastObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best LocalRow
	for _, r := range ReadLocalFile(c.cfg.LocalFile) {
		if r.Observed > best.Observed {
			best = r
		}
	}
	if best.Observed == 0 {
		return LastObservation{}, false
	}
	age := c.now().Unix() - best.Observed
	if age < 0 {
		age = 0
	}
	return LastObservation{Host: best.Host, IP: best.IP, Observed: time.Unix(best.Observed, 0), Age: time.Duration(age) * time.Second}, true
}

// QueueLocal возвращает в очередь отправки подходящие строки local.tsv
// (googlevideo_queue_local_observations): допустимые имя и IP, не старше 7 суток,
// не отправленные за 30 суток и не стоящие в очереди. Для старых строк без
// observed_at время выводится как expires-7 суток (но не позже «сейчас»),
// чтобы миграция не «омолаживала» наблюдение. Возвращает число добавленных.
func (c *Collector) QueueLocal() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().Unix()
	maxAge := int64(ObservationMaxAge / time.Second)
	cutoff := now - int64(ReportedRetention/time.Second)
	reported := make(map[[2]string]struct{})
	for _, r := range ReadReportedFile(c.cfg.ReportedFile) {
		if r.ReportedAt >= cutoff {
			reported[[2]string{r.Host, r.IP}] = struct{}{}
		}
	}
	queued := make(map[[2]string]struct{})
	for _, file := range c.spoolFiles() {
		for _, r := range ReadPendingFile(file) {
			queued[[2]string{r.Host, r.IP}] = struct{}{}
		}
	}
	var pending []PendingRow
	for _, r := range ReadLocalFile(c.cfg.LocalFile) {
		observed := r.Observed
		if observed <= 0 {
			observed = r.Expires - maxAge
			if observed > now {
				observed = now
			}
		}
		if observed > now || now-observed > maxAge {
			continue
		}
		if !PublicIPv4(r.IP) || !ValidHostname(r.Host) {
			continue
		}
		key := [2]string{r.Host, r.IP}
		if _, ok := reported[key]; ok {
			continue
		}
		if _, ok := queued[key]; ok {
			continue
		}
		queued[key] = struct{}{}
		pending = append(pending, PendingRow{IP: r.IP, Observed: observed, Host: r.Host})
	}
	return c.appendPendingBatch(pending)
}
