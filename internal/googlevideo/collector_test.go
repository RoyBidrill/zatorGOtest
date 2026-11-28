package googlevideo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCentral map[string]bool

func (f fakeCentral) Contains(ip string) bool { return f[ip] }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_800_000_000, 0)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newCollector(t *testing.T, central CentralChecker) (*Collector, *clock) {
	t.Helper()
	clk := newClock()
	c := NewCollector(CollectorConfig{Dir: filepath.Join(t.TempDir(), "gv"), Central: central, Now: clk.Now})
	return c, clk
}

const (
	hostA = "rr1---sn-h5gtov-n8vl.googlevideo.com"
	hostB = "rr2---sn-h5gtov-n8vl.googlevideo.com"
	hostC = "rr3---sn-h5gtov-n8vl.googlevideo.com"
)

func mustObserve(t *testing.T, c *Collector, host, ip string, ttl int) ObserveResult {
	t.Helper()
	res, err := c.Observe(Observation{Host: host, IP: ip, TTL: ttl, Type: "A"})
	if err != nil {
		t.Fatalf("Observe(%s,%s): %v", host, ip, err)
	}
	return res
}

func writeText(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewCollector_DefaultPaths(t *testing.T) {
	c := NewCollector(CollectorConfig{})
	if c.LocalFile() != filepath.Join(DefaultStateDir, "local.tsv") ||
		c.PendingFile() != filepath.Join(DefaultStateDir, "pending.tsv") ||
		c.ReportedFile() != filepath.Join(DefaultStateDir, "reported.tsv") {
		t.Errorf("paths: %s %s %s", c.LocalFile(), c.PendingFile(), c.ReportedFile())
	}
	custom := NewCollector(CollectorConfig{Dir: "d", LocalFile: "l", PendingFile: "p", ReportedFile: "r"})
	if custom.LocalFile() != "l" || custom.PendingFile() != "p" || custom.ReportedFile() != "r" {
		t.Error("explicit paths must win")
	}
}

func TestObserve_StoresLocalAndPendingFormats(t *testing.T) {
	c, clk := newCollector(t, nil)
	res := mustObserve(t, c, "RR1---SN-H5GTOV-N8VL.googlevideo.com.", "9.9.9.9", 1200)
	now := clk.Now().Unix()
	if !res.Queued || res.AlreadyQueued || res.AlreadyReported || res.Central || res.Host != hostA ||
		res.Observed != now || res.Expires != now+1200 {
		t.Fatalf("result = %+v", res)
	}
	// local.tsv: host ip expires observed
	if got, want := readText(t, c.LocalFile()), fmt.Sprintf("%s\t9.9.9.9\t%d\t%d\n", hostA, now+1200, now); got != want {
		t.Errorf("local.tsv = %q, want %q", got, want)
	}
	// pending.tsv: ip observed host
	if got, want := readText(t, c.PendingFile()), fmt.Sprintf("9.9.9.9\t%d\t%s\n", now, hostA); got != want {
		t.Errorf("pending.tsv = %q, want %q", got, want)
	}
	if _, err := os.Stat(c.ReportedFile()); !os.IsNotExist(err) {
		t.Error("reported.tsv must not be created by Observe")
	}
	if !c.HasPending() {
		t.Error("HasPending")
	}
}

func TestObserve_DuplicateAndPerHostHistory(t *testing.T) {
	c, clk := newCollector(t, nil)
	mustObserve(t, c, hostA, "9.9.9.9", 600)
	clk.Advance(10 * time.Second)
	res := mustObserve(t, c, hostA, "9.9.9.9", 600)
	if res.Queued || !res.AlreadyQueued {
		t.Errorf("repeated pair must not be queued twice: %+v", res)
	}
	// local.tsv: строка пары обновлена, а не продублирована.
	rows := c.Local()
	if len(rows) != 1 || rows[0].Observed != clk.Now().Unix() {
		t.Errorf("local rows = %+v", rows)
	}
	// Другой хост на тот же IP — отдельная пара (история host/ip важна даже при
	// совпадении IP).
	res = mustObserve(t, c, hostB, "9.9.9.9", 600)
	if !res.Queued {
		t.Errorf("new host for the same ip must be queued: %+v", res)
	}
	mustObserve(t, c, hostC, "8.8.4.4", 600)
	if got := len(c.Pending()); got != 3 {
		t.Errorf("pending rows = %d, want 3", got)
	}
	if got := len(c.Local()); got != 3 {
		t.Errorf("local rows = %d, want 3", got)
	}
}

func TestObserve_Rejections(t *testing.T) {
	c, _ := newCollector(t, nil)
	cases := []struct {
		name string
		obs  Observation
		want error
	}{
		{"foreign host", Observation{Host: "youtube.com", IP: "9.9.9.9", TTL: 60}, ErrHostname},
		{"bare googlevideo.com", Observation{Host: "googlevideo.com", IP: "9.9.9.9", TTL: 60}, ErrHostname},
		{"empty host", Observation{IP: "9.9.9.9", TTL: 60}, ErrHostname},
		{"AAAA", Observation{Host: hostA, IP: "9.9.9.9", TTL: 60, Type: "AAAA"}, ErrRecordType},
		{"CNAME", Observation{Host: hostA, IP: "9.9.9.9", TTL: 60, Type: "CNAME"}, ErrRecordType},
		{"private ip", Observation{Host: hostA, IP: "192.168.1.1", TTL: 60}, ErrNonPublicIP},
		{"loopback", Observation{Host: hostA, IP: "127.0.0.1", TTL: 60}, ErrNonPublicIP},
		{"not an ip", Observation{Host: hostA, IP: "2001:db8::1", TTL: 60}, ErrNonPublicIP},
		{"zero ttl", Observation{Host: hostA, IP: "9.9.9.9", TTL: 0}, ErrTTL},
		{"negative ttl", Observation{Host: hostA, IP: "9.9.9.9", TTL: -5}, ErrTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Observe(tc.obs)
			if !errors.Is(err, tc.want) || !errors.Is(err, ErrRejected) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := os.Stat(c.LocalFile()); !os.IsNotExist(err) {
		t.Error("rejected observations must not touch the state files")
	}
	// Тип по умолчанию — A.
	if _, err := c.Observe(Observation{Host: hostA, IP: "9.9.9.9", TTL: 60}); err != nil {
		t.Errorf("empty type must mean A: %v", err)
	}
}

func TestObserve_TTLCapAndExpiry(t *testing.T) {
	c, clk := newCollector(t, nil)
	res := mustObserve(t, c, hostA, "9.9.9.9", 10_000_000)
	if res.Expires-res.Observed != MaxTTLSeconds {
		t.Errorf("ttl must be capped to 7 days: %d", res.Expires-res.Observed)
	}
	mustObserve(t, c, hostB, "8.8.4.4", 100)
	clk.Advance(101 * time.Second)
	mustObserve(t, c, hostC, "1.1.1.1", 100) // выбрасывает истёкшую строку hostB
	hosts := map[string]bool{}
	for _, r := range c.Local() {
		hosts[r.Host] = true
	}
	if hosts[hostB] || !hosts[hostA] || !hosts[hostC] || len(hosts) != 2 {
		t.Errorf("local hosts = %v", hosts)
	}
	// Очередь отправки живёт дольше TTL: строка hostB остаётся в pending.
	var pendingHosts []string
	for _, p := range c.Pending() {
		pendingHosts = append(pendingHosts, p.Host)
	}
	if len(pendingHosts) != 3 {
		t.Errorf("pending = %v", pendingHosts)
	}
}

func TestObserveText(t *testing.T) {
	c, _ := newCollector(t, nil)
	if _, err := c.ObserveText(hostA, "9.9.9.9", "300", "A"); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []string{"", "abc", "0", "00", "-1", "1.5", "12x"} {
		if _, err := c.ObserveText(hostA, "8.8.4.4", ttl, "A"); !errors.Is(err, ErrTTL) {
			t.Errorf("ttl %q: %v", ttl, err)
		}
	}
	res, err := c.ObserveText(hostB, "8.8.4.4", "99999999999", "A")
	if err != nil || res.Expires-res.Observed != MaxTTLSeconds {
		t.Errorf("long ttl: %v %+v", err, res)
	}
	if _, err := c.ObserveText(hostC, "1.1.1.1", "60", "AAAA"); !errors.Is(err, ErrRecordType) {
		t.Errorf("type: %v", err)
	}
}

func TestParseTTL(t *testing.T) {
	cases := map[string]int{"1": 1, "300": 300, "604800": 604800, "604801": 604800, "999999": 604800, "1000000": 604800, "0000001": MaxTTLSeconds, "000300": 300}
	for in, want := range cases {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "000000", "x", "-5", " 5", "5 "} {
		if _, err := ParseTTL(in); !errors.Is(err, ErrTTL) {
			t.Errorf("ParseTTL(%q) must fail", in)
		}
	}
}

func TestObserve_ReportedSuppressesQueue(t *testing.T) {
	c, clk := newCollector(t, nil)
	now := clk.Now().Unix()
	writeText(t, c.ReportedFile(), fmt.Sprintf(
		"%s\t9.9.9.9\t%d\n%s\t8.8.4.4\t%d\n", hostA, now-3600, hostB, now-int64(31*24*3600)))

	res := mustObserve(t, c, hostA, "9.9.9.9", 600)
	if !res.AlreadyReported || res.Queued {
		t.Errorf("recently reported: %+v", res)
	}
	// Запись старше 30 суток не мешает повторной отправке.
	res = mustObserve(t, c, hostB, "8.8.4.4", 600)
	if res.AlreadyReported || !res.Queued {
		t.Errorf("stale report: %+v", res)
	}
	// Но local.tsv пополняется в любом случае.
	if len(c.Local()) != 2 {
		t.Errorf("local = %+v", c.Local())
	}
	if p := c.Pending(); len(p) != 1 || p[0].Host != hostB {
		t.Errorf("pending = %+v", p)
	}
}

func TestObserve_DedupAcrossSpoolFiles(t *testing.T) {
	c, clk := newCollector(t, nil)
	dir := filepath.Dir(c.PendingFile())
	now := clk.Now().Unix()
	writeText(t, c.PendingFile()+".sending.123", fmt.Sprintf("9.9.9.9\t%d\t%s\n", now, hostA))
	writeText(t, filepath.Join(dir, "pending.retry.1.2"), fmt.Sprintf("8.8.4.4\t%d\t%s\n", now, hostB))

	if res := mustObserve(t, c, hostA, "9.9.9.9", 60); !res.AlreadyQueued {
		t.Errorf("sending file must dedupe: %+v", res)
	}
	if res := mustObserve(t, c, hostB, "8.8.4.4", 60); !res.AlreadyQueued {
		t.Errorf("retry file must dedupe: %+v", res)
	}
	if res := mustObserve(t, c, hostC, "8.8.4.4", 60); !res.Queued {
		t.Errorf("different host must be queued: %+v", res)
	}
	// HasPending видит retry-файл даже без pending.tsv.
	c2, _ := newCollector(t, nil)
	if c2.HasPending() {
		t.Error("empty collector has no pending")
	}
	writeText(t, filepath.Join(filepath.Dir(c2.PendingFile()), "pending.retry.5.6"), "9.9.9.9\t1\thost\n")
	if !c2.HasPending() {
		t.Error("retry file counts as pending")
	}
	if len(c2.Pending()) != 1 {
		t.Errorf("Pending() must include retry rows: %+v", c2.Pending())
	}
}

func TestObserve_RowLimits(t *testing.T) {
	c, clk := newCollector(t, nil)
	now := clk.Now().Unix()
	var local, pending strings.Builder
	for i := 0; i < MaxStateRows; i++ {
		fmt.Fprintf(&local, "rr1---sn-old%d.googlevideo.com\t11.0.%d.%d\t%d\t%d\n", i, i>>8, i&255, now+1000, now-1)
		fmt.Fprintf(&pending, "11.0.%d.%d\t%d\trr1---sn-old%d.googlevideo.com\n", i>>8, i&255, now-1, i)
	}
	writeText(t, c.LocalFile(), local.String())
	writeText(t, c.PendingFile(), pending.String())

	mustObserve(t, c, hostA, "9.9.9.9", 600)

	rows := c.Local()
	if len(rows) != MaxStateRows || rows[len(rows)-1].Host != hostA || rows[0].Host != "rr1---sn-old1.googlevideo.com" {
		t.Errorf("local: %d rows, first=%s last=%s", len(rows), rows[0].Host, rows[len(rows)-1].Host)
	}
	pend := ReadPendingFile(c.PendingFile())
	if len(pend) != MaxStateRows || pend[len(pend)-1].Host != hostA || pend[0].Host != "rr1---sn-old1.googlevideo.com" {
		t.Errorf("pending: %d rows, first=%s", len(pend), pend[0].Host)
	}
}

func TestObserve_CentralIPFlag(t *testing.T) {
	c, _ := newCollector(t, fakeCentral{"9.9.9.9": true})
	res := mustObserve(t, c, hostA, "9.9.9.9", 600)
	// Пара всё равно попадает в историю: IP из центрального списка не исключает наблюдение.
	if !res.Central || !res.Queued {
		t.Errorf("central ip: %+v", res)
	}
	if res := mustObserve(t, c, hostB, "8.8.4.4", 600); res.Central {
		t.Error("non-central ip flagged as central")
	}
}

func TestKernelIPs(t *testing.T) {
	c, clk := newCollector(t, fakeCentral{"8.8.4.4": true})
	mustObserve(t, c, hostA, "9.9.9.9", 600)
	mustObserve(t, c, hostB, "9.9.9.9", 600) // дубль IP
	mustObserve(t, c, hostC, "8.8.4.4", 600) // в центральном списке
	mustObserve(t, c, "rr9---sn-x.googlevideo.com", "1.1.1.1", 30)
	if got := c.KernelIPs(); !reflect.DeepEqual(got, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Errorf("KernelIPs = %v", got)
	}
	clk.Advance(31 * time.Second)
	if got := c.KernelIPs(); !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
		t.Errorf("after expiry = %v", got)
	}
	clk.Advance(time.Hour)
	if got := c.KernelIPs(); len(got) != 0 {
		t.Errorf("all expired = %v", got)
	}
}

func TestKernelIPs_Limit128(t *testing.T) {
	c, clk := newCollector(t, nil)
	now := clk.Now().Unix()
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "rr1---sn-h%d.googlevideo.com\t11.0.0.%d\t%d\t%d\n", i, i, now+100, now)
	}
	// Непубличные адреса в файле игнорируются.
	fmt.Fprintf(&b, "rr1---sn-p.googlevideo.com\t10.1.1.1\t%d\t%d\n", now+100, now)
	writeText(t, c.LocalFile(), b.String())
	got := c.KernelIPs()
	if len(got) != KernelIPLimit {
		t.Errorf("len = %d, want %d", len(got), KernelIPLimit)
	}
	for _, ip := range got {
		if !PublicIPv4(ip) {
			t.Errorf("non-public %s", ip)
		}
	}
}

func TestLastObservation(t *testing.T) {
	c, clk := newCollector(t, nil)
	if _, ok := c.LastObservation(); ok {
		t.Error("no observations yet")
	}
	now := clk.Now().Unix()
	writeText(t, c.LocalFile(), fmt.Sprintf(
		"rr1---sn-old.googlevideo.com\t9.9.9.8\t%d\t%d\nrr1---sn-new.googlevideo.com\t9.9.9.9\t%d\t%d\nrr1---sn-legacy.googlevideo.com\t9.9.9.7\t%d\n",
		now+60, now-20, now+60, now-3, now+60))
	last, ok := c.LastObservation()
	if !ok || last.Host != "rr1---sn-new.googlevideo.com" || last.IP != "9.9.9.9" || last.Age != 3*time.Second {
		t.Fatalf("last = %+v", last)
	}
	if got := last.Describe(); got != "rr1---sn-new.googlevideo.com → 9.9.9.9; 3 с назад" {
		t.Errorf("Describe = %q", got)
	}
	// Наблюдение «из будущего» даёт нулевой возраст, а не отрицательный.
	writeText(t, c.LocalFile(), fmt.Sprintf("rr1---sn-f.googlevideo.com\t9.9.9.9\t%d\t%d\n", now+60, now+30))
	if last, _ := c.LastObservation(); last.Age != 0 {
		t.Errorf("age = %v", last.Age)
	}
	// Только старые трёхколоночные строки: observed неизвестен.
	writeText(t, c.LocalFile(), fmt.Sprintf("rr1---sn-l.googlevideo.com\t9.9.9.9\t%d\n", now+60))
	if _, ok := c.LastObservation(); ok {
		t.Error("legacy rows have no observation time")
	}
}

func TestQueueLocal(t *testing.T) {
	c, clk := newCollector(t, nil)
	now := clk.Now().Unix()
	week := int64(7 * 24 * 3600)
	writeText(t, c.LocalFile(), strings.Join([]string{
		fmt.Sprintf("%s\t9.9.9.1\t%d\t%d", hostA, now+600, now-60),     // новая → в очередь
		fmt.Sprintf("%s\t9.9.9.2\t%d\t%d", hostB, now+600, now-week-1), // старше 7 суток
		fmt.Sprintf("bad.example.com\t9.9.9.3\t%d\t%d", now+600, now),  // чужое имя
		fmt.Sprintf("%s\t10.0.0.5\t%d\t%d", hostC, now+600, now),       // непубличный IP
		fmt.Sprintf("%s\t9.9.9.4\t%d\t%d", hostA, now+600, now-30),     // уже отправлено
		fmt.Sprintf("%s\t9.9.9.5\t%d\t%d", hostB, now+600, now-30),     // уже в очереди
		fmt.Sprintf("%s\t9.9.9.6\t%d", hostC, now+week-100),            // legacy: observed = expires-7d = now-100
		fmt.Sprintf("%s\t9.9.9.7\t%d", hostC, now+600),                 // legacy: observed = now-week+600
		fmt.Sprintf("%s\t9.9.9.8\t%d\t%d", hostA, now+600, now+1000),   // из будущего
		"garbage line",
		"",
	}, "\n")+"\n")
	writeText(t, c.ReportedFile(), fmt.Sprintf("%s\t9.9.9.4\t%d\n", hostA, now-10))
	writeText(t, c.PendingFile(), fmt.Sprintf("9.9.9.5\t%d\t%s\n", now-5, hostB))

	n, err := c.QueueLocal()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("queued = %d, want 3", n)
	}
	got := map[string]int64{}
	for _, p := range c.Pending() {
		got[p.IP] = p.Observed
	}
	if got["9.9.9.1"] != now-60 || got["9.9.9.6"] != now-100 || got["9.9.9.7"] != now+600-week {
		t.Errorf("pending observed times: %v", got)
	}
	if len(got) != 4 { // + прежняя 9.9.9.5
		t.Errorf("pending = %v", got)
	}
	// Повторный вызов ничего не добавляет.
	if n, _ := c.QueueLocal(); n != 0 {
		t.Errorf("second call queued %d", n)
	}
	// Старая строка не «молодеет»: observed не превышает now.
	writeText(t, c.LocalFile(), fmt.Sprintf("%s\t9.9.9.9\t%d\n", hostA, now+10*week))
	_, _ = c.QueueLocal()
	// expires-7d = now+3 недели → обрезается до now
	for _, p := range c.Pending() {
		if p.IP == "9.9.9.9" && p.Observed != now {
			t.Errorf("observed must be capped at now: %d vs %d", p.Observed, now)
		}
	}
}

func TestRowFormatsRoundTrip(t *testing.T) {
	l := LocalRow{Host: hostA, IP: "9.9.9.9", Expires: 200, Observed: 100}
	if l.TSV() != hostA+"\t9.9.9.9\t200\t100" {
		t.Errorf("local TSV = %q", l.TSV())
	}
	if (LocalRow{Host: hostA, IP: "9.9.9.9", Expires: 200}).TSV() != hostA+"\t9.9.9.9\t200" {
		t.Error("legacy local row has three columns")
	}
	p := PendingRow{IP: "9.9.9.9", Observed: 100, Host: hostA}
	if p.TSV() != "9.9.9.9\t100\t"+hostA {
		t.Errorf("pending TSV = %q", p.TSV())
	}
	if (PendingRow{IP: "9.9.9.9", Observed: 100}).TSV() != "9.9.9.9\t100" {
		t.Error("legacy pending row has two columns")
	}
	r := ReportedRow{Host: hostA, IP: "9.9.9.9", ReportedAt: 300}
	if r.TSV() != hostA+"\t9.9.9.9\t300" {
		t.Errorf("reported TSV = %q", r.TSV())
	}

	dir := t.TempDir()
	writeText(t, filepath.Join(dir, "l"), l.TSV()+"\nbroken\nh\tip\tNaN\n\nh\tip\t5\t-1\n"+LocalRow{Host: "x", IP: "y", Expires: 5}.TSV()+"\r\n")
	rows := ReadLocalFile(filepath.Join(dir, "l"))
	if len(rows) != 3 || rows[0] != l || rows[1].Observed != 0 || rows[2].Host != "x" {
		t.Errorf("local rows = %+v", rows)
	}
	writeText(t, filepath.Join(dir, "p"), p.TSV()+"\nip\tNaN\nonly\n9.9.9.8\t7\n")
	prow := ReadPendingFile(filepath.Join(dir, "p"))
	if len(prow) != 2 || prow[0] != p || prow[1].Host != "" || prow[1].Observed != 7 {
		t.Errorf("pending rows = %+v", prow)
	}
	writeText(t, filepath.Join(dir, "r"), r.TSV()+"\nx\ty\n")
	if rr := ReadReportedFile(filepath.Join(dir, "r")); len(rr) != 1 || rr[0] != r {
		t.Errorf("reported rows = %+v", rr)
	}
	if ReadLocalFile(filepath.Join(dir, "missing")) != nil || ReadPendingFile(filepath.Join(dir, "missing")) != nil || ReadReportedFile(filepath.Join(dir, "missing")) != nil {
		t.Error("missing files give nil")
	}
}

func TestObserve_ConcurrentWriters(t *testing.T) {
	c, _ := newCollector(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.Observe(Observation{Host: fmt.Sprintf("rr1---sn-h%d.googlevideo.com", i), IP: fmt.Sprintf("11.1.1.%d", i+1), TTL: 600})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if n := len(c.Local()); n != 24 {
		t.Errorf("local rows = %d, want 24", n)
	}
	if n := len(c.Pending()); n != 24 {
		t.Errorf("pending rows = %d, want 24", n)
	}
}

func TestCollector_LogsDecisions(t *testing.T) {
	var logs []string
	clk := newClock()
	c := NewCollector(CollectorConfig{Dir: t.TempDir(), Now: clk.Now, Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }})
	mustObserve(t, c, hostA, "9.9.9.9", 60)
	mustObserve(t, c, hostA, "9.9.9.9", 60)
	_, _ = c.Observe(Observation{Host: "evil.com", IP: "9.9.9.9", TTL: 60})
	_, _ = c.Observe(Observation{Host: hostA, IP: "10.0.0.1", TTL: 60})
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"result=queued", "result=already_queued", "reason=hostname", "reason=non_public_ip"} {
		if !strings.Contains(joined, want) {
			t.Errorf("log lacks %q:\n%s", want, joined)
		}
	}
}

func TestObserveBatch(t *testing.T) {
	clk := newClock()
	dir := filepath.Join(t.TempDir(), "gv")
	hostsPath := filepath.Join(t.TempDir(), "googlevideo-hosts.txt")
	c := NewCollector(CollectorConfig{Dir: dir, HostsFile: hostsPath, Now: clk.Now})
	now := clk.Now().Unix()

	writeText(t, c.ReportedFile(), fmt.Sprintf("%s\t9.9.9.1\t%d\n", hostA, now-60))
	writeText(t, c.PendingFile(), fmt.Sprintf("9.9.9.2\t%d\t%s\n", now-30, hostB))

	results, err := c.ObserveBatch([]Observation{
		{Host: "invalid.example.com", IP: "9.9.9.9", TTL: 60},   // отбрасывается
		{Host: hostA, IP: "10.0.0.1", TTL: 60},                  // отбрасывается
		{Host: hostA, IP: "9.9.9.1", TTL: 300, Type: "A"},       // already_reported
		{Host: hostB, IP: "9.9.9.2", TTL: 300, Type: "A"},       // already_queued
		{Host: hostC, IP: "9.9.9.3", TTL: 300, Type: "A"},       // queued
		{Host: hostC, IP: "9.9.9.3", TTL: 600, Type: "A"},       // дубль в батче -> already_queued, обновляет TTL в local
	})
	if err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4: %+v", len(results), results)
	}
	if !results[0].AlreadyReported || results[0].Queued {
		t.Errorf("results[0] = %+v", results[0])
	}
	if !results[1].AlreadyQueued || results[1].Queued {
		t.Errorf("results[1] = %+v", results[1])
	}
	if !results[2].Queued {
		t.Errorf("results[2] = %+v", results[2])
	}
	if !results[3].AlreadyQueued || results[3].Queued {
		t.Errorf("results[3] = %+v", results[3])
	}
	if got := len(c.Local()); got != 3 {
		t.Fatalf("local rows = %d, want 3", got)
	}
	if got := len(c.Pending()); got != 2 {
		t.Fatalf("pending rows = %d, want 2", got)
	}
	hosts, err := NewHostsFile(hostsPath).List()
	if err != nil || len(hosts) != 3 {
		t.Fatalf("hosts = %v err=%v", hosts, err)
	}
}
