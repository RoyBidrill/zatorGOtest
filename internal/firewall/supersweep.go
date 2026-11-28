package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Постоянные транспорта SuperSweep (совпадают с lib/supersweep_transport.sh).
const (
	// SuperSweepQueue — выделенная очередь изолированного nfqws2.
	SuperSweepQueue = 65535
	// SuperSweepPortFirst/Last — зарезервированные локальные порты проб curl.
	SuperSweepPortFirst = 62000
	SuperSweepPortLast  = 62999
	// SuperSweepProbeUID — пользователь изолированного nfqws2.
	SuperSweepProbeUID = 65533
	// SuperSweepComment — комментарий собственных nft-правил.
	SuperSweepComment = "z2r_supersweep"
	// SuperSweepNftOutputChain — собственная nft-цепочка route/output.
	SuperSweepNftOutputChain = "z2r_supersweep_output"
	// DefaultPortRangeFile — диапазон эфемерных портов ядра.
	DefaultPortRangeFile = "/proc/sys/net/ipv4/ip_local_port_range"

	// iptables-цепочки изоляции.
	SSChainOut  = "Z2R_SS_OUT"
	SSChainPost = "Z2R_SS_POST"
	SSChainPre  = "Z2R_SS_PRE"
	SSChainIn   = "Z2R_SS_IN"
	SSChainRaw  = "Z2R_SS_RAW"
)

// Хуки iptables в порядке установки.
var superSweepInstallHooks = []string{"POSTROUTING", "PREROUTING", "INPUT", "OUTPUT", "RAWOUTPUT", "SOCKETOUTPUT"}

// Цепочки в порядке создания.
var superSweepChains = []string{SSChainOut, SSChainPost, SSChainPre, SSChainIn, SSChainRaw}

// Ошибки SuperSweep.
var (
	// ErrSuperSweepInvalid — некорректная конфигурация транспорта.
	ErrSuperSweepInvalid = errors.New("firewall: invalid supersweep configuration")
	// ErrUnfinishedCleanup — предыдущая очистка не завершена.
	ErrUnfinishedCleanup = errors.New("firewall: unfinished supersweep cleanup; call Stop first")
	// ErrEphemeralOverlap — зарезервированные порты пересекаются с диапазоном ядра.
	ErrEphemeralOverlap = errors.New("firewall: reserved ports overlap kernel ephemeral range")
	// ErrStaleNftRules — в nft найдены чужие/устаревшие правила и цепочка проб.
	ErrStaleNftRules = errors.New("firewall: foreign/stale nft supersweep rules exist")
	// ErrCleanupIncomplete — очистка не завершена, повторите Stop.
	ErrCleanupIncomplete = errors.New("firewall: supersweep cleanup incomplete; retry Stop")
	// ErrTransportInactive — транспорт не активен или его правила повреждены.
	ErrTransportInactive = errors.New("firewall: supersweep transport inactive or damaged")
)

var nftChainLineRe = regexp.MustCompile(`^\s*chain\s+(\S+)\s*\{`)

// SuperSweepConfig — параметры изоляции проб SuperSweep.
type SuperSweepConfig struct {
	// Backend — iptables или nftables (явный выбор обязателен).
	Backend Backend
	// Marks — метки: Desync, DesyncPostnat, Filter, ClientScopeMask
	// (SuperSweep по умолчанию 0x08000000).
	Marks MarkSet
	// Wssize — активная конфигурация WSSIZE для маркировки проб до NFQUEUE.
	Wssize *WssizeConfig
	// Postnat — NAT-хуки zapret2 (см. PostnatFromGetter).
	Postnat bool
	// NftTable — таблица zapret2 (по умолчанию zapret2).
	NftTable string
	// QNum — очередь изолированного nfqws2 (по умолчанию 65535).
	QNum int
	// PortFirst/PortLast — зарезервированные порты (по умолчанию 62000–62999).
	PortFirst, PortLast int
	// ProbeUID — UID изолированного nfqws2 для -m owner / meta skuid
	// (по умолчанию SuperSweepProbeUID; на Keenetic обычно nobody=65534).
	ProbeUID uint32
	// TrafficUID — UID Go-процесса, который открывает тестовые HTTP-соединения.
	// Он отдельный от ProbeUID: nfqws2 запускается от nobody, а checker обычно от root.
	TrafficUID uint32
	// IptWait — аргументы ожидания xtables-блокировки (например "-w","5").
	// nil: определяется автоматически при Start.
	IptWait []string
	// PortRangeFile — файл диапазона эфемерных портов ядра.
	PortRangeFile string
	// RetryDelay — пауза между попытками Reconcile (по умолчанию 3 с).
	RetryDelay time.Duration
	// ReadFile заменяет os.ReadFile (для тестов).
	ReadFile func(string) ([]byte, error)
}

// DefaultSuperSweepConfig возвращает конфигурацию по умолчанию.
func DefaultSuperSweepConfig() SuperSweepConfig {
	return SuperSweepConfig{
		Marks:         DefaultMarks(),
		Postnat:       true,
		NftTable:      DefaultNftTable,
		QNum:          SuperSweepQueue,
		PortFirst:     SuperSweepPortFirst,
		PortLast:      SuperSweepPortLast,
		PortRangeFile: DefaultPortRangeFile,
		RetryDelay:    3 * time.Second,
	}
}

// SuperSweepConfigFromGetter строит конфигурацию из переменных zapret2
// (FWTYPE, метки, POSTNAT, POSTNAT_ALL, ZAPRET_NFT_TABLE).
func SuperSweepConfigFromGetter(get Getter) (SuperSweepConfig, error) {
	c := DefaultSuperSweepConfig()
	if b, ok := ParseBackend(getTrim(get, "FWTYPE")); ok {
		c.Backend = b
	}
	marks, err := MarksFromGetter(get)
	if err != nil {
		return c, err
	}
	c.Marks = marks
	c.Postnat = PostnatFromGetter(get)
	if v := getTrim(get, "ZAPRET_NFT_TABLE"); v != "" {
		c.NftTable = v
	}
	return c, nil
}

func (c SuperSweepConfig) withDefaults() SuperSweepConfig {
	if c.NftTable == "" {
		c.NftTable = DefaultNftTable
	}
	if c.QNum == 0 {
		c.QNum = SuperSweepQueue
	}
	if c.PortFirst == 0 && c.PortLast == 0 {
		c.PortFirst, c.PortLast = SuperSweepPortFirst, SuperSweepPortLast
	}
	if c.PortRangeFile == "" {
		c.PortRangeFile = DefaultPortRangeFile
	}
	if c.Marks.SuperSweep == 0 {
		c.Marks.SuperSweep = SuperSweepMark
	}
	if c.ProbeUID == 0 {
		c.ProbeUID = SuperSweepProbeUID
	}
	return c
}

// Validate проверяет backend, таблицу, порты, очередь и метки.
func (c SuperSweepConfig) Validate() error {
	c = c.withDefaults()
	if c.Backend != BackendIptables && c.Backend != BackendNftables {
		return fmt.Errorf("%w: backend must be iptables or nftables", ErrSuperSweepInvalid)
	}
	if !nftTableRe.MatchString(c.NftTable) {
		return fmt.Errorf("%w: invalid nft table name %q", ErrSuperSweepInvalid, c.NftTable)
	}
	if c.PortFirst < 1 || c.PortLast < c.PortFirst || c.PortLast > 65535 {
		return fmt.Errorf("%w: invalid reserved port range %d-%d", ErrSuperSweepInvalid, c.PortFirst, c.PortLast)
	}
	if c.QNum < 1 || c.QNum > 65535 {
		return fmt.Errorf("%w: invalid queue number %d", ErrSuperSweepInvalid, c.QNum)
	}
	if err := c.Marks.CheckSuperSweep(); err != nil {
		return err
	}
	if c.Wssize != nil && c.Wssize.Active() {
		w := c.Wssize.withDefaults()
		if err := w.Validate(); err != nil {
			return err
		}
		if w.Backend != c.Backend || w.NftTable != c.NftTable || w.Postnat != c.Postnat || w.Marks != c.Marks {
			return fmt.Errorf("%w: WSSIZE and SuperSweep firewall settings differ", ErrSuperSweepInvalid)
		}
	}
	return nil
}

// CheckEphemeralRange сверяет диапазон эфемерных портов ядра (first, last) с
// зарезервированными портами SuperSweep.
func (c SuperSweepConfig) CheckEphemeralRange(first, last int) error {
	c = c.withDefaults()
	if first <= 0 || last < first || last > 65535 {
		return fmt.Errorf("%w: invalid kernel ephemeral port range %d-%d", ErrSuperSweepInvalid, first, last)
	}
	if !(last < c.PortFirst || first > c.PortLast) {
		return fmt.Errorf("%w: %d-%d vs %d-%d", ErrEphemeralOverlap, c.PortFirst, c.PortLast, first, last)
	}
	return nil
}

// ParsePortRange разбирает содержимое ip_local_port_range ("32768\t60999").
func ParsePortRange(data string) (first, last int, err error) {
	f := strings.Fields(data)
	if len(f) != 2 || len(f[0]) > 5 || len(f[1]) > 5 {
		return 0, 0, fmt.Errorf("%w: cannot parse kernel ephemeral port range %q", ErrSuperSweepInvalid, strings.TrimSpace(data))
	}
	if first, err = strconv.Atoi(f[0]); err != nil {
		return 0, 0, fmt.Errorf("%w: %q", ErrSuperSweepInvalid, f[0])
	}
	if last, err = strconv.Atoi(f[1]); err != nil {
		return 0, 0, fmt.Errorf("%w: %q", ErrSuperSweepInvalid, f[1])
	}
	return first, last, nil
}

func (c SuperSweepConfig) iptPorts() string   { return fmt.Sprintf("%d:%d", c.PortFirst, c.PortLast) }
func (c SuperSweepConfig) nftPorts() string   { return fmt.Sprintf("%d-%d", c.PortFirst, c.PortLast) }
func (c SuperSweepConfig) markDesync() string { return markPair(c.Marks.Desync, c.Marks.Desync) }
func (c SuperSweepConfig) markSS() string {
	return markPair(c.Marks.SuperSweep, c.Marks.SuperSweep)
}

// IptablesChains возвращает имена изолирующих цепочек в порядке создания.
func (c SuperSweepConfig) IptablesChains() []string {
	return append([]string(nil), superSweepChains...)
}

// IptablesHooks возвращает имена хуков в порядке установки.
// RAWOUTPUT и SOCKETOUTPUT — логические хуки цепочки OUTPUT.
func (c SuperSweepConfig) IptablesHooks() []string {
	return append([]string(nil), superSweepInstallHooks...)
}

// IptablesHookArgs возвращает аргументы правила хука (без "-t mangle" и ожидания):
// action — "-I", "-D" или "-C".
func (c SuperSweepConfig) IptablesHookArgs(action, hook string) ([]string, error) {
	c = c.withDefaults()
	d, ss, ports := c.markDesync(), c.markSS(), c.iptPorts()
	tcpOut := []string{"-p", "tcp", "--sport", ports, "--dport", "443"}
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	switch hook {
	case "OUTPUT":
		return join([]string{action, "OUTPUT"}, tcpOut,
			[]string{"-m", "owner", "--uid-owner", "0", "-m", "mark", "!", "--mark", d, "-j", SSChainOut}), nil
	case "RAWOUTPUT":
		return join([]string{action, "OUTPUT"}, tcpOut,
			[]string{"-m", "owner", "--uid-owner", strconv.Itoa(int(c.ProbeUID)), "-j", SSChainRaw}), nil
	case "SOCKETOUTPUT":
		return join([]string{action, "OUTPUT"}, tcpOut,
			[]string{"-m", "owner", "!", "--socket-exists", "-m", "mark", "!", "--mark", d, "-j", SSChainOut}), nil
	case "POSTROUTING":
		return join([]string{action, "POSTROUTING"}, tcpOut,
			[]string{"-m", "mark", "!", "--mark", d, "-m", "mark", "--mark", ss,
				"-m", "conntrack", "--ctdir", "ORIGINAL", "-j", SSChainPost}), nil
	case "PREROUTING", "INPUT":
		target := SSChainPre
		if hook == "INPUT" {
			target = SSChainIn
		}
		return join([]string{action, hook},
			[]string{"-p", "tcp", "--sport", "443", "--dport", ports,
				"-m", "mark", "!", "--mark", d,
				"-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "REPLY",
				"-m", "connmark", "--mark", ss, "-j", target}), nil
	}
	return nil, fmt.Errorf("%w: unknown hook %q", ErrSuperSweepInvalid, hook)
}

// IptablesChainRules возвращает правила (аргументы "-A ...") для наполнения
// изолирующих цепочек. Хуки сюда не входят: они активируются последними.
func (c SuperSweepConfig) IptablesChainRules() [][]string {
	c = c.withDefaults()
	d, ss := c.markDesync(), c.markSS()
	q := strconv.Itoa(c.QNum)
	raw := FormatMark(c.Marks.Desync | c.Marks.SuperSweep)
	rules := [][]string{
		{"-A", SSChainOut, "-p", "tcp", "--sport", c.iptPorts(), "--dport", "443",
			"-m", "mark", "!", "--mark", d, "-j", "MARK", "--set-xmark", ss},
		{"-A", SSChainOut, "-j", "CONNMARK", "--or-mark", FormatMark(c.Marks.SuperSweep)},
		{"-A", SSChainOut, "-j", "ACCEPT"},
		{"-A", SSChainPre, "-j", "CONNMARK", "--restore-mark",
			"--nfmask", FormatMark(c.Marks.SuperSweep), "--ctmask", FormatMark(c.Marks.SuperSweep)},
		// ACCEPT завершает mangle-хук и обходит рабочий NFQUEUE-путь.
		{"-A", SSChainPre, "-j", "ACCEPT"},
		{"-A", SSChainPost, "-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"},
		{"-A", SSChainPost, "-j", "ACCEPT"},
		{"-A", SSChainIn, "-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"},
		{"-A", SSChainIn, "-j", "ACCEPT"},
	}
	if c.Wssize != nil && c.Wssize.Active() {
		w := c.Wssize.withDefaults()
		// HTTP checker runs in the Go daemon, not in the nfqws2 process.
		// Mark its reserved Googlevideo sockets in the normal OUTPUT chain.
		wssizeOut := []string{"-A", SSChainOut, "-m", "owner", "--uid-owner", strconv.Itoa(int(c.TrafficUID)),
			"-m", "set", "--match-set", w.SetName, "dst", "-p", "tcp", "--dport", "443",
			"-m", "mark", "!", "--mark", markPair(w.Marks.Desync, w.Marks.Desync),
			"-j", "MARK", "--set-xmark", markPair(w.Marks.Wssize, w.Marks.Wssize)}
		rules = append([][]string{wssizeOut}, rules...)
		desync := markPair(w.Marks.Desync, w.Marks.Desync)
		rules = append(rules,
			[]string{"-A", SSChainRaw, "-m", "set", "--match-set", w.SetName, "dst", "-p", "tcp", "--dport", "443",
				"-m", "mark", "!", "--mark", desync, "-j", "MARK", "--set-xmark", markPair(w.Marks.Wssize, w.Marks.Wssize)},
		)
	}
	rules = append(rules,
		[]string{"-A", SSChainRaw, "-j", "MARK", "--or-mark", raw},
		[]string{"-A", SSChainRaw, "-j", "ACCEPT"},
	)
	return rules
}

// IptablesInstallCommands возвращает полную последовательность команд установки
// (создание цепочек, правила, затем активация хуков) для ручного применения
// или генерации скриптов. wait — необязательные аргументы ожидания (-w 5).
func (c SuperSweepConfig) IptablesInstallCommands(wait ...string) ([]Command, error) {
	ipt := func(args ...string) Command {
		a := append(append([]string(nil), wait...), "-t", "mangle")
		return Command{Name: "iptables", Args: append(a, args...)}
	}
	var cmds []Command
	for _, ch := range superSweepChains {
		cmds = append(cmds, ipt("-N", ch))
	}
	for _, rule := range c.IptablesChainRules() {
		cmds = append(cmds, ipt(rule...))
	}
	for _, hook := range superSweepInstallHooks {
		args, err := c.IptablesHookArgs("-I", hook)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, ipt(args...))
	}
	return cmds, nil
}

// NftChains возвращает имена nft-цепочек (post, pre).
func (c SuperSweepConfig) NftChains() (post, pre string) {
	if c.Postnat {
		return "postnat_hook", "prenat_hook"
	}
	return "postrouting_hook", "prerouting_hook"
}

// NftRuleCount — ожидаемое число собственных nft-правил (10, с NAT-хуками 11).
func (c SuperSweepConfig) NftRuleCount() int {
	post, _ := c.NftChains()
	n := 10
	if post == "postnat_hook" {
		n++
	}
	if c.Wssize != nil && c.Wssize.Active() {
		n++
	}
	return n
}

// NftTransaction возвращает атомарную nft-транзакцию установки: вставки в
// нативные хуки zapret2 (в обратном порядке: mark, queue, return) и цепочку
// route/output для проб.
func (c SuperSweepConfig) NftTransaction() string {
	c = c.withDefaults()
	post, pre := c.NftChains()
	t := c.NftTable
	d := FormatMark(c.Marks.Desync)
	ss := FormatMark(c.Marks.SuperSweep)
	ports := c.nftPorts()
	out := fmt.Sprintf("meta nfproto ipv4 meta mark & %s == 0 meta mark & %s != 0 tcp sport %s tcp dport 443", d, ss, ports)
	reply := fmt.Sprintf("meta nfproto ipv4 ct direction reply ct state established ct mark & %s != 0 tcp sport 443 tcp dport %s", ss, ports)
	cm := ` comment "` + SuperSweepComment + `"`
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	// После mangle OUTPUT policy routing затирает ранний mark и отправляет пробы
	// в VPN: route-цепочка пересчитывает только наши потоки.
	w("create chain inet %s %s { type route hook output priority -1; policy accept; }", t, SuperSweepNftOutputChain)
	if c.Wssize != nil && c.Wssize.Active() {
		ws := c.Wssize.withDefaults()
		w("add rule inet %s %s meta nfproto ipv4 meta skuid %d tcp sport %s tcp dport 443 ip daddr @%s meta mark & %s == 0 meta mark set meta mark | %s comment \"%s\"",
			t, SuperSweepNftOutputChain, c.TrafficUID, ports, ws.SetName, FormatMark(ws.Marks.Wssize), FormatMark(ws.Marks.Wssize), SuperSweepComment)
	}
	w("insert rule inet %s %s %s return%s", t, post, out, cm)
	w("insert rule inet %s %s %s queue num %d bypass%s", t, post, out, c.QNum, cm)
	w("insert rule inet %s %s %s ct mark set ct mark | %s%s", t, post, out, ss, cm)
	if post == "postnat_hook" {
		w("insert rule inet %s %s %s meta mark set meta mark | %s%s", t, post, out, FormatMark(c.Marks.DesyncPostnat), cm)
	}
	w("insert rule inet %s %s %s return%s", t, pre, reply, cm)
	w("insert rule inet %s %s %s queue num %d bypass%s", t, pre, reply, c.QNum, cm)
	w("insert rule inet %s %s %s meta mark set meta mark | %s%s", t, pre, reply, ss, cm)
	w("add rule inet %s %s meta nfproto ipv4 meta skuid 0 meta mark & %s == 0 tcp sport %s tcp dport 443 meta mark set meta mark | %s%s",
		t, SuperSweepNftOutputChain, d, ports, ss, cm)
	w("add rule inet %s %s meta nfproto ipv4 meta skuid %d tcp sport %s tcp dport 443 meta mark set meta mark | %s | %s%s",
		t, SuperSweepNftOutputChain, c.ProbeUID, ports, d, ss, cm)
	// После close() TLS close_notify/FIN/RST идут без socket UID: исключаем все
	// прочие сокеты (включая основной nfqws2), затем маркируем socketless-пакеты.
	w("add rule inet %s %s meta nfproto ipv4 meta skuid >= 0 tcp sport %s tcp dport 443 return%s",
		t, SuperSweepNftOutputChain, ports, cm)
	w("add rule inet %s %s meta nfproto ipv4 tcp sport %s tcp dport 443 meta mark set meta mark | %s%s",
		t, SuperSweepNftOutputChain, ports, ss, cm)
	return b.String()
}

// ---------------------------------------------------------------- SuperSweep

// SuperSweep управляет жизненным циклом транспортных цепочек изоляции проб:
// Start создаёт цепочки и хуки, Stop их снимает. Вызывающий отвечает за
// блокировку запуска и жизненный цикл nfqws2 на очереди SuperSweepQueue
// (nfqws2 запускается до Start, останавливается после Stop).
// Не потокобезопасен.
type SuperSweep struct {
	cfg SuperSweepConfig
	r   Runner

	active    bool
	nftActive bool
	nftChain  bool
	chains    []string // созданные цепочки (последняя создана — первая в списке)
	hooks     []string // установленные хуки (последний установленный — первый)
	wait      []string
	waitDone  bool
}

// NewSuperSweep создаёт управляющий объект; конфигурация проверяется сразу.
func NewSuperSweep(cfg SuperSweepConfig, r Runner) (*SuperSweep, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &SuperSweep{cfg: cfg, r: r}
	if cfg.IptWait != nil {
		s.wait, s.waitDone = cfg.IptWait, true
	}
	return s, nil
}

// Config возвращает действующую конфигурацию.
func (s *SuperSweep) Config() SuperSweepConfig { return s.cfg }

// Active сообщает, что транспорт запущен.
func (s *SuperSweep) Active() bool { return s.active }

func (s *SuperSweep) ipt(args ...string) Command {
	a := append(append([]string(nil), s.wait...), "-t", "mangle")
	return Command{Name: "iptables", Args: append(a, args...)}
}

func (s *SuperSweep) iptRun(ctx context.Context, args ...string) ([]byte, error) {
	return s.r.Run(ctx, s.ipt(args...))
}

// Start проверяет диапазон портов и метки и устанавливает транспорт.
// Повторный вызов на активном транспорте — no-op. Для nftables резервного
// пути через рабочий NFQUEUE нет: при ошибке установка прерывается.
func (s *SuperSweep) Start(ctx context.Context) error {
	if s.active {
		return nil
	}
	if len(s.chains) > 0 || len(s.hooks) > 0 {
		return ErrUnfinishedCleanup
	}
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	data, err := s.readPortRange()
	if err != nil {
		return err
	}
	first, last, err := ParsePortRange(data)
	if err != nil {
		return err
	}
	if err := s.cfg.CheckEphemeralRange(first, last); err != nil {
		return err
	}
	if s.cfg.Backend == BackendNftables {
		if err := s.nftInstall(ctx); err != nil {
			return fmt.Errorf("native nft hook installation failed; no fallback to production NFQUEUE: %w", err)
		}
		s.active = true
		return nil
	}
	if !s.waitDone {
		s.detectWait(ctx)
	}
	if err := s.iptInstall(ctx); err != nil {
		// Откат через Background + retry: canceled sweep-ctx иначе оставляет
		// частично установленные хуки. ForceCleanup не используем — он сидит
		// полный список и трогает чужие/несозданные цепочки.
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = stopWithRetry(cleanCtx, s)
		cancel()
		return fmt.Errorf("iptables installation failed; partial transport removed: %w", err)
	}
	s.active = true
	return nil
}

func (s *SuperSweep) readPortRange() (string, error) {
	read := s.cfg.ReadFile
	if read == nil {
		read = osReadFile
	}
	b, err := read(s.cfg.PortRangeFile)
	if err != nil {
		return "", fmt.Errorf("%w: cannot read kernel ephemeral port range: %v", ErrSuperSweepInvalid, err)
	}
	return string(b), nil
}

func (s *SuperSweep) detectWait(ctx context.Context) {
	s.waitDone = true
	for _, w := range [][]string{{"-w", "5"}, {"-w"}} {
		args := append(append([]string(nil), w...), "-t", "mangle", "-L", "OUTPUT", "-n")
		if _, err := s.r.Run(ctx, Command{Name: "iptables", Args: args}); err == nil {
			s.wait = w
			return
		}
	}
	s.wait = nil
}

func (s *SuperSweep) iptInstall(ctx context.Context) error {
	for _, ch := range superSweepChains {
		if _, err := s.iptRun(ctx, "-N", ch); err != nil {
			return err
		}
		s.chains = append([]string{ch}, s.chains...)
	}
	for _, rule := range s.cfg.IptablesChainRules() {
		if _, err := s.iptRun(ctx, rule...); err != nil {
			return err
		}
	}
	// Классификация активируется последней: частично установленные правила
	// не могут пометить трафик.
	for _, hook := range superSweepInstallHooks {
		args, err := s.cfg.IptablesHookArgs("-I", hook)
		if err != nil {
			return err
		}
		if _, err := s.iptRun(ctx, args...); err != nil {
			return err
		}
		s.hooks = append([]string{hook}, s.hooks...)
	}
	return nil
}

// --- nftables

type nftOwnedRule struct {
	Chain  string
	Handle int
}

func parseNftOwned(listing, comment string) []nftOwnedRule {
	var (
		rules []nftOwnedRule
		chain string
	)
	for _, line := range strings.Split(listing, "\n") {
		if m := nftChainLineRe.FindStringSubmatch(line); m != nil {
			chain = m[1]
			continue
		}
		if m := nftHandleRe.FindStringSubmatch(line); m != nil && m[1] == comment {
			if h, err := strconv.Atoi(m[2]); err == nil {
				rules = append(rules, nftOwnedRule{Chain: chain, Handle: h})
			}
		}
	}
	return rules
}

func (s *SuperSweep) nftOwned(ctx context.Context) ([]nftOwnedRule, error) {
	out, err := run(ctx, s.r, "nft", "-a", "list", "table", "inet", s.cfg.NftTable)
	if err != nil {
		return nil, err
	}
	return parseNftOwned(string(out), SuperSweepComment), nil
}

func (s *SuperSweep) nftInstall(ctx context.Context) error {
	post, pre := s.cfg.NftChains()
	t := s.cfg.NftTable
	for _, ch := range []string{"predefrag", post, pre} {
		if _, err := run(ctx, s.r, "nft", "list", "chain", "inet", t, ch); err != nil {
			return err
		}
	}
	owned, err := s.nftOwned(ctx)
	if err != nil {
		return err
	}
	if len(owned) > 0 {
		return ErrStaleNftRules
	}
	if _, err := run(ctx, s.r, "nft", "list", "chain", "inet", t, SuperSweepNftOutputChain); err == nil {
		return ErrStaleNftRules
	}
	if _, err := runStdin(ctx, s.r, s.cfg.NftTransaction(), "nft", "-f", "-"); err != nil {
		return err
	}
	s.nftChain, s.nftActive = true, true
	return nil
}

// Check проверяет, что транспорт цел: nft — число собственных правил; iptables —
// хуки, правила цепочек и порядок (пробные хуки должны стоять перед рабочим
// NFQUEUE, который restart-fw может вставить выше).
func (s *SuperSweep) Check(ctx context.Context) error {
	if !s.active {
		return ErrTransportInactive
	}
	if s.nftActive {
		owned, err := s.nftOwned(ctx)
		if err != nil {
			return err
		}
		if len(owned) != s.cfg.NftRuleCount() {
			return fmt.Errorf("%w: %d nft rules, want %d", ErrTransportInactive, len(owned), s.cfg.NftRuleCount())
		}
		return nil
	}
	for _, hook := range s.hooks {
		args, err := s.cfg.IptablesHookArgs("-C", hook)
		if err != nil {
			return err
		}
		if _, err := s.iptRun(ctx, args...); err != nil {
			return fmt.Errorf("%w: hook %s: %v", ErrTransportInactive, hook, err)
		}
	}
	q := strconv.Itoa(s.cfg.QNum)
	for _, ch := range []string{SSChainPost, SSChainIn} {
		if _, err := s.iptRun(ctx, "-C", ch, "-j", "NFQUEUE", "--queue-num", q, "--queue-bypass"); err != nil {
			return fmt.Errorf("%w: chain %s: %v", ErrTransportInactive, ch, err)
		}
		if _, err := s.iptRun(ctx, "-C", ch, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("%w: chain %s: %v", ErrTransportInactive, ch, err)
		}
	}
	raw := FormatMark(s.cfg.Marks.Desync | s.cfg.Marks.SuperSweep)
	if _, err := s.iptRun(ctx, "-C", SSChainRaw, "-j", "MARK", "--or-mark", raw); err != nil {
		return fmt.Errorf("%w: chain %s: %v", ErrTransportInactive, SSChainRaw, err)
	}
	if _, err := s.iptRun(ctx, "-C", SSChainRaw, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("%w: chain %s: %v", ErrTransportInactive, SSChainRaw, err)
	}
	return s.orderCheck(ctx)
}

// orderCheck проверяет, что в POSTROUTING и INPUT переход в нашу цепочку стоит
// раньше любого NFQUEUE (iptables -S).
func (s *SuperSweep) orderCheck(ctx context.Context) error {
	out, err := s.iptRun(ctx, "-S")
	if err != nil {
		return err
	}
	return CheckProbeOrder(string(out))
}

// CheckProbeOrder анализирует вывод `iptables -t mangle -S`: переходы в
// Z2R_SS_POST (POSTROUTING) и Z2R_SS_IN (INPUT) должны существовать и стоять
// перед любым правилом NFQUEUE в соответствующей цепочке.
func CheckProbeOrder(listing string) error {
	probe := map[string]bool{}
	blocked := false
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "-A" || (f[1] != "POSTROUTING" && f[1] != "INPUT") {
			continue
		}
		for i := 2; i < len(f)-1; i++ {
			if f[i] != "-j" {
				continue
			}
			target := f[i+1]
			if (f[1] == "POSTROUTING" && target == SSChainPost) || (f[1] == "INPUT" && target == SSChainIn) {
				probe[f[1]] = true
			}
			if target == "NFQUEUE" && !probe[f[1]] {
				blocked = true
			}
			break
		}
	}
	if blocked || !probe["POSTROUTING"] || !probe["INPUT"] {
		return fmt.Errorf("%w: probe hooks missing or placed after production NFQUEUE", ErrTransportInactive)
	}
	return nil
}

// Stop снимает транспорт: сначала хуки (классификация), затем цепочки.
// Исчезнувшее правило — не ошибка (Keenetic ndm периодически перепроверяет
// firewall). При неполной очистке возвращает ErrCleanupIncomplete: повторите
// Stop до успеха; состояние (оставшиеся хуки/цепочки) сохраняется.
func (s *SuperSweep) Stop(ctx context.Context) error {
	if s.nftActive {
		rules, err := s.nftOwned(ctx)
		if err != nil {
			return err
		}
		var b strings.Builder
		for _, r := range rules {
			fmt.Fprintf(&b, "delete rule inet %s %s handle %d\n", s.cfg.NftTable, r.Chain, r.Handle)
		}
		if s.nftChain {
			if _, err := run(ctx, s.r, "nft", "list", "chain", "inet", s.cfg.NftTable, SuperSweepNftOutputChain); err == nil {
				fmt.Fprintf(&b, "delete chain inet %s %s\n", s.cfg.NftTable, SuperSweepNftOutputChain)
			}
		}
		if b.Len() > 0 {
			if _, err := runStdin(ctx, s.r, b.String(), "nft", "-f", "-"); err != nil {
				return err
			}
		}
		s.nftChain, s.nftActive = false, false
	}
	s.active = false

	var (
		remainingHooks []string
		hooksLive      bool
	)
	for _, hook := range s.hooks {
		args, err := s.cfg.IptablesHookArgs("-D", hook)
		if err != nil {
			return err
		}
		if _, err := s.iptRun(ctx, args...); err == nil {
			continue
		}
		live := hook
		if hook == "RAWOUTPUT" || hook == "SOCKETOUTPUT" {
			live = "OUTPUT"
		}
		listing, err := s.iptRun(ctx, "-nL", live)
		if err != nil {
			return err
		}
		if strings.Contains(string(listing), "Z2R_SS_") {
			hooksLive = true
			remainingHooks = append(remainingHooks, hook)
		}
	}
	s.hooks = remainingHooks

	incomplete := false
	if !hooksLive {
		var remainingChains []string
		for _, ch := range s.chains {
			if _, err := s.iptRun(ctx, "-F", ch); err == nil {
				if _, err := s.iptRun(ctx, "-X", ch); err == nil {
					continue
				}
			}
			listing, err := s.iptRun(ctx, "-nL")
			if err != nil {
				return err
			}
			if hasChainHeader(string(listing), ch) {
				remainingChains = append(remainingChains, ch)
				incomplete = true
			}
		}
		s.chains = remainingChains
	}
	if hooksLive || incomplete {
		return ErrCleanupIncomplete
	}
	return nil
}

func hasChainHeader(listing, chain string) bool {
	for _, line := range strings.Split(listing, "\n") {
		if strings.HasPrefix(line, "Chain "+chain+" ") || line == "Chain "+chain {
			return true
		}
	}
	return false
}

// Reinstall пересоздаёт транспорт iptables (Stop + Start) — для хуков
// перепроверки firewall, где состояния родителя нет: список собственных
// правил восстанавливается из конфигурации.
func (s *SuperSweep) Reinstall(ctx context.Context) error {
	if s.cfg.Backend != BackendIptables {
		return fmt.Errorf("%w: reinstall is iptables-only", ErrSuperSweepInvalid)
	}
	if err := s.ForceCleanup(ctx); err != nil {
		return err
	}
	return s.Start(ctx)
}

// ForceCleanup снимает Z2R_SS_* даже без живого in-memory state (после
// потери *SuperSweep / неполного Stop). Для iptables сидирует полный
// список хуков/цепочек и повторяет Stop с паузой RetryDelay; для nftables
// принудительно включает поиск собственных правил и цепочки.
func (s *SuperSweep) ForceCleanup(ctx context.Context) error {
	if s.cfg.Backend == BackendNftables {
		s.cfg = s.cfg.withDefaults()
		s.nftActive = true
		s.nftChain = true
		s.active = false
		err := stopWithRetry(ctx, s)
		if isNftNotFound(err) {
			s.nftChain, s.nftActive = false, false
			return nil
		}
		return err
	}
	s.cfg = s.cfg.withDefaults()
	if !s.waitDone {
		s.detectWait(ctx)
	}
	// Сиды: последний установленный хук снимаем первым.
	s.hooks = reverse(superSweepInstallHooks)
	s.chains = reverse(superSweepChains)
	s.active = false
	return stopWithRetry(ctx, s)
}

func isNftNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "does not exist")
}

func stopWithRetry(ctx context.Context, s *SuperSweep) error {
	delay := s.cfg.RetryDelay
	if delay <= 0 {
		delay = 3 * time.Second
	}
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		last = s.Stop(ctx)
		if last == nil {
			return nil
		}
		if !errors.Is(last, ErrCleanupIncomplete) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return last
}

// Reconcile для iptables проверяет наличие и порядок хуков и при отклонении
// переустанавливает транспорт (до 5 попыток с паузой RetryDelay).
// Для nftables — no-op.
func (s *SuperSweep) Reconcile(ctx context.Context) error {
	if s.cfg.Backend != BackendIptables {
		return nil
	}
	args, err := s.cfg.IptablesHookArgs("-C", "SOCKETOUTPUT")
	if err != nil {
		return err
	}
	if _, cerr := s.iptRun(ctx, args...); cerr == nil && s.orderCheck(ctx) == nil {
		return nil
	}
	var last error
	for attempt := 1; attempt <= 5; attempt++ {
		if last = s.Reinstall(ctx); last == nil {
			return nil
		}
		if attempt == 5 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.RetryDelay):
		}
	}
	return last
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
