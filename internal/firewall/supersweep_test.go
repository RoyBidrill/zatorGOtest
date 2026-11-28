package firewall

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ssConfig(b Backend) SuperSweepConfig {
	c := DefaultSuperSweepConfig()
	c.Backend = b
	c.RetryDelay = time.Millisecond
	c.ReadFile = func(string) ([]byte, error) { return []byte("32768\t60999\n"), nil }
	return c
}

const goodOrderListing = `-P PREROUTING ACCEPT
-A PREROUTING -p tcp -m tcp --sport 443 --dport 62000:62999 -j Z2R_SS_PRE
-A POSTROUTING -p tcp -m tcp --sport 62000:62999 --dport 443 -j Z2R_SS_POST
-A POSTROUTING -p tcp -j NFQUEUE --queue-num 200 --queue-bypass
-A INPUT -p tcp -j Z2R_SS_IN
-A INPUT -p tcp -j NFQUEUE --queue-num 200 --queue-bypass
`

func newSS(t *testing.T, cfg SuperSweepConfig, r Runner) *SuperSweep {
	t.Helper()
	s, err := NewSuperSweep(cfg, r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSuperSweepConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*SuperSweepConfig)
		wantErr error
	}{
		{"ok", func(*SuperSweepConfig) {}, nil},
		{"no backend", func(c *SuperSweepConfig) { c.Backend = BackendNone }, ErrSuperSweepInvalid},
		{"bad table", func(c *SuperSweepConfig) { c.NftTable = "a;b" }, ErrSuperSweepInvalid},
		{"bad ports", func(c *SuperSweepConfig) { c.PortFirst, c.PortLast = 100, 50 }, ErrSuperSweepInvalid},
		{"bad queue", func(c *SuperSweepConfig) { c.QNum = 70000 }, ErrSuperSweepInvalid},
		{"desync collides with supersweep mark", func(c *SuperSweepConfig) { c.Marks.Desync = 0x08000000 }, ErrMarkCollision},
		{"postnat collides", func(c *SuperSweepConfig) { c.Marks.DesyncPostnat = 0x0c000000 }, ErrMarkCollision},
		{"filter collides", func(c *SuperSweepConfig) { c.Marks.Filter = 0x08000000 }, ErrMarkCollision},
		{"client scope collides", func(c *SuperSweepConfig) { c.Marks.ClientScopeMask = 0x0f000000 }, ErrMarkCollision},
		{"zero desync", func(c *SuperSweepConfig) { c.Marks.Desync = 0 }, ErrZeroMark},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ssConfig(BackendIptables)
			tt.mutate(&c)
			if err := c.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			_, err := NewSuperSweep(c, NewRecordingRunner())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewSuperSweep err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSuperSweepConfigFromGetter(t *testing.T) {
	c, err := SuperSweepConfigFromGetter(mapGetter(map[string]string{
		"FWTYPE": "nftables", "POSTNAT": "0", "ZAPRET_NFT_TABLE": "zapret",
		"DESYNC_MARK": "0x40000000", "FILTER_MARK": "0x10000000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend != BackendNftables || c.Postnat || c.NftTable != "zapret" || c.Marks.Filter != 0x10000000 {
		t.Errorf("config = %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
}

func TestParsePortRange(t *testing.T) {
	if f, l, err := ParsePortRange("32768\t60999\n"); err != nil || f != 32768 || l != 60999 {
		t.Errorf("got %d %d %v", f, l, err)
	}
	for _, bad := range []string{"", "1", "1 2 3", "a b", "123456 1"} {
		if _, _, err := ParsePortRange(bad); err == nil {
			t.Errorf("ParsePortRange(%q) must fail", bad)
		}
	}
}

func TestSuperSweepEphemeralRange(t *testing.T) {
	c := ssConfig(BackendIptables)
	for _, tt := range []struct {
		first, last int
		ok          bool
	}{
		{32768, 60999, true},
		{1024, 62000, false},
		{62500, 65000, false},
		{63000, 65535, true},
		{1, 61999, true},
		{0, 100, false},
		{200, 100, false},
	} {
		err := c.CheckEphemeralRange(tt.first, tt.last)
		if (err == nil) != tt.ok {
			t.Errorf("%d-%d: err = %v, ok = %v", tt.first, tt.last, err, tt.ok)
		}
	}
	if err := c.CheckEphemeralRange(50000, 65000); !errors.Is(err, ErrEphemeralOverlap) {
		t.Errorf("err = %v", err)
	}
}

func TestSuperSweepIptablesInstallCommands(t *testing.T) {
	c := ssConfig(BackendIptables)
	c.Marks.Desync = 0x40000000
	cmds, err := c.IptablesInstallCommands("-w", "5")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 5+11+6 {
		t.Fatalf("len = %d", len(cmds))
	}
	var lines []string
	for _, cmd := range cmds {
		lines = append(lines, cmd.String())
	}
	for _, want := range []string{
		"iptables -w 5 -t mangle -N Z2R_SS_OUT",
		"iptables -w 5 -t mangle -A Z2R_SS_OUT -p tcp --sport 62000:62999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j MARK --set-xmark 0x08000000/0x08000000",
		"iptables -w 5 -t mangle -A Z2R_SS_OUT -j CONNMARK --or-mark 0x08000000",
		"iptables -w 5 -t mangle -A Z2R_SS_RAW -j MARK --or-mark 0x48000000",
		"iptables -w 5 -t mangle -A Z2R_SS_PRE -j CONNMARK --restore-mark --nfmask 0x08000000 --ctmask 0x08000000",
		"iptables -w 5 -t mangle -A Z2R_SS_POST -j NFQUEUE --queue-num 65535 --queue-bypass",
		"iptables -w 5 -t mangle -A Z2R_SS_IN -j NFQUEUE --queue-num 65535 --queue-bypass",
		"iptables -w 5 -t mangle -I POSTROUTING -p tcp --sport 62000:62999 --dport 443 -m mark ! --mark 0x40000000/0x40000000 -m mark --mark 0x08000000/0x08000000 -m conntrack --ctdir ORIGINAL -j Z2R_SS_POST",
		"iptables -w 5 -t mangle -I PREROUTING -p tcp --sport 443 --dport 62000:62999 -m mark ! --mark 0x40000000/0x40000000 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x08000000/0x08000000 -j Z2R_SS_PRE",
		"iptables -w 5 -t mangle -I INPUT -p tcp --sport 443 --dport 62000:62999 -m mark ! --mark 0x40000000/0x40000000 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x08000000/0x08000000 -j Z2R_SS_IN",
		"iptables -w 5 -t mangle -I OUTPUT -p tcp --sport 62000:62999 --dport 443 -m owner --uid-owner 0 -m mark ! --mark 0x40000000/0x40000000 -j Z2R_SS_OUT",
		"iptables -w 5 -t mangle -I OUTPUT -p tcp --sport 62000:62999 --dport 443 -m owner --uid-owner 65533 -j Z2R_SS_RAW",
		"iptables -w 5 -t mangle -I OUTPUT -p tcp --sport 62000:62999 --dport 443 -m owner ! --socket-exists -m mark ! --mark 0x40000000/0x40000000 -j Z2R_SS_OUT",
	} {
		if !contains(lines, want) {
			t.Errorf("missing command:\n  %s", want)
		}
	}
	// Хуки активируются последними.
	for i, l := range lines {
		if strings.Contains(l, " -I ") && i < 5+11 {
			t.Errorf("hook activated before the chains are filled: %s", l)
		}
	}
	if _, err := c.IptablesHookArgs("-I", "BOGUS"); !errors.Is(err, ErrSuperSweepInvalid) {
		t.Errorf("unknown hook: %v", err)
	}
	if got := CommandsScript(cmds); !strings.Contains(got, "iptables -w 5 -t mangle -N Z2R_SS_OUT\n") {
		t.Error("CommandsScript lost commands")
	}
}

func TestSuperSweepIptablesStartStop(t *testing.T) {
	r := NewRecordingRunner("iptables")
	s := newSS(t, ssConfig(BackendIptables), r)
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Fatal("must be active")
	}
	lines := r.Lines()
	if lines[0] != "iptables -w 5 -t mangle -L OUTPUT -n" {
		t.Errorf("wait detection = %q", lines[0])
	}
	cmds, _ := s.cfg.IptablesInstallCommands("-w", "5")
	var want []string
	for _, c := range cmds {
		want = append(want, c.String())
	}
	if got := lines[1:]; !reflect.DeepEqual(got, want) {
		t.Errorf("install commands differ:\n got: %v\nwant: %v", got, want)
	}

	// Повторный Start — no-op.
	n := len(r.Calls())
	if err := s.Start(ctx); err != nil || len(r.Calls()) != n {
		t.Errorf("second Start must be a no-op: %v", err)
	}

	r.Reset()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Active() {
		t.Error("must be inactive after Stop")
	}
	stop := r.Lines()
	// Сначала хуки в обратном порядке установки, затем цепочки в обратном порядке создания.
	order := []string{"SOCKETOUTPUT", "RAWOUTPUT", "OUTPUT", "INPUT", "PREROUTING", "POSTROUTING"}
	for i, hook := range order {
		args, _ := s.cfg.IptablesHookArgs("-D", hook)
		if w := (Command{Name: "iptables", Args: append([]string{"-w", "5", "-t", "mangle"}, args...)}).String(); stop[i] != w {
			t.Errorf("stop[%d] = %q, want %q", i, stop[i], w)
		}
	}
	var chainOps []string
	for _, l := range stop[6:] {
		chainOps = append(chainOps, strings.TrimPrefix(l, "iptables -w 5 -t mangle "))
	}
	wantChains := []string{"-F Z2R_SS_RAW", "-X Z2R_SS_RAW", "-F Z2R_SS_IN", "-X Z2R_SS_IN", "-F Z2R_SS_PRE", "-X Z2R_SS_PRE",
		"-F Z2R_SS_POST", "-X Z2R_SS_POST", "-F Z2R_SS_OUT", "-X Z2R_SS_OUT"}
	if !reflect.DeepEqual(chainOps, wantChains) {
		t.Errorf("chain cleanup = %v", chainOps)
	}

	// Stop идемпотентен.
	r.Reset()
	if err := s.Stop(ctx); err != nil || len(r.Calls()) != 0 {
		t.Errorf("second Stop: %v %v", err, r.Lines())
	}
	// После Stop можно запустить снова.
	if err := s.Start(ctx); err != nil {
		t.Errorf("restart: %v", err)
	}
}

func TestSuperSweepWaitDetectionFallback(t *testing.T) {
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if strings.Contains(strings.Join(c.Args, " "), "-L OUTPUT -n") && contains(c.Args, "5") {
			return nil, ErrExit1() // нет «-w 5»
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.wait, []string{"-w"}) {
		t.Errorf("wait = %v", s.wait)
	}

	r = NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-L") {
			return nil, ErrExit1()
		}
		return nil, nil
	}
	s = newSS(t, ssConfig(BackendIptables), r)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.wait != nil {
		t.Errorf("wait = %v", s.wait)
	}
	for _, l := range r.Lines() {
		if !strings.Contains(l, " -L ") && strings.HasPrefix(l, "iptables -w") {
			t.Errorf("no -w expected after failed detection: %s", l)
		}
	}
}

func TestSuperSweepExplicitWaitSkipsDetection(t *testing.T) {
	c := ssConfig(BackendIptables)
	c.IptWait = []string{}
	r := NewRecordingRunner("iptables")
	s := newSS(t, c, r)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Lines()[0], "-L OUTPUT") {
		t.Errorf("detection must be skipped: %s", r.Lines()[0])
	}
	if !strings.HasPrefix(r.Lines()[0], "iptables -t mangle -N ") {
		t.Errorf("first = %s", r.Lines()[0])
	}
}

func TestSuperSweepPartialInstallRollsBack(t *testing.T) {
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if strings.HasSuffix(strings.Join(c.Args, " "), "-N Z2R_SS_PRE") {
			return []byte("Chain already exists"), ErrExit1()
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	if s.Active() {
		t.Error("must not be active")
	}
	joined := strings.Join(r.Lines(), "\n")
	for _, want := range []string{"-X Z2R_SS_POST", "-X Z2R_SS_OUT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rollback missing %s", want)
		}
	}
	// Чужую (не созданную нами) цепочку не трогаем.
	if strings.Contains(joined, "-X Z2R_SS_PRE") {
		t.Error("foreign chain Z2R_SS_PRE must not be removed")
	}
	if len(s.chains) != 0 || len(s.hooks) != 0 {
		t.Errorf("state not cleaned: %v %v", s.chains, s.hooks)
	}
}

func TestSuperSweepHookFailureRollsBackHooks(t *testing.T) {
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		if strings.Contains(a, "-I INPUT") {
			return nil, ErrExit1()
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	joined := strings.Join(r.Lines(), "\n")
	if !strings.Contains(joined, "-D POSTROUTING") || !strings.Contains(joined, "-D PREROUTING") {
		t.Errorf("installed hooks must be removed:\n%s", joined)
	}
	if strings.Contains(joined, "-D INPUT") {
		t.Errorf("hook that failed to install must not be deleted:\n%s", joined)
	}
}

func TestSuperSweepStopHookVanished(t *testing.T) {
	// ndm выметает чужие цепи: -D отказывает, но в листинге правила уже нет.
	r := NewRecordingRunner("iptables")
	s := newSS(t, ssConfig(BackendIptables), r)
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-D") && contains(c.Args, "OUTPUT") {
			return nil, ErrExit1()
		}
		return []byte("Chain OUTPUT (policy ACCEPT)\n"), nil
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("vanished hook is not an error: %v", err)
	}
}

func TestSuperSweepStopIncompleteThenRetry(t *testing.T) {
	r := NewRecordingRunner("iptables")
	s := newSS(t, ssConfig(BackendIptables), r)
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	transient := true
	r.Handler = func(c Command) ([]byte, error) {
		if transient && contains(c.Args, "-D") && contains(c.Args, "POSTROUTING") {
			return []byte("xtables lock"), ErrExit1()
		}
		if transient && contains(c.Args, "-nL") && contains(c.Args, "POSTROUTING") {
			return []byte("Chain POSTROUTING\nZ2R_SS_POST all\n"), nil
		}
		return nil, nil
	}
	err := s.Stop(ctx)
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("err = %v, want ErrCleanupIncomplete", err)
	}
	if !reflect.DeepEqual(s.hooks, []string{"POSTROUTING"}) {
		t.Errorf("remaining hooks = %v", s.hooks)
	}
	// Цепочки не трогаются, пока жив хук.
	for _, l := range r.Lines() {
		if strings.Contains(l, " -X ") {
			t.Errorf("chains must stay while hooks are live: %s", l)
		}
	}
	// До завершения очистки новый Start запрещён.
	if err := s.Start(ctx); !errors.Is(err, ErrUnfinishedCleanup) {
		t.Errorf("Start = %v, want ErrUnfinishedCleanup", err)
	}
	transient = false
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(s.hooks) != 0 || len(s.chains) != 0 {
		t.Errorf("state after retry: %v %v", s.hooks, s.chains)
	}
}

func TestSuperSweepStopChainBusy(t *testing.T) {
	r := NewRecordingRunner("iptables")
	s := newSS(t, ssConfig(BackendIptables), r)
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	busy := true
	r.Handler = func(c Command) ([]byte, error) {
		if busy && contains(c.Args, "-X") && contains(c.Args, "Z2R_SS_PRE") {
			return nil, ErrExit1()
		}
		if busy && contains(c.Args, "-nL") && len(c.Args) == 5 { // iptables -w 5 -t mangle -nL
			return []byte("Chain Z2R_SS_PRE (0 references)\n"), nil
		}
		return nil, nil
	}
	if err := s.Stop(ctx); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(s.chains, []string{"Z2R_SS_PRE"}) {
		t.Errorf("remaining chains = %v", s.chains)
	}
	busy = false
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSuperSweepStartGuards(t *testing.T) {
	ctx := context.Background()

	// Диапазон эфемерных портов ядра пересекается с зарезервированными.
	r := NewRecordingRunner("iptables")
	c := ssConfig(BackendIptables)
	c.ReadFile = func(string) ([]byte, error) { return []byte("1024 65000"), nil }
	if err := newSS(t, c, r).Start(ctx); !errors.Is(err, ErrEphemeralOverlap) || len(r.Calls()) != 0 {
		t.Errorf("overlap: %v %v", err, r.Lines())
	}

	// Не удалось прочитать диапазон.
	c.ReadFile = func(string) ([]byte, error) { return nil, errors.New("denied") }
	if err := newSS(t, c, r).Start(ctx); !errors.Is(err, ErrSuperSweepInvalid) {
		t.Errorf("read error: %v", err)
	}

	// Мусор в диапазоне.
	c.ReadFile = func(string) ([]byte, error) { return []byte("abc"), nil }
	if err := newSS(t, c, r).Start(ctx); !errors.Is(err, ErrSuperSweepInvalid) {
		t.Errorf("garbage: %v", err)
	}
}

func TestSuperSweepCheckIptables(t *testing.T) {
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-S") {
			return []byte(goodOrderListing), nil
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	ctx := context.Background()
	if err := s.Check(ctx); !errors.Is(err, ErrTransportInactive) {
		t.Errorf("inactive Check = %v", err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(ctx); err != nil {
		t.Fatalf("healthy Check: %v", err)
	}

	// Пропал хук.
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-C") && contains(c.Args, "POSTROUTING") {
			return nil, ErrExit1()
		}
		return []byte(goodOrderListing), nil
	}
	if err := s.Check(ctx); !errors.Is(err, ErrTransportInactive) {
		t.Errorf("missing hook Check = %v", err)
	}

	// Рабочий NFQUEUE оказался выше пробного перехода.
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-S") {
			return []byte("-A POSTROUTING -j NFQUEUE --queue-num 200\n-A POSTROUTING -j Z2R_SS_POST\n-A INPUT -j Z2R_SS_IN\n"), nil
		}
		return nil, nil
	}
	if err := s.Check(ctx); !errors.Is(err, ErrTransportInactive) {
		t.Errorf("order Check = %v", err)
	}
}

func TestCheckProbeOrder(t *testing.T) {
	if err := CheckProbeOrder(goodOrderListing); err != nil {
		t.Errorf("good listing: %v", err)
	}
	for name, listing := range map[string]string{
		"empty":               "",
		"no input hook":       "-A POSTROUTING -j Z2R_SS_POST\n",
		"nfqueue first (in)":  "-A POSTROUTING -j Z2R_SS_POST\n-A INPUT -j NFQUEUE --queue-num 1\n-A INPUT -j Z2R_SS_IN\n",
		"nfqueue first (out)": "-A POSTROUTING -j NFQUEUE --queue-num 1\n-A POSTROUTING -j Z2R_SS_POST\n-A INPUT -j Z2R_SS_IN\n",
	} {
		if err := CheckProbeOrder(listing); !errors.Is(err, ErrTransportInactive) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSuperSweepReconcile(t *testing.T) {
	ctx := context.Background()

	// Здоровый транспорт: переустановки нет.
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-S") {
			return []byte(goodOrderListing), nil
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	s.waitDone = true
	if err := s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range r.Lines() {
		if strings.Contains(l, " -N ") || strings.Contains(l, " -D ") {
			t.Errorf("healthy transport must not be reinstalled: %s", l)
		}
	}

	// Хук потерян: Stop + Start.
	r = NewRecordingRunner("iptables")
	state := "lost"
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-C") && contains(c.Args, "OUTPUT") && state == "lost" {
			return nil, ErrExit1()
		}
		if contains(c.Args, "-S") {
			return []byte(goodOrderListing), nil
		}
		if contains(c.Args, "-N") {
			state = "reinstalled"
		}
		return nil, nil
	}
	s = newSS(t, ssConfig(BackendIptables), r)
	s.waitDone = true
	if err := s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Error("transport must be reinstalled")
	}
	joined := strings.Join(r.Lines(), "\n")
	if !strings.Contains(joined, "-D POSTROUTING") || !strings.Contains(joined, "-I POSTROUTING") {
		t.Errorf("reinstall sequence missing:\n%s", joined)
	}

	// Reinstall/Reconcile для nftables не поддерживаются / no-op.
	sn := newSS(t, ssConfig(BackendNftables), NewRecordingRunner("nft"))
	if err := sn.Reconcile(ctx); err != nil {
		t.Errorf("nft Reconcile must be a no-op: %v", err)
	}
	if err := sn.Reinstall(ctx); !errors.Is(err, ErrSuperSweepInvalid) {
		t.Errorf("nft Reinstall: %v", err)
	}
}

func TestSuperSweepReconcileGivesUp(t *testing.T) {
	r := NewRecordingRunner("iptables")
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "-N") {
			return nil, ErrExit1() // установка всегда падает
		}
		if contains(c.Args, "-C") {
			return nil, ErrExit1()
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendIptables), r)
	s.waitDone = true
	if err := s.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile must report persistent failure")
	}
	n := 0
	for _, l := range r.Lines() {
		if strings.HasSuffix(l, "-N Z2R_SS_OUT") {
			n++
		}
	}
	if n != 5 {
		t.Errorf("install attempts = %d, want 5", n)
	}
}

// ---------------------------------------------------------------- nftables

const nftEmptyTable = "table inet zapret2 {\n\tchain postnat_hook {\n\t\tcounter # handle 1\n\t}\n}\n"

func nftSSHandler(table *string, outputChainExists *bool) func(Command) ([]byte, error) {
	return func(c Command) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		switch {
		case a == "-a list table inet zapret2":
			return []byte(*table), nil
		case a == "list chain inet zapret2 z2r_supersweep_output":
			if *outputChainExists {
				return nil, nil
			}
			return nil, ErrExit1()
		case strings.HasPrefix(a, "list chain inet zapret2 "):
			return nil, nil
		}
		return nil, nil
	}
}

func TestSuperSweepNftTransaction(t *testing.T) {
	c := ssConfig(BackendNftables)
	txn := c.NftTransaction()
	lines := strings.Split(strings.TrimSpace(txn), "\n")
	if len(lines) != 1+c.NftRuleCount() || c.NftRuleCount() != 11 {
		t.Fatalf("postnat: %d lines, count %d", len(lines), c.NftRuleCount())
	}
	for _, want := range []string{
		"create chain inet zapret2 z2r_supersweep_output { type route hook output priority -1; policy accept; }",
		`insert rule inet zapret2 postnat_hook meta nfproto ipv4 meta mark & 0x40000000 == 0 meta mark & 0x08000000 != 0 tcp sport 62000-62999 tcp dport 443 queue num 65535 bypass comment "z2r_supersweep"`,
		`insert rule inet zapret2 postnat_hook meta nfproto ipv4 meta mark & 0x40000000 == 0 meta mark & 0x08000000 != 0 tcp sport 62000-62999 tcp dport 443 meta mark set meta mark | 0x20000000 comment "z2r_supersweep"`,
		`insert rule inet zapret2 prenat_hook meta nfproto ipv4 ct direction reply ct state established ct mark & 0x08000000 != 0 tcp sport 443 tcp dport 62000-62999 queue num 65535 bypass comment "z2r_supersweep"`,
		`add rule inet zapret2 z2r_supersweep_output meta nfproto ipv4 meta skuid 65533 tcp sport 62000-62999 tcp dport 443 meta mark set meta mark | 0x40000000 | 0x08000000 comment "z2r_supersweep"`,
		`add rule inet zapret2 z2r_supersweep_output meta nfproto ipv4 meta skuid >= 0 tcp sport 62000-62999 tcp dport 443 return comment "z2r_supersweep"`,
	} {
		if !strings.Contains(txn, want) {
			t.Errorf("transaction missing:\n  %s\nin:\n%s", want, txn)
		}
	}
	// Для каждой из двух цепочек вставки идут в обратном порядке: mark, queue, return.
	ret := strings.Index(txn, "postnat_hook meta nfproto ipv4 meta mark & 0x40000000 == 0 meta mark & 0x08000000 != 0 tcp sport 62000-62999 tcp dport 443 return")
	queue := strings.Index(txn, "tcp dport 443 queue num")
	if ret < 0 || queue < 0 || ret > queue {
		t.Error("insert order must be return, queue, marks (so the final order is marks, queue, return)")
	}

	c.Postnat = false
	txn = c.NftTransaction()
	if c.NftRuleCount() != 10 || len(strings.Split(strings.TrimSpace(txn), "\n")) != 11 {
		t.Errorf("non-NAT: count %d", c.NftRuleCount())
	}
	if strings.Contains(txn, "postnat_hook") || !strings.Contains(txn, "postrouting_hook") || !strings.Contains(txn, "prerouting_hook") {
		t.Errorf("non-NAT chains expected:\n%s", txn)
	}
	if strings.Contains(txn, "0x20000000") {
		t.Error("POSTNAT mark must not be set for plain postrouting")
	}
}

func TestSuperSweepWssizeMarksProbeBeforeQueue(t *testing.T) {
	c := ssConfig(BackendNftables)
	c.ProbeUID = 65534
	c.TrafficUID = 0
	w := testWssizeConfig(BackendNftables)
	w.NFQWS2Enable = true
	w.Marks = c.Marks
	c.Wssize = &w
	txn := c.NftTransaction()
	mark := strings.Index(txn, `meta skuid 0 tcp sport 62000-62999 tcp dport 443 ip daddr @z2r_googlevideo4`)
	queue := strings.Index(txn, `queue num 65535 bypass comment "z2r_supersweep"`)
	if mark < 0 || queue < 0 || mark > queue {
		t.Fatalf("WSSIZE probe mark must be installed in output path before it reaches isolated NFQUEUE:\n%s", txn)
	}
	if c.NftRuleCount() != 12 || len(strings.Split(strings.TrimSpace(txn), "\n")) != 13 {
		t.Fatalf("unexpected rule count with WSSIZE: rules=%d lines=%d", c.NftRuleCount(), len(strings.Split(strings.TrimSpace(txn), "\n")))
	}
}

func TestSuperSweepIptablesWssizeMarksProbeFirst(t *testing.T) {
	c := ssConfig(BackendIptables)
	c.ProbeUID = 65534
	c.TrafficUID = 0
	w := testWssizeConfig(BackendIptables)
	w.NFQWS2Enable = true
	w.Marks = c.Marks
	c.Wssize = &w
	var rules [][]string
	var outRules [][]string
	for _, r := range c.IptablesChainRules() {
		if len(r) > 1 && r[1] == SSChainRaw {
			rules = append(rules, r)
		}
		if len(r) > 1 && r[1] == SSChainOut {
			outRules = append(outRules, r)
		}
	}
	if len(rules) != 3 || !strings.Contains(strings.Join(rules[0], " "), "z2r_googlevideo4") || !strings.Contains(strings.Join(rules[1], " "), "--or-mark") {
		t.Fatalf("expected WSSIZE mark before isolated DESYNC/SuperSweep mark: %#v", rules)
	}
	if len(outRules) == 0 || !strings.Contains(strings.Join(outRules[0], " "), "--uid-owner 0 -m set --match-set z2r_googlevideo4 dst") ||
		!strings.Contains(strings.Join(outRules[0], " "), "--set-xmark 0x04000000/0x04000000") {
		t.Fatalf("Go checker traffic must receive the WSSIZE mark in the root OUTPUT path: %#v", outRules)
	}
}

func TestSuperSweepNftStartStop(t *testing.T) {
	table := nftEmptyTable
	exists := false
	r := NewRecordingRunner("nft")
	r.Handler = nftSSHandler(&table, &exists)
	s := newSS(t, ssConfig(BackendNftables), r)
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Active() {
		t.Fatal("must be active")
	}
	last := r.Calls()[len(r.Calls())-1]
	if last.Name != "nft" || !reflect.DeepEqual(last.Args, []string{"-f", "-"}) || last.Stdin != s.cfg.NftTransaction() {
		t.Errorf("transaction call = %v", last)
	}
	// Для nftables iptables не вызывается.
	for _, l := range r.Lines() {
		if strings.HasPrefix(l, "iptables") {
			t.Errorf("unexpected iptables call: %s", l)
		}
	}

	// Листинг после установки: 11 правил + выходная цепочка.
	var b strings.Builder
	b.WriteString("table inet zapret2 {\n")
	b.WriteString("\tchain postnat_hook {\n")
	for i := 1; i <= 4; i++ {
		b.WriteString("\t\tx comment \"z2r_supersweep\" # handle " + string(rune('0'+i)) + "\n")
	}
	b.WriteString("\t\tcounter comment \"foreign\" # handle 9\n\t}\n\tchain prenat_hook {\n")
	for i := 5; i <= 7; i++ {
		b.WriteString("\t\tx comment \"z2r_supersweep\" # handle " + string(rune('0'+i)) + "\n")
	}
	b.WriteString("\t}\n\tchain z2r_supersweep_output {\n\t\ttype route hook output priority -1; policy accept;\n")
	b.WriteString("\t\tx comment \"z2r_supersweep\" # handle 21\n\t\ty comment \"z2r_supersweep\" # handle 22\n")
	b.WriteString("\t\tz comment \"z2r_supersweep\" # handle 23\n\t\tw comment \"z2r_supersweep\" # handle 24\n\t}\n}\n")
	table, exists = b.String(), true

	if err := s.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	r.Reset()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	calls := r.Calls()
	txn := calls[len(calls)-1].Stdin
	for _, want := range []string{
		"delete rule inet zapret2 postnat_hook handle 1\n",
		"delete rule inet zapret2 postnat_hook handle 4\n",
		"delete rule inet zapret2 prenat_hook handle 7\n",
		"delete rule inet zapret2 z2r_supersweep_output handle 24\n",
		"delete chain inet zapret2 z2r_supersweep_output\n",
	} {
		if !strings.Contains(txn, want) {
			t.Errorf("stop transaction missing %q:\n%s", want, txn)
		}
	}
	if strings.Contains(txn, "handle 9") {
		t.Errorf("foreign rule must not be deleted:\n%s", txn)
	}
	// Правила удаляются до цепочки.
	if strings.Index(txn, "delete chain") < strings.LastIndex(txn, "delete rule") {
		t.Errorf("chain deletion must come last:\n%s", txn)
	}
	if s.Active() {
		t.Error("must be inactive")
	}
	if err := s.Check(ctx); !errors.Is(err, ErrTransportInactive) {
		t.Errorf("Check after Stop = %v", err)
	}
}

func TestSuperSweepNftCheckDetectsMissingRules(t *testing.T) {
	table := nftEmptyTable
	exists := false
	r := NewRecordingRunner("nft")
	r.Handler = nftSSHandler(&table, &exists)
	s := newSS(t, ssConfig(BackendNftables), r)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	table = "table inet zapret2 {\n\tchain postnat_hook {\n\t\tx comment \"z2r_supersweep\" # handle 1\n\t}\n}\n"
	if err := s.Check(context.Background()); !errors.Is(err, ErrTransportInactive) {
		t.Errorf("Check = %v", err)
	}
}

func TestSuperSweepNftStaleAndMissing(t *testing.T) {
	ctx := context.Background()

	// Остаточные правила прошлого запуска.
	table := "table inet zapret2 {\n\tchain postnat_hook {\n\t\tx comment \"z2r_supersweep\" # handle 1\n\t}\n}\n"
	exists := false
	r := NewRecordingRunner("nft")
	r.Handler = nftSSHandler(&table, &exists)
	if err := newSS(t, ssConfig(BackendNftables), r).Start(ctx); !errors.Is(err, ErrStaleNftRules) {
		t.Errorf("stale rules: %v", err)
	}
	for _, c := range r.Calls() {
		if c.Stdin != "" {
			t.Errorf("no transaction expected: %q", c.Stdin)
		}
	}

	// Остаточная выходная цепочка.
	table, exists = nftEmptyTable, true
	if err := newSS(t, ssConfig(BackendNftables), r).Start(ctx); !errors.Is(err, ErrStaleNftRules) {
		t.Errorf("stale chain: %v", err)
	}

	// Нет нативных цепочек zapret2 — fallback на рабочий NFQUEUE не допускается.
	r = NewRecordingRunner("nft")
	r.Handler = func(c Command) ([]byte, error) {
		if contains(c.Args, "predefrag") {
			return nil, ErrExit1()
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendNftables), r)
	if err := s.Start(ctx); err == nil || s.Active() {
		t.Errorf("missing predefrag must fail: %v", err)
	}
	for _, l := range r.Lines() {
		if strings.HasPrefix(l, "iptables") {
			t.Errorf("fallback to iptables is forbidden: %s", l)
		}
	}
}

func TestParseNftOwned(t *testing.T) {
	listing := "table inet t {\n\tchain a {\n\t\tx comment \"z2r_supersweep\" # handle 3\n\t\ty comment \"other\" # handle 4\n\t}\n\tchain b {\n\t\tz comment \"z2r_supersweep\" # handle 10\n\t}\n}\n"
	got := parseNftOwned(listing, SuperSweepComment)
	want := []nftOwnedRule{{"a", 3}, {"b", 10}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSuperSweepNftForceCleanupOrphan(t *testing.T) {
	table := "table inet zapret2 {\n" +
		"\tchain postnat_hook {\n\t\tx comment \"z2r_supersweep\" # handle 11\n\t}\n" +
		"\tchain z2r_supersweep_output {\n\t\tx comment \"z2r_supersweep\" # handle 21\n\t}\n" +
		"}\n"
	exists := true
	r := NewRecordingRunner("nft")
	r.Handler = nftSSHandler(&table, &exists)
	s := newSS(t, ssConfig(BackendNftables), r)

	if err := s.ForceCleanup(context.Background()); err != nil {
		t.Fatalf("ForceCleanup: %v", err)
	}
	calls := r.Calls()
	if len(calls) == 0 {
		t.Fatal("expected nft cleanup calls on fresh SuperSweep")
	}
	txn := calls[len(calls)-1].Stdin
	for _, want := range []string{
		"delete rule inet zapret2 postnat_hook handle 11\n",
		"delete rule inet zapret2 z2r_supersweep_output handle 21\n",
		"delete chain inet zapret2 z2r_supersweep_output\n",
	} {
		if !strings.Contains(txn, want) {
			t.Errorf("orphan cleanup missing %q:\n%s", want, txn)
		}
	}
}

func TestSuperSweepNftForceCleanupMissingTable(t *testing.T) {
	r := NewRecordingRunner("nft")
	r.Handler = func(c Command) ([]byte, error) {
		if strings.Join(c.Args, " ") == "-a list table inet zapret2" {
			return []byte("Error: No such file or directory\nlist table inet zapret2\n"), ErrExit1()
		}
		return nil, nil
	}
	s := newSS(t, ssConfig(BackendNftables), r)
	if err := s.ForceCleanup(context.Background()); err != nil {
		t.Fatalf("ForceCleanup with missing table must succeed, got: %v", err)
	}
	if s.nftActive || s.nftChain {
		t.Errorf("expected nft flags cleared, got active=%v chain=%v", s.nftActive, s.nftChain)
	}
}
