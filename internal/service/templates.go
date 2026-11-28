package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Имена файлов и каталогов служб.
const (
	systemdDir      = "/etc/systemd/system"
	initDir         = "/etc/init.d"
	entwareInitDir  = "/opt/etc/init.d"
	merlinHookFile  = "/jffs/scripts/firewall-start"
	keeneticHookDir = "/opt/etc/ndm/netfilter.d"
	// KeeneticHookName — имя ndm-хука.
	KeeneticHookName = "000-zapret2.sh"

	defaultPath = "/opt/bin:/opt/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// TemplateData — данные для шаблонов unit/init-файлов.
type TemplateData struct {
	Name         string   // имя службы (zapret2, zator-webui)
	Description  string   // описание
	Command      []string // исполняемый файл и аргументы
	PIDFile      string   // PID-файл (SysV/Entware)
	LogFile      string   // лог stdout/stderr для SysV/Entware
	InitScript   string   // путь init-скрипта (для restart-fw)
	FWHook       string   // необязательный скрипт межсетевого экрана
	WssizeBin    string   // zator binary for WSSIZE lifecycle hooks
	ZatorRoot    string   // runtime root passed to managed processes
	ZapretRoot   string   // zapret2 root passed to managed processes
	ReleaseOwner string   // GitHub owner for update checks
	ReleaseRepo  string   // GitHub repository for update checks
	Path         string   // значение PATH
	Start        int      // порядок запуска (procd START=)
}

// ExecStart — командная строка для systemd (аргументы через пробел).
func (d TemplateData) ExecStart() string { return strings.Join(d.Command, " ") }

// ShellCommand — командная строка с экранированием для sh.
func (d TemplateData) ShellCommand() string {
	q := make([]string, len(d.Command))
	for i, a := range d.Command {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// Exe — первый элемент команды (исполняемый файл).
func (d TemplateData) Exe() string {
	if len(d.Command) == 0 {
		return ""
	}
	return d.Command[0]
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// RenderSystemd формирует содержимое systemd unit.
func RenderSystemd(d TemplateData) (string, error) {
	var b strings.Builder
	b.Grow(512)
	b.WriteString(`[Unit]
Description=`)
	b.WriteString(d.Description)
	b.WriteString(`
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PATH=`)
	b.WriteString(d.Path)
	b.WriteString(`
Environment=ZATOR_ROOT=`)
	b.WriteString(d.ZatorRoot)
	b.WriteString(`
Environment=ZAPRET2_ROOT=`)
	b.WriteString(d.ZapretRoot)
	if validReleaseRepository(d.ReleaseOwner, d.ReleaseRepo) {
		b.WriteString("\nEnvironment=ZATOR_OWNER=")
		b.WriteString(d.ReleaseOwner)
		b.WriteString("\nEnvironment=ZATOR_REPO=")
		b.WriteString(d.ReleaseRepo)
	}
	if d.FWHook != "" {
		b.WriteString(`
ExecStartPre=-`)
		b.WriteString(d.FWHook)
		b.WriteString(` start
ExecStopPost=-`)
		b.WriteString(d.FWHook)
		b.WriteString(` stop`)
	}
	if d.WssizeBin != "" {
		b.WriteString(`
ExecStartPre=-`)
		b.WriteString(d.WssizeBin)
		b.WriteString(` wssize-hook start
ExecStopPost=-`)
		b.WriteString(d.WssizeBin)
		b.WriteString(` wssize-hook stop`)
	}
	b.WriteString(`
ExecStart=`)
	b.WriteString(d.ExecStart())
	b.WriteString(`
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`)
	return b.String(), nil
}

// RenderProcd формирует init-скрипт procd (OpenWrt).
func RenderProcd(d TemplateData) (string, error) {
	var b strings.Builder
	b.Grow(1024)
	b.WriteString(`#!/bin/sh /etc/rc.common
# `)
	b.WriteString(d.Description)
	b.WriteString(` (создано zator)
START=`)
	b.WriteString(strconv.Itoa(d.Start))
	b.WriteString(`
STOP=10
USE_PROCD=1
PATH=`)
	b.WriteString(d.Path)
	b.WriteString(`
export PATH
ZATOR_ROOT=`)
	b.WriteString(shellQuote(d.ZatorRoot))
	b.WriteString(`
ZAPRET2_ROOT=`)
	b.WriteString(shellQuote(d.ZapretRoot))
	b.WriteString(`
export ZATOR_ROOT ZAPRET2_ROOT

start_service() {`)
	if d.FWHook != "" {
		q := shellQuote(d.FWHook)
		b.WriteString(`
	[ -x `)
		b.WriteString(q)
		b.WriteString(` ] && `)
		b.WriteString(q)
		b.WriteString(` start`)
	}
	if d.WssizeBin != "" {
		q := shellQuote(d.WssizeBin)
		b.WriteString(`
	`)
		b.WriteString(q)
		b.WriteString(` wssize-hook start || logger -t zator-wssize 'failed to apply WSSIZE rules'`)
	}
	b.WriteString(`
	procd_open_instance`)
	if validReleaseRepository(d.ReleaseOwner, d.ReleaseRepo) {
		b.WriteString(`
	procd_set_param env ZATOR_OWNER=`)
		b.WriteString(shellQuote(d.ReleaseOwner))
		b.WriteString(` ZATOR_REPO=`)
		b.WriteString(shellQuote(d.ReleaseRepo))
	}
	b.WriteString(`
	procd_set_param command `)
	b.WriteString(d.ShellCommand())
	b.WriteString(`
	procd_set_param respawn
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

stop_service() {`)
	if d.FWHook != "" {
		q := shellQuote(d.FWHook)
		b.WriteString(`
	[ -x `)
		b.WriteString(q)
		b.WriteString(` ] && `)
		b.WriteString(q)
		b.WriteString(` stop`)
	}
	if d.WssizeBin != "" {
		q := shellQuote(d.WssizeBin)
		b.WriteString(`
	`)
		b.WriteString(q)
		b.WriteString(` wssize-hook stop || logger -t zator-wssize 'failed to remove WSSIZE rules'`)
	}
	b.WriteString(`
	return 0
}`)
	if d.FWHook != "" {
		q := shellQuote(d.FWHook)
		b.WriteString(`

restart_fw() {
	[ -x `)
		b.WriteString(q)
		b.WriteString(` ] && `)
		b.WriteString(q)
		b.WriteString(` restart`)
		if d.WssizeBin != "" {
			b.WriteString(`
	`)
			b.WriteString(shellQuote(d.WssizeBin))
			b.WriteString(` wssize-hook restart || logger -t zator-wssize 'failed to apply WSSIZE rules'`)
		}
		b.WriteString(`
}
EXTRA_COMMANDS="restart_fw"`)
	}
	b.WriteByte('\n')
	return b.String(), nil
}

// RenderSysV формирует init-скрипт SysV/Entware.
func RenderSysV(d TemplateData) (string, error) {
	var b strings.Builder
	b.Grow(2048)
	b.WriteString("#!/bin/sh\n# ")
	b.WriteString(d.Description)
	b.WriteString(" (создано zator)\nPATH=")
	b.WriteString(d.Path)
	b.WriteString("\nexport PATH\nZATOR_ROOT=")
	b.WriteString(shellQuote(d.ZatorRoot))
	b.WriteString("\nZAPRET2_ROOT=")
	b.WriteString(shellQuote(d.ZapretRoot))
	b.WriteString("\nexport ZATOR_ROOT ZAPRET2_ROOT\nNAME=")
	b.WriteString(shellQuote(d.Name))
	if validReleaseRepository(d.ReleaseOwner, d.ReleaseRepo) {
		b.WriteString("\nZATOR_OWNER=")
		b.WriteString(shellQuote(d.ReleaseOwner))
		b.WriteString("\nZATOR_REPO=")
		b.WriteString(shellQuote(d.ReleaseRepo))
		b.WriteString("\nexport ZATOR_OWNER ZATOR_REPO")
	}
	b.WriteString("\nPIDFILE=")
	b.WriteString(shellQuote(d.PIDFile))
	b.WriteString("\nLOGFILE=")
	b.WriteString(shellQuote(d.LogFile))
	if d.FWHook != "" {
		b.WriteString("\nFWHOOK=")
		b.WriteString(shellQuote(d.FWHook))
	}
	b.WriteString(`

is_running() {
	[ -f "$PIDFILE" ] || return 1
	pid="$(cat "$PIDFILE" 2>/dev/null)"
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

fw() {`)
	if d.FWHook != "" {
		b.WriteString(`
	[ -x "$FWHOOK" ] && "$FWHOOK" "$1"`)
	}
	if d.WssizeBin != "" {
		b.WriteString(`
	`)
		b.WriteString(shellQuote(d.WssizeBin))
		b.WriteString(` wssize-hook "$1" || echo "WSSIZE firewall hook failed" >&2`)
	}
	b.WriteString(`
	return 0
}

start() {
	if is_running; then
		echo "$NAME уже запущен"
		return 0
	fi
	fw start
	mkdir -p "$(dirname "$PIDFILE")"
	if [ -n "$LOGFILE" ]; then
		mkdir -p "$(dirname "$LOGFILE")"
		# Ротация: не раздувать flash (Keenetic 128–256MB).
		LOG_MAX_BYTES="${Z2R_SERVICE_LOG_MAX:-262144}"
		if [ -f "$LOGFILE" ]; then
			sz=$(wc -c <"$LOGFILE" 2>/dev/null || echo 0)
			sz=$(echo "$sz" | tr -d ' \t')
			if [ -n "$sz" ] && [ "$sz" -gt "$LOG_MAX_BYTES" ] 2>/dev/null; then
				mv -f "$LOGFILE" "$LOGFILE.old" 2>/dev/null || true
			fi
		fi
		: >>"$LOGFILE"
	else
		LOGFILE=/dev/null
	fi
	# Keenetic/Entware: не глотать stderr — иначе webui падает молча, а install врёт «запущен».
	if command -v nohup >/dev/null 2>&1; then
		nohup `)
	b.WriteString(d.ShellCommand())
	b.WriteString(` >>"$LOGFILE" 2>&1 &
	else
		`)
	b.WriteString(d.ShellCommand())
	b.WriteString(` >>"$LOGFILE" 2>&1 &
	fi
	echo $! > "$PIDFILE"
	sleep 1
	if ! is_running; then
		echo "$NAME не запустился (лог: $LOGFILE)" >&2
		rm -f "$PIDFILE"
		return 1
	fi
	echo "$NAME запущен"
}

stop() {
	if is_running; then
		kill "$(cat "$PIDFILE")" 2>/dev/null
		sleep 1
		if is_running; then
			kill -9 "$(cat "$PIDFILE")" 2>/dev/null
		fi
	fi
	rm -f "$PIDFILE"
	fw stop
	echo "$NAME остановлен"
}

case "$1" in
	start) start ;;
	stop) stop ;;
	restart) stop; sleep 1; start ;;
	restart-fw) fw restart ;;
	status)
		if is_running; then echo "$NAME работает"; else echo "$NAME остановлен"; exit 3; fi
		;;
	*) echo "usage: $0 {start|stop|restart|restart-fw|status}"; exit 1 ;;
esac
`)
	return b.String(), nil
}

// RenderOpenRC формирует нативный скрипт службы OpenRC (#!/sbin/openrc-run).
func RenderOpenRC(d TemplateData) (string, error) {
	desc := strings.NewReplacer("\r", " ", "\n", " ").Replace(d.Description)
	var b strings.Builder
	b.Grow(768)
	b.WriteString("#!/sbin/openrc-run\n# ")
	b.WriteString(desc)
	b.WriteString(" (создано zator)\ndescription=")
	b.WriteString(shellQuote(desc))
	b.WriteString("\ncommand=")
	b.WriteString(shellQuote(d.Exe()))
	if len(d.Command) > 1 {
		b.WriteString("\ncommand_args=")
		b.WriteString(openrcCommandArgs(d.Command[1:]))
	}
	b.WriteString("\ncommand_background=\"yes\"\npidfile=\"/run/${RC_SVCNAME}.pid\"")
	if d.LogFile != "" {
		qLog := shellQuote(d.LogFile)
		b.WriteString("\noutput_log=")
		b.WriteString(qLog)
		b.WriteString("\nerror_log=")
		b.WriteString(qLog)
	}
	b.WriteString("\n\ndepend() {\n\tneed net\n}\n\nstart_pre() {\n\tPATH=\"${PATH:+$PATH:}\"")
	b.WriteString(shellQuote(d.Path))
	b.WriteString("\n\texport PATH\n\tZATOR_ROOT=")
	b.WriteString(shellQuote(d.ZatorRoot))
	b.WriteString("\n\tZAPRET2_ROOT=")
	b.WriteString(shellQuote(d.ZapretRoot))
	b.WriteString("\n\texport ZATOR_ROOT ZAPRET2_ROOT")
	if validReleaseRepository(d.ReleaseOwner, d.ReleaseRepo) {
		b.WriteString("\n\tZATOR_OWNER=")
		b.WriteString(shellQuote(d.ReleaseOwner))
		b.WriteString("\n\tZATOR_REPO=")
		b.WriteString(shellQuote(d.ReleaseRepo))
		b.WriteString("\n\texport ZATOR_OWNER ZATOR_REPO")
	}
	if d.LogFile != "" {
		b.WriteString("\n\tmkdir -p \"$(dirname \"$pidfile\")\" \"$(dirname \"$output_log\")\"" +
			"\n\tLOG_MAX_BYTES=\"${Z2R_SERVICE_LOG_MAX:-262144}\"" +
			"\n\tif [ -f \"$output_log\" ]; then" +
			"\n\t\tsz=$(wc -c <\"$output_log\" 2>/dev/null || echo 0)" +
			"\n\t\tsz=$(echo \"$sz\" | tr -d ' \\t')" +
			"\n\t\tif [ -n \"$sz\" ] && [ \"$sz\" -gt \"$LOG_MAX_BYTES\" ] 2>/dev/null; then" +
			"\n\t\t\tmv -f \"$output_log\" \"$output_log.old\" 2>/dev/null || true" +
			"\n\t\tfi" +
			"\n\tfi")
	} else {
		b.WriteString("\n\tmkdir -p \"$(dirname \"$pidfile\")\"")
	}
	b.WriteString("\n}\n")
	return b.String(), nil
}

// RenderOpenRCZapretWrapper формирует тонкий OpenRC-скрипт для zapret2 поверх
// штатного init.d/sysv/zapret2 (запасной вариант при отсутствии init.d/openrc/zapret2).
func RenderOpenRCZapretWrapper(sysvScript string) (string, error) {
	if strings.TrimSpace(sysvScript) == "" {
		return "", fmt.Errorf("service: пустой путь к SysV init zapret2")
	}
	if err := validatePath(sysvScript); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}
	q := shellQuote(filepath.ToSlash(sysvScript))
	var b strings.Builder
	b.Grow(384)
	b.WriteString("#!/sbin/openrc-run\n# zapret2 (создано zator)\ndescription=\"zapret2 (nfqws2)\"\nextra_commands=\"restart_fw\"\n\ndepend() {\n\tneed net\n}\n\nstart() {\n\tebegin \"Starting zapret2\"\n\t")
	b.WriteString(q)
	b.WriteString(" start\n\teend $?\n}\n\nstop() {\n\tebegin \"Stopping zapret2\"\n\t")
	b.WriteString(q)
	b.WriteString(" stop\n\teend $?\n}\n\nstatus() {\n\t")
	b.WriteString(q)
	b.WriteString(" status\n}\n\nrestart_fw() {\n\tebegin \"Reloading zapret2 firewall\"\n\t")
	b.WriteString(q)
	b.WriteString(" restart-fw\n\teend $?\n}\n")
	return b.String(), nil
}

func openrcCommandArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	joined := strings.Join(q, " ")
	var b strings.Builder
	b.Grow(len(joined) + 4)
	b.WriteByte('"')
	for i := 0; i < len(joined); i++ {
		switch c := joined[i]; c {
		case '\\', '"', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// RenderKeeneticHook формирует ndm-хук netfilter.d.
func RenderKeeneticHook(d TemplateData) (string, error) {
	var b strings.Builder
	b.Grow(192)
	b.WriteString(`#!/bin/sh
# ndm пересобирает firewall при сетевых событиях: возвращаем правила zapret2.
[ "$table" != "mangle" ] && [ "$table" != "nat" ] && exit 0
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH
`)
	b.WriteString(shellQuote(d.InitScript))
	b.WriteString(` restart-fw
exit 0
`)
	return b.String(), nil
}

// MerlinHookLine — строка для /jffs/scripts/firewall-start.
func MerlinHookLine(initScript string) string {
	return shellQuote(filepath.ToSlash(initScript)) + " restart-fw"
}

// AddHookLine добавляет line в содержимое скрипта, если её там ещё нет
// (сравнение построчно, как grep -qxF). Пустое содержимое получает shebang.
func AddHookLine(content, line string) string {
	if content == "" {
		content = "#!/bin/sh\n"
	}
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimRight(l, "\r") == line {
			return content
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

// RemoveHookLine удаляет все вхождения line (целой строкой).
func RemoveHookLine(content, line string) string {
	lines := strings.Split(content, "\n")
	out := lines[:0:0]
	for _, l := range lines {
		if strings.TrimRight(l, "\r") != line {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// templateData собирает данные шаблона для службы.
func (m *manager) templateData(u Unit) TemplateData {
	d := TemplateData{
		Name:         string(u),
		Path:         defaultPath,
		FWHook:       slash(m.cfg.FWHook),
		ZatorRoot:    slash(m.cfg.Paths.ZatorRoot),
		ZapretRoot:   slash(m.cfg.Paths.ZapretRoot),
	}
	switch u {
	case UnitZapret2:
		d.Description = "zapret2 (nfqws2)"
		// nfqws2 @file жёстко ограничен MAX_CONFIG_FILE_SIZE (16 КБ) в nfq2/nfqws.c,
		// а полный nfqws2.args > 32 КБ — запускаем через zator exec-nfqws2 (execve → argv).
		d.Command = []string{
			slash(m.cfg.ZatorBin),
			"exec-nfqws2",
			slash(filepath.Join(m.cfg.Paths.ZapretRoot, "nfq2", "nfqws2")),
			slash(m.cfg.ArgsFile),
		}
		d.Start = 90
		if m.cfg.FWHook != "" {
			d.WssizeBin = slash(m.cfg.ZatorBin)
		}
	case UnitValidator:
		d.Description = "zator strategy-validator (circular_quality watchdog)"
		script := slash(filepath.Join(m.cfg.Paths.LuaDir, "strategy-validator.sh"))
		d.Command = []string{script, "--daemon"}
		d.Start = 91
		d.FWHook = ""
	case UnitWebUI:
		d.Description = "zator Web UI"
		d.Command = []string{slash(m.cfg.ZatorBin), "webui"}
		d.Start = 95
		d.FWHook = "" // межсетевой экран относится только к zapret2
		d.ReleaseOwner = os.Getenv("ZATOR_OWNER")
		d.ReleaseRepo = os.Getenv("ZATOR_REPO")
	}
	runDir := "/var/run"
	switch m.cfg.Backend {
	case BackendEntware:
		runDir = "/opt/var/run"
	case BackendOpenRC:
		runDir = "/run"
	}
	d.PIDFile = runDir + "/" + string(u) + ".pid"
	d.LogFile = slash(filepath.Join(os.TempDir(), "zator", "logs", string(u)+".log"))
	return d
}

func slash(p string) string { return filepath.ToSlash(p) }

func validReleaseRepository(owner, repo string) bool {
	validPart := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
		return true
	}
	return validPart(owner) && validPart(repo)
}
