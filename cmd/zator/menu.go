package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/AloofLibra/zator"
	"github.com/AloofLibra/zator/internal/app"
	"github.com/AloofLibra/zator/internal/backup"
	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/deploy"
	"github.com/AloofLibra/zator/internal/orchestra"
	"github.com/AloofLibra/zator/internal/paths"
	"github.com/AloofLibra/zator/internal/service"
	"github.com/AloofLibra/zator/internal/sweep"
	"github.com/AloofLibra/zator/internal/webapi"
	"golang.org/x/term"
)

// menu — намеренно последовательный текстовый интерфейс: он не опрашивает
// клавиатуру и использует те же команды, что и неинтерактивный CLI.
const menuBack = -1

func runMenu(input io.Reader, output, stderr io.Writer) int {
	r := bufio.NewReader(input)
	for {
		menuClearScreen(output)
		title := fmt.Sprintf("ZATOR GO %s", zator.Version())
		state := "● НЕ УСТАНОВЛЕН"
		if a, err := app.Load(); err == nil {
			if a.Installed() {
				state = "● УСТАНОВЛЕН"
				if ctl, err := service.New(service.Config{Platform: a.Platform, Paths: a.Paths}); err == nil {
					if st, err := ctl.Status(context.Background(), service.UnitZapret2); err == nil {
						if st.Running {
							state = "● РАБОТАЕТ"
						} else {
							state = "● ОСТАНОВЛЕН"
						}
					}
				}
			}
			fmt.Fprintf(output, "%-52s%s\n", menuColor("96;1", title), menuColor("96", state))
			fmt.Fprintln(output, menuColor("90", strings.Repeat("─", 72)))
			fmt.Fprintf(output, "Платформа: %s\nСлужба:    zapret2 %s\nОбновления: %s\n", a.Platform, stateLabel(state), menuColor("96", menuCachedUpdates(a.Paths, a.Installed())))
		} else {
			fmt.Fprintf(output, "%s\n", menuColor("96;1", title))
		}
		fmt.Fprintln(output, menuColor("90", strings.Repeat("─", 72)))
		fmt.Fprintln(output, menuColor("96;1", "ГЛАВНОЕ МЕНЮ"))
		fmt.Fprintln(output, "1.  Статус и диагностика")
		fmt.Fprintln(output, "2.  Стратегии")
		fmt.Fprintln(output, "3.  Supersweep — подбор стратегий")
		fmt.Fprintln(output, "4.  Домены и списки")
		fmt.Fprintln(output, "5.  Настройки обхода")
		fmt.Fprintln(output, "6.  Службы")
		fmt.Fprintln(output, "7.  Обновление ZatorGO")
		fmt.Fprintln(output, "8.  Резервные копии")
		fmt.Fprintln(output, "9.  Дополнительные инструменты")
		fmt.Fprintln(output, "0.  Выход")
		fmt.Fprintln(output, menuColor("90", strings.Repeat("─", 72)))
		choice, err := menuRead(r, output, "Выбор: ")
		if err != nil {
			if err == io.EOF {
				return 0
			}
			fmt.Fprintln(stderr, err)
			return 1
		}
		var code int
		switch choice {
		case "0":
			if menuExit(r, output, stderr) {
				return 0
			}
		case "1":
			code = menuPage(output, stderr, "Статус и диагностика", func() int { return menuStatus(r, output, stderr) })
		case "2":
			code = menuPage(output, stderr, "Стратегии", func() int { return menuStrategies(r, output, stderr) })
		case "3":
			code = menuPage(output, stderr, "Supersweep", func() int { return menuSweep(r, output, stderr) })
		case "4":
			code = menuPage(output, stderr, "Домены и списки", func() int { return menuDomains(r, output, stderr) })
		case "5":
			code = menuPage(output, stderr, "Настройки обхода", func() int { return menuSettings(r, output, stderr) })
		case "6":
			code = menuPage(output, stderr, "Службы", func() int { return menuServices(r, output, stderr) })
		case "7":
			code = menuPage(output, stderr, "Обновление", func() int { return menuUpdate(r, output, stderr) })
		case "8":
			code = menuPage(output, stderr, "Резервные копии", func() int { return menuBackups(r, output, stderr) })
		case "9":
			code = menuPage(output, stderr, "Инструменты", func() int { return menuTools(r, output, stderr) })
		default:
			fmt.Fprintln(output, "Введите номер от 0 до 9.")
		}
		if code != 0 {
			fmt.Fprintf(stderr, "Команда завершилась с кодом %d.\n", code)
		}
	}
}

func menuPage(out, errw io.Writer, title string, page func() int) int {
	for {
		menuClearScreen(out)
		fmt.Fprintln(out, menuColor("96;1", strings.ToUpper(title)))
		fmt.Fprintln(out, menuColor("90", strings.Repeat("─", 72)))
		code := page()
		if code == menuBack {
			return 0
		}
		if code != 0 {
			fmt.Fprintf(errw, "Команда завершилась с кодом %d.\n", code)
		}
	}
}

func menuClearScreen(w io.Writer) {
	out, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(out.Fd())) || os.Getenv("TERM") == "dumb" {
		return
	}
	// Clear the visible screen only. Omitting CSI 3J preserves terminal scrollback.
	_, _ = fmt.Fprint(w, "\x1b[2J\x1b[H")
}

func stateLabel(state string) string {
	switch state {
	case "● РАБОТАЕТ":
		return "запущена"
	case "● ОСТАНОВЛЕН":
		return "остановлена"
	default:
		return "не проверена"
	}
}

func menuCachedUpdates(p paths.Paths, installed bool) string {
	cache := deploy.LatestCachePath(p)
	info, err := os.Stat(cache)
	if err != nil {
		return "не проверялись"
	}
	raw, err := os.ReadFile(cache)
	if err != nil {
		return "кэш недоступен"
	}
	latest, err := deploy.ParseLatest(raw)
	if err != nil {
		return "кэш повреждён"
	}
	current, err := deploy.ReadVersion(p)
	if err != nil {
		return "кэш есть, текущая версия неизвестна"
	}
	result := deploy.CompareLatest(current, latest, installed)
	state := "актуально по кэшу"
	if result.UpdateAvailable() {
		state = "доступно по кэшу"
	}
	return fmt.Sprintf("%s (кэш от %s)", state, info.ModTime().Format("2006-01-02 15:04"))
}

func menuRead(r *bufio.Reader, w io.Writer, prompt string) (string, error) {
	fmt.Fprint(w, menuColor("96;1", prompt))
	s, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if err == io.EOF && s == "" {
		return "", io.EOF
	}
	return strings.TrimSpace(s), nil
}

func menuStatus(r *bufio.Reader, out, errw io.Writer) int {
	code := cmdStatus(out, errw)
	fmt.Fprintln(out, "\n 1. Обновить статус\n 2. Ошибки nfqws2 и предупреждения служб\n 3. Проверить доступность\n 4. Службы\n 0. Назад")
	c, err := menuRead(r, out, "Выберите пункт: ")
	if err != nil {
		return menuBack
	}
	switch c {
	case "0":
		return menuBack
	case "1":
		return cmdStatus(out, errw)
	case "2":
		return cmdErrors(nil, out, errw)
	case "3":
		s, err := menuServer()
		if err != nil {
			fmt.Fprintln(errw, err)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.CLIReachability(ctx)
		return menuResult(out, errw, res, err)
	case "4":
		return menuPage(out, errw, "Службы", func() int { return menuServices(r, out, errw) })
	default:
		fmt.Fprintln(out, "Некорректный выбор.")
	}
	return code
}

func menuStrategies(r *bufio.Reader, out, errw io.Writer) int {
	a, err := app.Load()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	cfg, err := config.Load(a.Paths.ZapretConfig)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	store := orchestra.NewStore(a.Paths.StateOrchestraDir())
	srv, err := menuServer()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	scope, ok := menuChooseScope(r, out, srv)
	if !ok {
		return menuBack
	}
	menuClearScreen(out)
	fmt.Fprintf(out, "%s · %s\n", menuColor("96;1", "СТРАТЕГИИ"), scope)
	fmt.Fprintf(out, "Ручные фиксации: %s\n\n", map[bool]string{true: "есть", false: "нет"}[store.HasLocks()])
	for _, p := range cfg.Profiles() {
		lock, source, err := srv.CLIProfileLockLabel(scope, p.ID)
		if err != nil {
			fmt.Fprintln(errw, err)
			return 1
		}
		fmt.Fprintf(out, " %2d. %-18s стратегия %s (%s, макс. %d)\n", p.ID, p.Label, lock, source, cfg.ProfileMaxStrategyOrDefault(p.ID))
	}
	fmt.Fprintln(out, "\n 1. Зафиксировать стратегию / выключить профиль (0)\n 2. Снять фиксацию (auto)\n 3. Проверить профиль\n 0. Назад")
	c, e := menuRead(r, out, "Выберите пункт: ")
	if e != nil {
		return menuBack
	}
	if c == "0" {
		return menuBack
	}
	idText, e := menuRead(r, out, "Номер профиля: ")
	if e != nil {
		return 0
	}
	id, e := strconv.Atoi(idText)
	if e != nil || !config.ValidProfile(id) {
		fmt.Fprintln(errw, "Некорректный профиль.")
		return 1
	}
	switch c {
	case "1":
		raw, e := menuRead(r, out, fmt.Sprintf("Стратегия 0..%d (0 = выключить профиль): ", cfg.ProfileMaxStrategyOrDefault(id)))
		if e != nil {
			return 0
		}
		n, e := strconv.Atoi(raw)
		if e != nil || n < 0 || n > cfg.ProfileMaxStrategyOrDefault(id) {
			fmt.Fprintln(errw, "Номер стратегии вне допустимого диапазона.")
			return 1
		}
		if n == 0 {
			ok, e := menuConfirm(r, out, "Отключить профиль?")
			if e != nil || !ok {
				return 0
			}
		}
		res, err := srv.CLISetProfileLock(context.Background(), scope, id, &n)
		return menuResult(out, errw, res, err)
	case "2":
		ok, e := menuConfirm(r, out, "Снять фиксацию и вернуть профиль в auto?")
		if e != nil || !ok {
			return 0
		}
		res, err := srv.CLISetProfileLock(context.Background(), scope, id, nil)
		return menuResult(out, errw, res, err)
	case "3":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := srv.CLIProfileCheck(ctx, id)
		return menuResult(out, errw, res, err)
	default:
		fmt.Fprintln(out, "Введите 1, 2, 3 или 0.")
		return 0
	}
}

func menuServices(r *bufio.Reader, out, errw io.Writer) int {
	code := cmdService([]string{"status"}, out, errw)
	fmt.Fprintln(out, "\n 1. Запустить службу\n 2. Остановить службу\n 3. Перезапустить службу\n 4. Предупреждения\n 0. Назад")
	c, err := menuRead(r, out, "Выберите пункт: ")
	if err != nil {
		return menuBack
	}
	switch c {
	case "0":
		return menuBack
	case "1", "2", "3":
		fmt.Fprintf(out, "Службы: 1 zapret2, 2 %s, 3 %s\n", service.UnitValidator, service.UnitWebUI)
		fmt.Fprintln(out, " 0. Назад")
		unitChoice, e := menuRead(r, out, "Номер службы: ")
		if e != nil {
			return 0
		}
		if unitChoice == "0" {
			return 0
		}
		units := map[string]string{"1": "zapret2", "2": string(service.UnitValidator), "3": string(service.UnitWebUI)}
		unit, ok := units[unitChoice]
		if !ok {
			fmt.Fprintln(errw, "Некорректная служба.")
			return 1
		}
		action := map[string]string{"1": "start", "2": "stop", "3": "restart"}[c]
		if action != "start" {
			ok, e := menuConfirm(r, out, fmt.Sprintf("%s %s?", map[string]string{"stop": "Остановить", "restart": "Перезапустить"}[action], unit))
			if e != nil || !ok {
				return 0
			}
		}
		return cmdService([]string{action, unit}, out, errw)
	case "4":
		return cmdService([]string{"warnings"}, out, errw)
	default:
		fmt.Fprintln(out, "Некорректный выбор.")
	}
	return code
}

func menuBackups(r *bufio.Reader, out, errw io.Writer) int {
	a, err := app.Load()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	m := backup.NewIn(a.Paths, a.Paths.BackupDir)
	items, err := m.List()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	fmt.Fprintf(out, "Резервные копии (%d):\n", len(items))
	for i, item := range items {
		fmt.Fprintf(out, " %d. %s  %d байт  %s\n", i+1, item.Name, item.Size, item.ModTime.Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(out, "\n 1. Создать резервную копию\n 2. Smart-восстановление\n 3. Откат последнего обновления\n 0. Назад")
	c, err := menuRead(r, out, "Выберите пункт: ")
	if err != nil {
		return menuBack
	}
	switch c {
	case "0":
		return menuBack
	case "1":
		created, e := m.Create(backup.CreateOptions{IncludeLists: true, IncludeExtraStrats: true, IncludeOrchestraState: true})
		if e != nil {
			fmt.Fprintln(errw, e)
			return 1
		}
		fmt.Fprintf(out, "Создана резервная копия: %s (%d байт)\n", created.Name, created.Size)
		return 0
	case "2":
		if len(items) == 0 {
			fmt.Fprintln(out, "Список резервных копий пуст.")
			return 0
		}
		choice, e := menuRead(r, out, fmt.Sprintf("Номер копии для восстановления (1..%d, 0 — назад): ", len(items)))
		if e != nil || choice == "0" {
			return 0
		}
		n, e := strconv.Atoi(choice)
		if e != nil || n < 1 || n > len(items) {
			fmt.Fprintln(errw, "Некорректный номер резервной копии.")
			return 1
		}
		name := items[n-1].Name
		fmt.Fprintln(out, "Smart-восстановление переносит поддерживаемые настройки и состояние списков/фиксаций; живой config полностью не заменяется.")
		ok, e := menuConfirm(r, out, "Восстановить эту резервную копию?")
		if e != nil || !ok {
			return 0
		}
		result, e := m.Restore(name, backup.RestoreOptions{Mode: backup.ModeSmart})
		if e != nil {
			fmt.Fprintln(errw, e)
			return 1
		}
		fmt.Fprintf(out, "Восстановлено файлов: %d; параметров config: %d\n", len(result.Files), len(result.SmartApplied))
		return 0
	case "3":
		return cmdRollback(nil, out, errw)
	default:
		fmt.Fprintln(out, "Некорректный выбор.")
	}
	return 0
}

func menuTools(r *bufio.Reader, out, errw io.Writer) int {
	fmt.Fprintln(out, " 1. Проверить HTTPS/TLS (blockcheck2)\n 2. Свои стратегии\n 3. Блобы и SNI\n 4. h3-curl (HTTP/3 для Профиля 5)\n 5. Запустить Web UI\n 6. Статус авторизации\n 7. Включить авторизацию\n 8. Отключить авторизацию\n 9. Справка CLI\n 0. Назад")
	c, err := menuRead(r, out, "Выберите пункт: ")
	if err != nil {
		return menuBack
	}
	switch c {
	case "0":
		return menuBack
	case "1":
		fmt.Fprintln(out, "Внимание: blockcheck2 временно останавливает zapret2 и затем пытается восстановить службу.")
		ok, e := menuConfirm(r, out, "Запустить проверку?")
		if e != nil || !ok {
			return 0
		}
		domain, e := menuRead(r, out, "Домен или URL для проверки: ")
		if e != nil {
			return 0
		}
		return cmdBlockcheck([]string{"-y", domain}, out, errw)
	case "2":
		return menuCustomStrategies(r, out, errw)
	case "3":
		return menuBlobsAndSNI(r, out, errw)
	case "4":
		return menuH3Curl(r, out, errw)
	case "5":
		return cmdServe("webui", nil, out, errw)
	case "6":
		return cmdAuth([]string{"status"}, out, errw)
	case "7":
		return cmdAuth([]string{"enable"}, out, errw)
	case "8":
		ok, e := menuConfirm(r, out, "Отключить проверку доступа к Web UI?")
		if e != nil || !ok {
			return 0
		}
		return cmdAuth([]string{"disable", "-y"}, out, errw)
	case "9":
		fmt.Fprint(out, usage)
	default:
		fmt.Fprintln(out, "Некорректный выбор.")
	}
	return 0
}

func menuServer() (*webapi.Server, error) {
	a, err := app.Load()
	if err != nil {
		return nil, err
	}
	return webapi.New(webapi.Options{App: a, Static: os.DirFS(a.Paths.WebUIDir)})
}

func menuResult(out, errw io.Writer, value any, err error) int {
	if err != nil {
		fmt.Fprintln(errw, menuColor("31", fmt.Sprint(err)))
		return 1
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		fmt.Fprintln(errw, e)
		return 1
	}
	fmt.Fprintln(out, menuColor("32", "Готово"))
	fmt.Fprintln(out, string(data))
	return 0
}

func menuColor(code, text string) string {
	if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("TERM") == "dumb" || os.Getenv("NO_COLOR") != "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func menuConfirm(r *bufio.Reader, out io.Writer, question string) (bool, error) {
	for {
		a, err := menuRead(r, out, question+" 1. Да  0. Нет: ")
		if err != nil {
			return false, err
		}
		switch a {
		case "1":
			return true, nil
		case "0":
			return false, nil
		default:
			fmt.Fprintln(out, "Введите 1 или 0.")
		}
	}
}

func menuChooseScope(r *bufio.Reader, out io.Writer, s *webapi.Server) (string, bool) {
	scopes, err := s.CLIClientScopes()
	if err != nil {
		fmt.Fprintln(out, "Не удалось прочитать список scope:", err)
		return "", false
	}
	for {
		menuClearScreen(out)
		fmt.Fprintln(out, menuColor("96;1", "ОБЛАСТЬ ПРИМЕНЕНИЯ"))
		fmt.Fprintln(out, menuColor("90", strings.Repeat("─", 72)))
		fmt.Fprintln(out, "Область применения:")
		for i, scope := range scopes {
			label := scope
			if scope == orchestra.ScopeDefault {
				label = "default — все клиенты"
			}
			fmt.Fprintf(out, " %d. %s\n", i+1, label)
		}
		fmt.Fprintln(out, " 0. Назад")
		choice, err := menuRead(r, out, "Выберите scope: ")
		if err != nil || choice == "0" {
			return "", false
		}
		n, err := strconv.Atoi(choice)
		if err == nil && n >= 1 && n <= len(scopes) {
			return scopes[n-1], true
		}
		fmt.Fprintf(out, "Введите номер от 1 до %d или 0 для возврата.\n", len(scopes))
	}
}

func menuChooseTLS(r *bufio.Reader, out io.Writer) (string, bool) {
	choices := []struct{ label, value string }{
		{"TLS 1.2 и 1.3", "any"},
		{"Только TLS 1.2", "12"},
		{"Только TLS 1.3", "13"},
		{"Оба режима отдельно", "both"},
	}
	for {
		menuClearScreen(out)
		fmt.Fprintln(out, menuColor("96;1", "ВЕРСИИ TLS"))
		fmt.Fprintln(out, menuColor("90", strings.Repeat("─", 72)))
		fmt.Fprintln(out, "Версии TLS:")
		for i, choice := range choices {
			fmt.Fprintf(out, " %d. %s\n", i+1, choice.label)
		}
		fmt.Fprintln(out, " 0. Назад")
		choice, err := menuRead(r, out, "Выберите режим TLS: ")
		if err != nil || choice == "0" {
			return "", false
		}
		n, err := strconv.Atoi(choice)
		if err == nil && n >= 1 && n <= len(choices) {
			return choices[n-1].value, true
		}
		fmt.Fprintln(out, "Введите номер от 1 до 4 или 0 для возврата.")
	}
}

func menuSweep(r *bufio.Reader, out, errw io.Writer) int {
	fmt.Fprintln(out, " 1. Состояние и прогресс\n 2. Полный Supersweep\n 3. Быстрый подбор профиля\n 4. Отменить текущий прогон\n 0. Назад")
	a, e := menuRead(r, out, "Выберите пункт: ")
	if e != nil {
		return menuBack
	}
	if a == "0" {
		return menuBack
	}
	s, err := menuServer()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	ctx := context.Background()
	var result map[string]any
	switch a {
	case "1":
		result, err = s.CLISupersweep(ctx, "status", nil)
	case "2":
		pref, ok := menuChooseTLS(r, out)
		if !ok {
			return 0
		}
		domains, e := menuRead(r, out, "Дополнительные домены через запятую (Enter — стандартный список): ")
		if e != nil {
			return 0
		}
		incQ, _ := menuConfirm(r, out, "Включить подбор Профиля 5 (YouTube QUIC HTTP/3, живой режим)?")
		vals := map[string]string{"tls_pref": pref, "domain": domains}
		if incQ {
			vals["include_quic"] = "1"
			rnd, _ := menuRead(r, out, "Число раундов QUIC на стратегию (1..5, Enter=1): ")
			if rnd != "" {
				vals["quic_rounds"] = rnd
			}
		}
		ok, e = menuConfirm(r, out, "Полный Supersweep проверит профили и домены, может выполняться долго и менять фиксации. Начать?")
		if e != nil || !ok {
			return 0
		}
		scope, ok := menuChooseScope(r, out, s)
		if !ok {
			return 0
		}
		vals["scope"] = scope
		menuClearScreen(out)
		fmt.Fprintf(out, "%s · scope %s\n\n", menuColor("96;1", "ПОЛНЫЙ SUPERSWEEP"), scope)
		result, err = s.CLISupersweep(ctx, "start", vals)
	case "3":
		ptext, e := menuRead(r, out, "Профиль быстрого подбора (1 YouTube, 2 Googlevideo, 3 РКН, 4 Discord, 5 YouTube QUIC): ")
		if e != nil {
			return 0
		}
		p, pe := strconv.Atoi(ptext)
		if pe != nil || p < 1 || p > 5 {
			fmt.Fprintln(errw, "Допустимы профили 1..5.")
			return 1
		}
		addr := ""
		pref := "any"
		quicRounds := ""
		if p == 5 {
			fmt.Fprintln(out, "Внимание: подбор Профиля 5 выполняется в живом режиме через h3-curl (без изоляции).")
			quicRounds, _ = menuRead(r, out, "Число раундов QUIC (1..5, Enter=1): ")
		} else {
			addr, e = menuRead(r, out, "Адрес проверки (Enter — стандартный): ")
			if e != nil {
				return 0
			}
			var okTLS bool
			pref, okTLS = menuChooseTLS(r, out)
			if !okTLS {
				return 0
			}
			if addr == "" {
				addr = "стандартный"
			}
		}
		menuClearScreen(out)
		fmt.Fprintf(out, "%s · профиль %d\n\n", menuColor("96;1", "БЫСТРЫЙ ПОДБОР"), p)
		ok, e := menuConfirm(r, out, "Начать быстрый подбор?")
		if e != nil || !ok {
			return 0
		}
		scope, ok := menuChooseScope(r, out, s)
		if !ok {
			return 0
		}
		menuClearScreen(out)
		fmt.Fprintf(out, "%s · scope %s\n\n", menuColor("96;1", "БЫСТРЫЙ ПОДБОР"), scope)
		vals := map[string]string{"quick_profile": fmt.Sprint(p), "scope": scope, "tls_pref": pref}
		if p != 5 {
			vals["address"] = addr
		} else if quicRounds != "" {
			vals["quic_rounds"] = quicRounds
		}
		result, err = s.CLISupersweep(ctx, "start", vals)
	case "4":
		ok, e := menuConfirm(r, out, "Отменить именно тестирование Supersweep?")
		if e != nil || !ok {
			return 0
		}
		result, err = s.CLISupersweep(ctx, "cancel", nil)
	default:
		fmt.Fprintln(out, "Некорректный выбор.")
		return 0
	}
	if a == "2" || a == "3" {
		if err != nil {
			fmt.Fprintln(errw, err)
			return 1
		}
		fmt.Fprintln(out, "Прогон запущен. Ctrl+C отменяет именно тестирование; выход из меню не отменяет прогон.")
		return monitorSweep(s, out, errw)
	}
	code := menuResult(out, errw, result, err)
	if a == "1" && err == nil {
		printSweepProgress(out, result)
	}
	return code
}

func monitorSweep(s *webapi.Server, out, errw io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		result, err := s.CLISupersweep(checkCtx, "status", nil)
		cancel()
		if err != nil {
			fmt.Fprintln(errw, "Не удалось прочитать состояние Supersweep:", err)
			return 1
		}
		printSweepLine(out, result)
		root, _ := result["running"].(bool)
		if !root {
			fmt.Fprintln(out)
			printSweepProgress(out, result)
			if rep, ok := extractSweepReport(result); ok && rep.Error != "" {
				fmt.Fprintln(out, "Supersweep остановлен с ошибкой.")
			} else {
				fmt.Fprintln(out, "Supersweep завершён.")
			}
			return 0
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(out, "\nПросмотр остановлен. Supersweep продолжает работу; для отмены выберите пункт 4.")
			return 0
		case <-ticker.C:
		}
	}
}

func extractSweepReport(value any) (sweep.Report, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return sweep.Report{}, false
	}
	rep, ok := root["report"].(sweep.Report)
	if !ok {
		b, _ := json.Marshal(root["report"])
		_ = json.Unmarshal(b, &rep)
	}
	return rep, rep.State.Valid()
}

func printSweepLine(out io.Writer, value any) {
	rep, ok := extractSweepReport(value)
	if !ok {
		return
	}
	pct := 0
	if rep.Total > 0 {
		pct = rep.Completed * 100 / rep.Total
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	fmt.Fprintf(out, "\rSupersweep %-12s %3d%% (%d/%d), воркеры %d, найдено %d", rep.Phase, pct, rep.Completed, rep.Total, len(rep.Workers), len(rep.Applied))
}

func menuExit(r *bufio.Reader, out, errw io.Writer) bool {
	s, err := menuServer()
	if err != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	state, err := s.CLISupersweep(ctx, "status", nil)
	cancel()
	if err != nil {
		return true
	}
	running, _ := state["running"].(bool)
	if !running {
		return true
	}
	fmt.Fprintln(out, "Supersweep ещё выполняется. Выход завершит процесс и прервёт прогон.")
	stop, err := menuConfirm(r, out, "Отменить тестирование и выйти?")
	if err != nil || !stop {
		return false
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	_, err = s.CLISupersweep(ctx, "cancel", nil)
	cancel()
	if err != nil {
		fmt.Fprintln(errw, err)
		return false
	}
	return true
}

func printSweepProgress(out io.Writer, value any) {
	rep, ok := extractSweepReport(value)
	if !ok {
		return
	}
	pct := 0
	if rep.Total > 0 {
		pct = rep.Completed * 100 / rep.Total
		if pct > 100 {
			pct = 100
		}
	}
	if pct < 0 {
		pct = 0
	}
	filled := pct / 5
	fmt.Fprintf(out, "Supersweep: %s\nПроверено: %d / %d\nПрогресс: [%s%s] %d%%\nВоркеры: %d\nСостояние: %s\nНайдено применений: %d\n", rep.Phase, rep.Completed, rep.Total, strings.Repeat("#", filled), strings.Repeat("-", 20-filled), pct, len(rep.Workers), rep.State, len(rep.Applied))
	if rep.Error != "" {
		fmt.Fprintf(out, "Ошибка: %s\n", rep.Error)
	}
}

func menuDomains(r *bufio.Reader, out, errw io.Writer) int {
	lists := []struct{ name, label string }{
		{"netrogat", "Исключения (netrogat)"},
		{"custom_rkn", "Свои домены РКН"},
		{"substring", "Подстроки"},
		{"netrogat_substring", "Исключения по подстрокам"},
		{"googlevideo", "Googlevideo IP"},
	}
	fmt.Fprintln(out, "Списки:")
	for i, list := range lists {
		fmt.Fprintf(out, " %d. %s\n", i+1, list.label)
	}
	fmt.Fprintln(out, " 0. Назад")
	choice, e := menuRead(r, out, "Выберите список: ")
	if e != nil || choice == "0" {
		return menuBack
	}
	n, err := strconv.Atoi(choice)
	if err != nil || n < 1 || n > len(lists) {
		fmt.Fprintln(errw, "Некорректный номер списка.")
		return 1
	}
	name := lists[n-1].name
	s, err := menuServer()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	scope, ok := menuChooseScope(r, out, s)
	if !ok {
		return 0
	}
	menuClearScreen(out)
	fmt.Fprintf(out, "%s · %s · scope %s\n\n", menuColor("96;1", "СПИСОК ДОМЕНОВ"), lists[n-1].label, scope)
	data, err := s.CLIDomains(context.Background(), name, scope, "list", nil)
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	items, _ := data["items"].([]map[string]any)
	if items == nil {
		b, _ := json.Marshal(data)
		var d struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(b, &d)
		items = d.Items
	}
	fmt.Fprintf(out, "Список %s: %d записей\n", name, len(items))
	const maxVisibleDomains = 40
	for i, it := range items {
		if i == maxVisibleDomains {
			fmt.Fprintf(out, "  ... ещё %d записей (поиск покажет совпадения)\n", len(items)-maxVisibleDomains)
			break
		}
		fmt.Fprintf(out, "  %v\n", it["value"])
	}
	if name == "custom_rkn" {
		fmt.Fprintln(out, " 1. Добавить\n 2. Удалить\n 3. Поиск\n 4. Импорт из файла\n 5. Назначить стратегию\n 6. Снять фиксацию\n 0. Назад")
	} else {
		fmt.Fprintln(out, " 1. Добавить\n 2. Удалить\n 3. Поиск\n 4. Импорт из файла\n 0. Назад")
	}
	a, e := menuRead(r, out, "Выберите пункт: ")
	if e != nil || a == "0" {
		return 0
	}
	if a == "3" {
		q, e := menuRead(r, out, "Строка поиска: ")
		if e != nil {
			return 0
		}
		n := 0
		for _, it := range items {
			v := fmt.Sprint(it["value"])
			if strings.Contains(strings.ToLower(v), strings.ToLower(q)) {
				fmt.Fprintln(out, v)
				n++
			}
		}
		fmt.Fprintf(out, "Найдено: %d\n", n)
		return 0
	}
	if a != "1" && a != "2" && a != "4" && !(name == "custom_rkn" && (a == "5" || a == "6")) {
		fmt.Fprintln(out, "Некорректный пункт.")
		return 0
	}
	if a == "5" || a == "6" {
		domain, e := menuRead(r, out, "Домен: ")
		if e != nil {
			return 0
		}
		if a == "6" {
			ok, e := menuConfirm(r, out, "Снять фиксацию стратегии?")
			if e != nil || !ok {
				return 0
			}
			res, err := s.CLIDomains(context.Background(), name, scope, "clear_strategy", map[string]string{"domain": domain})
			return menuResult(out, errw, res, err)
		}
		max := 0
		switch v := data["max_strategy"].(type) {
		case int:
			max = v
		case float64:
			max = int(v)
		}
		if max < 1 {
			max = 19
		}
		raw, e := menuRead(r, out, fmt.Sprintf("Стратегия 1..%d: ", max))
		if e != nil {
			return 0
		}
		n, pe := strconv.Atoi(raw)
		if pe != nil || n < 1 || n > max {
			fmt.Fprintln(errw, "Номер стратегии вне диапазона.")
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.CLIDomains(ctx, name, scope, "set_strategy", map[string]string{"domain": domain, "strategy": strconv.Itoa(n)})
		return menuResult(out, errw, res, err)
	}
	verb := map[string]string{"1": "add", "2": "remove", "4": "import"}[a]
	if verb == "remove" {
		d, e := menuRead(r, out, "Домен / значение: ")
		if e != nil {
			return 0
		}
		ok, e := menuConfirm(r, out, "Удалить запись из списка?")
		if e != nil || !ok {
			return 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.CLIDomains(ctx, name, scope, verb, map[string]string{"domain": d})
		return menuResult(out, errw, res, err)
	}
	if verb == "add" {
		d, e := menuRead(r, out, "Домен / значение: ")
		if e != nil {
			return 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.CLIDomains(ctx, name, scope, verb, map[string]string{"domain": d})
		return menuResult(out, errw, res, err)
	}
	if verb == "import" {
		file, e := menuRead(r, out, "Путь к файлу со списком: ")
		if e != nil {
			return 0
		}
		info, e := os.Stat(file)
		if e != nil {
			fmt.Fprintln(errw, e)
			return 1
		}
		if info.Size() > 4<<20 {
			fmt.Fprintln(errw, "Файл больше допустимых 4 MiB.")
			return 1
		}
		content, e := os.ReadFile(file)
		if e != nil {
			fmt.Fprintln(errw, e)
			return 1
		}
		lineCount := 0
		for _, b := range content {
			if b == '\n' {
				lineCount++
			}
		}
		if len(content) > 0 && content[len(content)-1] != '\n' {
			lineCount++
		}
		fmt.Fprintf(out, "Будет обработано строк: %d. Текущие записи сохранятся.\n", lineCount)
		ok, e := menuConfirm(r, out, "Импортировать список из файла?")
		if e != nil || !ok {
			return 0
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.CLIDomains(ctx, name, scope, verb, map[string]string{"domain": string(content)})
		return menuResult(out, errw, res, err)
	}
	return 0
}

func menuSettings(r *bufio.Reader, out, errw io.Writer) int {
	settings := []struct{ key, label string }{{"auto_mode", "Авторотация"}, {"fallback", "Fallback"}, {"hostlist", "Autohostlist"}, {"udp_games", "UDP Games"}, {"dns_desync", "DNS desync"}, {"rst_guard", "RST guard"}, {"wg_state", "WireGuard UDP"}, {"reasm", "Reassembly"}, {"wssize_ramp", "WSSIZE ramp"}}
	s, err := menuServer()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	for i, v := range settings {
		state, e := s.CLISetting(context.Background(), v.key)
		fmt.Fprintf(out, " %d. %s: %s\n", i+1, v.label, menuStateText(state))
		if e != nil {
			fmt.Fprintf(out, "    недоступно: %v\n", e)
		}
	}
	fmt.Fprintln(out, " 0. Назад")
	raw, e := menuRead(r, out, "Номер настройки для переключения: ")
	if e != nil || raw == "0" {
		return menuBack
	}
	n, e := strconv.Atoi(raw)
	if e != nil || n < 1 || n > len(settings) {
		fmt.Fprintln(errw, "Некорректный номер.")
		return 1
	}
	setting := settings[n-1]
	current, e := s.CLISetting(context.Background(), setting.key)
	if e != nil {
		fmt.Fprintln(errw, e)
		return 1
	}
	b, _ := json.Marshal(current)
	var st struct {
		Enabled bool   `json:"enabled"`
		Auto    bool   `json:"auto"`
		State   string `json:"state"`
	}
	_ = json.Unmarshal(b, &st)
	on := !st.Enabled
	if setting.key == "hostlist" {
		on = !st.Auto
	} else if st.State != "" {
		switch strings.ToLower(st.State) {
		case "включен", "включено", "enabled", "1", "on":
			on = false
		case "выключен", "выключено", "отключен", "disabled", "0", "off", "ручной":
			on = true
		}
	}
	value := "0"
	if on {
		value = "1"
	}
	ok, e := menuConfirm(r, out, fmt.Sprintf("%s: переключить состояние на %s?", setting.label, map[bool]string{true: "включено", false: "выключено"}[on]))
	if e != nil || !ok {
		return 0
	}
	res, err := s.CLISetSetting(context.Background(), setting.key, map[string]string{"value": value, "restart": "1"})
	return menuResult(out, errw, res, err)
}

func menuStateText(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	var state struct {
		State   string `json:"state"`
		Enabled *bool  `json:"enabled"`
		Auto    *bool  `json:"auto"`
	}
	if json.Unmarshal(b, &state) != nil {
		return fmt.Sprint(value)
	}
	if state.State != "" {
		return state.State
	}
	if state.Enabled != nil {
		return map[bool]string{true: "включено", false: "выключено"}[*state.Enabled]
	}
	if state.Auto != nil {
		return map[bool]string{true: "авто", false: "ручной"}[*state.Auto]
	}
	return fmt.Sprint(value)
}

func menuUpdate(r *bufio.Reader, out, errw io.Writer) int {
	a, err := app.Load()
	if err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}
	offline := deploy.ResolveOfflineBundle(os.Getenv)
	if offline.Offline {
		if offline.Bundle == nil {
			fmt.Fprintln(errw, "Офлайн-режим активен, но bundle приложения/ресурсов не найден.")
			return 1
		}
		fmt.Fprintf(out, "Офлайн bundle: %s\nСетевая проверка обновлений пропущена.\n", offline.Bundle.Tarball)
		ok, e := menuConfirm(r, out, "Применить обновление из локального bundle?")
		if e != nil || !ok {
			return menuBack
		}
		mode, ok := menuChooseUpdateMode(r, out, offline.Bundle.AppArchive != "", offline.Bundle.ConfigArchive != "")
		if !ok {
			return menuBack
		}
		return cmdUpdate([]string{"-mode", mode}, out, errw)
	}
	u := deploy.New(a.Paths)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := u.CheckLatest(ctx)
	if err != nil {
		fmt.Fprintf(errw, "Проверка обновления: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Установлена версия %s\n", zator.Version())
	if res.Latest != nil {
		fmt.Fprintf(out, "Последний релиз: %s\n", res.Latest.Release)
	}
	fmt.Fprintf(out, "Обновление доступно: %t\n", res.UpdateAvailable())
	fmt.Fprintf(out, "Обновление шаблона конфигурации: %t\n", res.UpdateConfig)
	if !res.UpdateAvailable() {
		fmt.Fprintln(out, "Проверка завершена.")
		return menuBack
	}
	mode, ok := menuChooseUpdateMode(r, out, res.UpdateZator || res.UpdateWebUI, res.UpdateConfig)
	if !ok {
		return menuBack
	}
	ok, e := menuConfirm(r, out, "Создать резервную копию и установить обновление?")
	if e != nil || !ok {
		return menuBack
	}
	return cmdUpdate([]string{"-mode", mode}, out, errw)
}

func menuChooseUpdateMode(r *bufio.Reader, out io.Writer, appUpdate, configUpdate bool) (string, bool) {
	if appUpdate && configUpdate {
		choice, err := menuRead(r, out, "Что обновить: 1 — Zator и Web UI, 2 — ресурсы/шаблон, 3 — всё, 0 — отмена: ")
		if err != nil || choice == "0" {
			return "", false
		}
		switch choice {
		case "1":
			return deploy.ModeApp, true
		case "2":
			return deploy.ModeConfig, true
		case "3":
			return deploy.ModeFull, true
		default:
			fmt.Fprintln(out, "Некорректный выбор.")
			return "", false
		}
	}
	if configUpdate {
		return deploy.ModeConfig, true
	}
	if appUpdate {
		return deploy.ModeApp, true
	}
	return "", false
}
