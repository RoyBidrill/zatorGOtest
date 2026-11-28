package googlevideo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AloofLibra/zator/internal/fsutil"
)

// Параметры центрального списка (Z2R_GOOGLEVIDEO_*).
const (
	// ListHeaderPrefix — обязательное начало первой строки списка.
	ListHeaderPrefix = "# googlevideo IPv4; generated="
	// MaxListIPs — максимум адресов в списке.
	MaxListIPs = 8192
	// MaxListBytes — максимальный размер списка (256 КБ).
	MaxListBytes = 262144
	// DefaultCacheTTL — срок годности кеша (6 часов).
	DefaultCacheTTL = 6 * time.Hour
	// DefaultListURL — источник по умолчанию: пусто (только локальный
	// assets/lists/googlevideo-ipv4.txt). Удалённый feed — opt-in через
	// EnvListURL / CentralList.URL.
	DefaultListURL = ""
	// LegacyRemoteListURL — прежний публичный feed (только явным URL).
	LegacyRemoteListURL = "https://alooflibra.fun/z4r/googlevideo-ips.txt"
	// EnvListURL — переменная окружения с URL удалённого списка.
	EnvListURL = "Z2R_GOOGLEVIDEO_IPS_URL"
	// DefaultFetchTimeout — таймаут загрузки списка.
	DefaultFetchTimeout = 10 * time.Second
	// ListFileName — имя файла кеша в каталоге списков.
	ListFileName = "googlevideo-ipv4.txt"
)

// ListURLFromEnv возвращает URL центрального списка googlevideo IPv4:
// Z2R_GOOGLEVIDEO_IPS_URL если задан, иначе LegacyRemoteListURL (как в zator 1.6.0).
// Значения off|none|0|false|disabled отключают удалённый feed (только локальный файл).
func ListURLFromEnv() string {
	v := strings.TrimSpace(os.Getenv(EnvListURL))
	if v == "" {
		return LegacyRemoteListURL
	}
	switch strings.ToLower(v) {
	case "off", "none", "0", "false", "disabled":
		return ""
	default:
		return v
	}
}

// Ошибки проверки списка.
var (
	// ErrListEmpty — список пуст.
	ErrListEmpty = errors.New("googlevideo: список пуст")
	// ErrListTooLarge — размер списка больше MaxListBytes.
	ErrListTooLarge = errors.New("googlevideo: список больше 256 КБ")
	// ErrListHeader — первая строка не является заголовком googlevideo.
	ErrListHeader = errors.New("googlevideo: нет заголовка '# googlevideo IPv4; generated='")
	// ErrListAddress — некорректный или непубличный адрес.
	ErrListAddress = errors.New("googlevideo: некорректный адрес в списке")
	// ErrListCount — адресов больше MaxListIPs либо нет ни одного.
	ErrListCount = errors.New("googlevideo: недопустимое число адресов")
	// ErrFetch — не удалось получить список с сервера.
	ErrFetch = errors.New("googlevideo: не удалось загрузить список")
)

// List — разобранный центральный список.
type List struct {
	// Generated — значение поля generated= из заголовка (как есть, до «;»).
	Generated string
	// IPs — адреса в порядке файла.
	IPs []string
}

// Contains сообщает, что ip есть в списке.
func (l List) Contains(ip string) bool {
	for _, v := range l.IPs {
		if v == ip {
			return true
		}
	}
	return false
}

// ParseList проверяет и разбирает содержимое списка: размер ≤ 256 КБ, первая
// строка `# googlevideo IPv4; generated=…`, далее по одному публичному IPv4 в
// строке (пустые строки допустимы), не более 8192 адресов и хотя бы один
// (googlevideo_ips_validate). Строки комментариев после заголовка недопустимы.
func ParseList(data []byte) (List, error) {
	if len(data) == 0 {
		return List{}, ErrListEmpty
	}
	if len(data) > MaxListBytes {
		return List{}, ErrListTooLarge
	}
	// Разбиение строго по «\n»: «\r» остаётся в строке и отвергается как мусор.
	lines := strings.Split(string(data), "\n")
	header := lines[0]
	if !strings.HasPrefix(header, ListHeaderPrefix) {
		return List{}, ErrListHeader
	}
	list := List{Generated: header[len(ListHeaderPrefix):]}
	if i := strings.IndexByte(list.Generated, ';'); i >= 0 {
		list.Generated = list.Generated[:i]
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if !PublicIPv4(line) {
			return List{}, fmt.Errorf("%w: %q", ErrListAddress, truncate(line, 40))
		}
		if len(list.IPs) >= MaxListIPs {
			return List{}, fmt.Errorf("%w: больше %d", ErrListCount, MaxListIPs)
		}
		list.IPs = append(list.IPs, line)
	}
	if len(list.IPs) == 0 {
		return List{}, fmt.Errorf("%w: адресов нет", ErrListCount)
	}
	return list, nil
}

// ValidateList — ParseList без результата.
func ValidateList(data []byte) error {
	_, err := ParseList(data)
	return err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Статусы обновления центрального списка.
const (
	UpdateFresh   = "fresh"   // кеш свежий, сеть не трогали
	UpdateFetched = "fetched" // список скачан, проверен и сохранён
)

// UpdateResult — итог CentralList.Update.
type UpdateResult struct {
	Status string
	Count  int
	// Generated — поле generated= загруженного/кешированного списка ("" если кеш не разбирался).
	Generated string
}

// CentralList — кеш центрального списка googlevideo на диске.
type CentralList struct {
	// URL — источник (по умолчанию DefaultListURL).
	URL string
	// File — путь кеша (например <root>/lists/googlevideo-ipv4.txt).
	File string
	// TTL — срок годности кеша; 0 — DefaultCacheTTL, отрицательный — всегда
	// обновлять (Z2R_GOOGLEVIDEO_IPS_CACHE_TTL=0).
	TTL time.Duration
	// Client — HTTP-клиент (по умолчанию с таймаутом DefaultFetchTimeout).
	Client *http.Client
	// Now — источник времени (по умолчанию time.Now).
	Now func() time.Time
	// RequestPath — необязательный путь маркера попытки (например, в tmpfs).
	// По умолчанию используется File + ".request".
	RequestPath string
	// SkipFreshNotify отключает вызов OnUpdate при свежем кеше (или отключённом feed);
	// при реальной загрузке нового списка OnUpdate вызывается всегда.
	SkipFreshNotify bool
	// OnUpdate вызывается после замены кеша и (если SkipFreshNotify=false) при
	// свежем кеше с актуальным списком — для синхронизации набора ядра.
	OnUpdate func(ips []string) error

	mu sync.Mutex // сериализует Update

	setMu   sync.Mutex // кеш множества адресов для Contains
	set     map[string]struct{}
	setMod  time.Time
	setSize int64
}

func (c *CentralList) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *CentralList) url() string {
	return strings.TrimSpace(c.URL)
}

func (c *CentralList) ttl() time.Duration {
	if c.TTL == 0 {
		return DefaultCacheTTL
	}
	return c.TTL
}

func (c *CentralList) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: DefaultFetchTimeout}
}

// RequestFile — маркер последней попытки обновления: «epoch\nok|failed\n».
func (c *CentralList) RequestFile() string {
	if c.RequestPath != "" {
		return c.RequestPath
	}
	return c.File + ".request"
}

// Fresh сообщает, что кеш непуст и моложе TTL.
func (c *CentralList) Fresh() bool {
	st, err := os.Stat(c.File)
	if err != nil || st.Size() == 0 {
		return false
	}
	ttl := c.ttl()
	if ttl < 0 {
		return false
	}
	return c.now().Sub(st.ModTime()) < ttl
}

// Load читает и проверяет кеш с диска. Нет файла — пустой список без ошибки.
func (c *CentralList) Load() (List, error) {
	data, err := os.ReadFile(c.File)
	if errors.Is(err, os.ErrNotExist) {
		return List{}, nil
	}
	if err != nil {
		return List{}, err
	}
	return ParseList(data)
}

// IPs возвращает адреса кеша; непроверяемый файл даёт пустой результат.
func (c *CentralList) IPs() []string {
	l, err := c.Load()
	if err != nil {
		return nil
	}
	return l.IPs
}

// Count возвращает число адресов кеша (googlevideo_ips_count): считаются все
// строки, не начинающиеся с «#», с одним полем.
func (c *CentralList) Count() int {
	f, err := os.Open(c.File)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t := sc.Text()
		if strings.HasPrefix(t, "#") {
			continue
		}
		if len(strings.Fields(t)) == 1 {
			n++
		}
	}
	return n
}

// Contains сообщает, что ip есть в кеше (как grep -Fx по файлу: проверка
// списка не требуется). Множество адресов кешируется по времени и размеру файла.
func (c *CentralList) Contains(ip string) bool {
	st, err := os.Stat(c.File)
	if err != nil || st.Size() == 0 {
		return false
	}
	c.setMu.Lock()
	defer c.setMu.Unlock()
	if c.set == nil || !c.setMod.Equal(st.ModTime()) || c.setSize != st.Size() {
		set := map[string]struct{}{}
		if f, err := os.Open(c.File); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				t := strings.TrimSpace(sc.Text())
				if t != "" && !strings.HasPrefix(t, "#") && len(strings.Fields(t)) == 1 {
					set[t] = struct{}{}
				}
			}
			f.Close()
		}
		c.set, c.setMod, c.setSize = set, st.ModTime(), st.Size()
	}
	_, ok := c.set[ip]
	return ok
}

// Update обновляет кеш. Пока кеш свежий и force=false, сеть не используется.
// Загруженный список (≤ 256 КБ) проверяется, записывается атомарно и только
// после этого заменяет кеш; при ошибке прежний кеш остаётся, а маркер
// request получает «failed».
func (c *CentralList) Update(ctx context.Context, force bool) (UpdateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.File == "" {
		return UpdateResult{}, fmt.Errorf("googlevideo: не задан File")
	}
	if !force && c.Fresh() {
		res := UpdateResult{Status: UpdateFresh}
		if l, err := c.Load(); err == nil {
			res.Count, res.Generated = len(l.IPs), l.Generated
			if !c.SkipFreshNotify {
				c.notify(l.IPs)
			}
		} else {
			res.Count = c.Count()
		}
		return res, nil
	}

	// Без URL — только локальный файл из репозитория/ассетов (self-contained).
	if c.url() == "" {
		l, err := c.Load()
		if err != nil {
			return UpdateResult{}, err
		}
		if len(l.IPs) == 0 {
			return UpdateResult{}, fmt.Errorf("%w: удалённый источник отключён, локальный список пуст", ErrFetch)
		}
		if !c.SkipFreshNotify {
			c.notify(l.IPs)
		}
		return UpdateResult{Status: UpdateFresh, Count: len(l.IPs), Generated: l.Generated}, nil
	}

	list, err := c.fetch(ctx)
	if err != nil {
		c.writeRequest(false)
		return UpdateResult{}, err
	}
	// Сохраняем исходный вид: заголовок может содержать max_age и т.п.
	if err := fsutil.AtomicWriteFile(c.File, list.raw, 0o644); err != nil {
		c.writeRequest(false)
		return UpdateResult{}, err
	}
	c.writeRequest(true)
	c.setMu.Lock()
	c.set = nil
	c.setMu.Unlock()
	c.notify(list.IPs)
	return UpdateResult{Status: UpdateFetched, Count: len(list.IPs), Generated: list.Generated}, nil
}

type fetchedList struct {
	List
	raw []byte
}

func (c *CentralList) fetch(ctx context.Context) (fetchedList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(), nil)
	if err != nil {
		return fetchedList{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := c.client().Do(req)
	if err != nil {
		return fetchedList{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fetchedList{}, fmt.Errorf("%w: HTTP %d", ErrFetch, resp.StatusCode)
	}
	// +1 байт, чтобы отличить ровно 256 КБ от превышения.
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
	if err != nil {
		return fetchedList{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	list, err := ParseList(data)
	if err != nil {
		return fetchedList{}, err
	}
	return fetchedList{List: list, raw: data}, nil
}

func (c *CentralList) notify(ips []string) {
	if c.OnUpdate != nil {
		_ = c.OnUpdate(ips)
	}
}

func (c *CentralList) writeRequest(ok bool) {
	status := "failed"
	if ok {
		status = "ok"
	}
	reqPath := c.RequestFile()
	_ = os.MkdirAll(filepath.Dir(reqPath), 0o755)
	_ = fsutil.AtomicWriteFile(reqPath, []byte(strconv.FormatInt(c.now().Unix(), 10)+"\n"+status+"\n"), 0o644)
}

// RequestStatus читает маркер последней попытки обновления: время и
// признак успеха. ok=false при отсутствии маркера.
func (c *CentralList) RequestStatus() (at time.Time, success, ok bool) {
	b, err := os.ReadFile(c.RequestFile())
	if err != nil {
		return time.Time{}, false, false
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return time.Time{}, false, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil {
		return time.Time{}, false, false
	}
	return time.Unix(ts, 0), strings.TrimSpace(lines[1]) == "ok", true
}
