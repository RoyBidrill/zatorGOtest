package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Методы пробы версии TLS.
const (
	MethodGET  = "GET"
	MethodHEAD = "HEAD"
)

const maxRedirects = 10

var errTooManyRedirects = errors.New("netcheck: too many redirects")

// Options — параметры проб (переменные Z2R_TLS_* из netcheck.sh).
type Options struct {
	// ConnectTimeout — таймаут установления TCP (по умолчанию 3 с).
	ConnectTimeout time.Duration
	// MaxTime — полный таймаут пробы версии TLS (по умолчанию 10 с для WSSIZE).
	MaxTime time.Duration
	// DownloadMaxTime — полный таймаут докачки (по умолчанию 10 с).
	DownloadMaxTime time.Duration
	// DownloadStall — простой потока после начала тела, после которого
	// докачка прерывается (аналог --speed-limit/--speed-time; по умолчанию 1 с).
	DownloadStall time.Duration
	// DownloadRange — сколько байт докачивать (по умолчанию 64 КБ).
	DownloadRange int
	// InsecureSkipVerify отключает проверку сертификата (curl -k): на роутерах
	// нет CA-бандла, а DPI-тесты интересует только транспорт.
	InsecureSkipVerify bool
	// RootCAs — корневые сертификаты для проверки (по умолчанию системные).
	RootCAs *x509.CertPool
	// UserAgent — заголовок User-Agent.
	UserAgent string
	// Method — GET (по умолчанию; читаются только заголовки) или HEAD.
	Method string
	// ProbeGap — задержка старта TLS 1.3 после TLS 1.2: одновременные
	// попытки обеих версий ТСПУ читает как сканер (Z2R_TLS_PROBE_GAP).
	ProbeGap time.Duration
	// WaitBoth — дожидаться обеих версий; иначе вторая проба добивается,
	// как только первая получила 2xx/3xx (Z2R_TLS_WAIT_BOTH).
	WaitBoth bool
	// AllowIPv6 разрешает IPv6 (по умолчанию только IPv4, как curl -4).
	AllowIPv6 bool
	// DialContext подменяет установку соединения (тесты, привязка к порту).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (o Options) withDefaults() Options {
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.MaxTime <= 0 {
		o.MaxTime = DefaultMaxTime
	}
	if o.DownloadMaxTime <= 0 {
		o.DownloadMaxTime = DefaultDownloadMaxTime
	}
	if o.DownloadStall <= 0 {
		o.DownloadStall = DefaultDownloadStall
	}
	if o.DownloadRange <= 0 {
		o.DownloadRange = DefaultDownloadRange
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	if strings.EqualFold(o.Method, MethodHEAD) {
		o.Method = MethodHEAD
	} else {
		o.Method = MethodGET
	}
	return o
}

// connState запоминает, состоялось ли TCP-соединение и с кем.
type connState struct {
	connected atomic.Bool
	mu        sync.Mutex
	ip        string
}

func (s *connState) remoteIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip
}

func (o Options) transport(minV, maxV uint16, st *connState) *http.Transport {
	dialer := &net.Dialer{Timeout: o.ConnectTimeout}
	inner := o.DialContext
	if inner == nil {
		inner = dialer.DialContext
	}
	allowV6 := o.AllowIPv6
	return &http.Transport{
		Proxy: nil, // как --noproxy '*'
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !allowV6 && network == "tcp" {
				network = "tcp4"
			}
			c, err := inner(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			st.connected.Store(true)
			if host, _, e := net.SplitHostPort(c.RemoteAddr().String()); e == nil {
				st.mu.Lock()
				st.ip = host
				st.mu.Unlock()
			}
			return c, nil
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         minV,
			MaxVersion:         maxV,
			RootCAs:            o.RootCAs,
			InsecureSkipVerify: o.InsecureSkipVerify, //nolint:gosec // осознанно: DPI-тест, см. Options.
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: o.MaxTime,
		// Keep-alives are closed explicitly per probe via tr.CloseIdleConnections();
		// omitting DisableKeepAlives avoids Connection: close so HTTP/1.1 servers
		// do not close the TCP socket mid-read (WSAECONNRESET on Windows loopback).
		DisableCompression: true,
	}
}

func (o Options) client(tr *http.Transport) *http.Client {
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errTooManyRedirects
			}
			return nil
		},
	}
}

func tlsBounds(v TLSVersion) (minV, maxV uint16, ok bool) {
	switch v {
	case TLS12:
		return tls.VersionTLS12, tls.VersionTLS12, true
	case TLS13:
		return tls.VersionTLS13, tls.VersionTLS13, true
	}
	return 0, 0, false
}

// classify сопоставляет ошибку Go классам кодов возврата curl.
func classify(err error, connected bool) ErrKind {
	if err == nil {
		return ErrNone
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return ErrTimeout
		}
		return ErrDNS
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return ErrTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ErrAborted
	}
	if errors.Is(err, errTooManyRedirects) {
		return ErrOther
	}
	if !connected {
		return ErrConn
	}
	return ErrTLS
}

// VersionState — z2r_tls_version_state: состояние версии по коду/ошибке.
func VersionState(code int, kind ErrKind) string {
	if code != 0 {
		if CodeOK(code) {
			return StateOK
		}
		return StateHTTP
	}
	switch kind {
	case ErrAborted:
		return StateAborted
	case ErrDNS:
		return StateDNS
	case ErrTimeout:
		return StateTimeout
	case ErrConn:
		return StateConn
	case ErrTLS:
		return StateTLS
	}
	return StateNone
}

func protoName(r *http.Response) string {
	switch {
	case r.ProtoMajor == 2:
		return "HTTP/2"
	case r.ProtoMajor == 3:
		return "HTTP/3"
	case r.Proto != "":
		return r.Proto
	}
	return "-"
}

// ProbeVersion выполняет одну пробу: GET/HEAD к rawURL, зафиксировав версию
// TLS, с редиректами. Тело не читается (HEAD-подобный запрос).
func ProbeVersion(ctx context.Context, rawURL string, ver TLSVersion, opts Options) VersionDetail {
	opts = opts.withDefaults()
	d := VersionDetail{Proto: "-", Time: "-", IP: "-"}
	minV, maxV, ok := tlsBounds(ver)
	if !ok {
		d.State = StateUnsupported
		d.Text = describeVersion(ver, d, opts)
		return d
	}
	if ctx.Err() != nil {
		d.Err = ErrAborted
		d.State = StateAborted
		d.Text = describeVersion(ver, d, opts)
		return d
	}

	ctx, cancel := context.WithTimeout(ctx, opts.MaxTime)
	defer cancel()
	st := &connState{}
	tr := opts.transport(minV, maxV, st)
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, opts.Method, rawURL, nil)
	if err != nil {
		d.Err = ErrOther
		d.State = StateNone
		d.Text = describeVersion(ver, d, opts)
		return d
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := opts.client(tr).Do(req)
	elapsed := time.Since(start)
	if err != nil {
		d.Err = classify(err, st.connected.Load())
		if ip := st.remoteIP(); ip != "" {
			d.IP = ip
		}
		d.State = VersionState(0, d.Err)
		d.Text = describeVersion(ver, d, opts)
		return d
	}
	_ = resp.Body.Close()
	d.Code = resp.StatusCode
	d.Proto = protoName(resp)
	d.Time = formatSeconds(elapsed)
	if ip := st.remoteIP(); ip != "" {
		d.IP = ip
	}
	d.State = VersionState(d.Code, ErrNone)
	d.Text = describeVersion(ver, d, opts)
	return d
}

// ProbeDownload докачивает до opts.DownloadRange байт (Range-запрос;
// сервер может Range проигнорировать — читается не более лимита). Простой
// потока дольше opts.DownloadStall прерывает чтение (поток срезан DPI).
func ProbeDownload(ctx context.Context, rawURL string, opts Options) Download {
	opts = opts.withDefaults()
	out := Download{Time: "-"}
	finish := func() Download {
		out.State = DownloadState(out.Err, out.Code, out.Size)
		out.Text = describeDownload(out, opts)
		return out
	}
	if ctx.Err() != nil {
		out.Err = ErrAborted
		return finish()
	}

	tctx, tcancel := context.WithTimeout(ctx, opts.DownloadMaxTime)
	defer tcancel()
	rctx, rcancel := context.WithCancel(tctx)
	defer rcancel()

	// Для докачки версия TLS не фиксируется: 1.2 — 1.3.
	st := &connState{}
	tr := opts.transport(tls.VersionTLS12, tls.VersionTLS13, st)
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		out.Err = ErrOther
		return finish()
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", opts.DownloadRange-1))

	start := time.Now()
	resp, err := opts.client(tr).Do(req)
	if err != nil {
		out.Err = classify(err, st.connected.Load())
		out.Time = formatSeconds(time.Since(start))
		return finish()
	}
	defer resp.Body.Close()
	out.Code = resp.StatusCode

	var stalled atomic.Bool
	stall := time.AfterFunc(opts.DownloadStall, func() {
		stalled.Store(true)
		rcancel()
	})
	defer stall.Stop()

	buf := make([]byte, 8192)
	for out.Size < opts.DownloadRange {
		limit := opts.DownloadRange - out.Size
		if limit > len(buf) {
			limit = len(buf)
		}
		n, rerr := resp.Body.Read(buf[:limit])
		if n > 0 {
			out.Size += n
			stall.Reset(opts.DownloadStall)
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				switch {
				case stalled.Load():
					out.Err = ErrTimeout
				case ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled):
					out.Err = ErrAborted
				default:
					out.Err = classify(rerr, true)
					if out.Err == ErrNone || out.Err == ErrAborted {
						out.Err = ErrTLS
					}
				}
			}
			break
		}
	}
	out.Time = formatSeconds(time.Since(start))
	return finish()
}

// DownloadState — z2r_tls_download_state.
func DownloadState(kind ErrKind, code, size int) string {
	if code == 206 || CodeOK(code) {
		if size > 0 {
			if kind == ErrNone {
				return DLOK
			}
			return DLCut
		}
		return DLZero
	}
	if kind == ErrNone {
		return DLZero
	}
	return DLFail
}
