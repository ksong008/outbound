package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	tuiccommon "github.com/daeuniverse/outbound/protocol/tuic/common"
	transporttls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
)

type Dialer struct {
	uploadEndpoint   endpoint
	downloadEndpoint *endpoint
	mode             string
	contentType      string
	headers          http.Header
	packetMaxBytes   int
	packetMinGap     time.Duration
	xmux            xmuxOptions
}

type extraConfig struct {
	Headers          map[string]string       `json:"headers"`
	NoGRPCHeader     bool                    `json:"noGRPCHeader"`
	DownloadSettings *downloadSettingsConfig `json:"downloadSettings"`
	ScMaxEachPostBytes rangedInt             `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs rangedInt           `json:"scMinPostsIntervalMs"`
	Xmux             *xmuxConfig             `json:"xmux"`
}

type downloadSettingsConfig struct {
	Address       string               `json:"address"`
	Port          int                  `json:"port"`
	Network       string               `json:"network"`
	Security      string               `json:"security"`
	TLSSettings   tlsSettingsConfig    `json:"tlsSettings"`
	XHTTPSettings xhttpSettingsConfig  `json:"xhttpSettings"`
}

type tlsSettingsConfig struct {
	ServerName    string   `json:"serverName"`
	AllowInsecure bool     `json:"allowInsecure"`
	ALPN          []string `json:"alpn"`
	Fingerprint   string   `json:"fingerprint"`
}

type xhttpSettingsConfig struct {
	Host  string `json:"host"`
	Path  string `json:"path"`
	Mode  string `json:"mode"`
	Extra string `json:"extra"`
}

type endpoint struct {
	dialer          netproxy.Dialer
	nextDialer      netproxy.Dialer
	addr            string
	host            string
	path            string
	serverName      string
	allowInsecure   bool
	alpn            string
	utlsImitate     string
	useH3           bool
}

type xmuxConfig struct {
	MaxConcurrency rangedInt `json:"maxConcurrency"`
	CMaxReuseTimes rangedInt `json:"cMaxReuseTimes"`
}

type xmuxOptions struct {
	enabled        bool
	maxConcurrency int
	maxReuseTimes  int
}

type h2PoolEntry struct {
	rawConn        netproxy.Conn
	h2Conn         *http2.ClientConn
	active         int
	reuseCount     int
	maxConcurrency int
	maxReuseTimes  int
}

type h2Pool struct {
	mu      sync.Mutex
	entries map[string][]*h2PoolEntry
}

type pooledH2Lease struct {
	rawConn netproxy.Conn
	h2Conn  *http2.ClientConn
	release func() error
}

var globalPacketUploadPool = &h2Pool{
	entries: make(map[string][]*h2PoolEntry),
}

type rangedInt struct {
	set bool
	min int
	max int
}

func (r *rangedInt) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		return nil
	}
	if len(raw) > 0 && raw[0] == '"' {
		unquoted, err := strconv.Unquote(raw)
		if err != nil {
			return err
		}
		raw = strings.TrimSpace(unquoted)
	}
	if strings.Contains(raw, "-") {
		parts := strings.SplitN(raw, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid range %q", raw)
		}
		min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return err
		}
		max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return err
		}
		if max < min {
			min, max = max, min
		}
		r.set = true
		r.min = min
		r.max = max
		return nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return err
	}
	r.set = true
	r.min = value
	r.max = value
	return nil
}

func (r rangedInt) Pick() int {
	if !r.set {
		return 0
	}
	if r.max <= r.min {
		return r.min
	}
	return r.min + rand.IntN(r.max-r.min+1)
}

func normalizeMode(mode, scheme string) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "", "auto":
		if scheme == "https" {
			return "stream-up", nil
		}
		return "", fmt.Errorf("xhttp: auto mode without tls is not supported yet")
	case "stream-up":
		return mode, nil
	case "stream-one":
		if scheme == "https" {
			return mode, nil
		}
		return "", fmt.Errorf("xhttp: stream-one without tls is not supported yet")
	case "packet-up":
		if scheme == "https" {
			return mode, nil
		}
		return "", fmt.Errorf("xhttp: packet-up without tls is not supported yet")
	default:
		return "", fmt.Errorf("xhttp: unsupported mode %q", mode)
	}
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func shouldUseH3(alpn string) bool {
	parts := strings.Split(alpn, ",")
	if len(parts) != 1 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(parts[0]), "h3")
}

func parseExtra(raw string) (extraConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return extraConfig{}, nil
	}
	var cfg extraConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return extraConfig{}, fmt.Errorf("xhttp: parse extra: %w", err)
	}
	return cfg, nil
}

func parseXmux(cfg *xmuxConfig) xmuxOptions {
	if cfg == nil {
		return xmuxOptions{}
	}
	maxConcurrency := cfg.MaxConcurrency.Pick()
	maxReuseTimes := cfg.CMaxReuseTimes.Pick()
	if maxConcurrency <= 0 && maxReuseTimes <= 0 {
		return xmuxOptions{}
	}
	return xmuxOptions{
		enabled:        true,
		maxConcurrency: maxConcurrency,
		maxReuseTimes:  maxReuseTimes,
	}
}

func newTLSEndpoint(
	option *dialer.ExtraOption,
	nextDialer netproxy.Dialer,
	addr string,
	host string,
	path string,
	serverName string,
	allowInsecure bool,
	alpn string,
	utlsImitate string,
) (endpoint, error) {
	useH3 := shouldUseH3(alpn)
	if useH3 {
		return endpoint{
			nextDialer:    nextDialer,
			addr:          addr,
			host:          host,
			path:          normalizePath(path),
			serverName:    serverName,
			allowInsecure: allowInsecure,
			alpn:          alpn,
			utlsImitate:   utlsImitate,
			useH3:         true,
		}, nil
	}
	tlsURL := url.URL{
		Scheme: option.TlsImplementation,
		Host:   addr,
		RawQuery: url.Values{
			"sni":           []string{serverName},
			"allowInsecure": []string{strconv.FormatBool(allowInsecure)},
			"utlsImitate":   []string{utlsImitate},
			"alpn":          []string{alpn},
		}.Encode(),
	}
	if tlsURL.Scheme == "" {
		tlsURL.Scheme = "tls"
	}
	tlsDialer, _, err := transporttls.NewTls(option, nextDialer, tlsURL.String())
	if err != nil {
		return endpoint{}, err
	}
	return endpoint{
		dialer:        tlsDialer,
		nextDialer:    nextDialer,
		addr:          addr,
		host:          host,
		path:          normalizePath(path),
		serverName:    serverName,
		allowInsecure: allowInsecure,
		alpn:          alpn,
		utlsImitate:   utlsImitate,
	}, nil
}

func buildDownloadEndpoint(
	option *dialer.ExtraOption,
	nextDialer netproxy.Dialer,
	mainAddr string,
	mainHost string,
	mainPath string,
	mainServerName string,
	mainAllowInsecure bool,
	mainALPN string,
	mainUtlsImitate string,
	cfg *downloadSettingsConfig,
) (*endpoint, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Network != "" && !strings.EqualFold(cfg.Network, "xhttp") {
		return nil, fmt.Errorf("xhttp: downloadSettings network %q is not supported", cfg.Network)
	}
	if cfg.Security != "" && !strings.EqualFold(cfg.Security, "tls") {
		return nil, fmt.Errorf("xhttp: downloadSettings security %q is not supported", cfg.Security)
	}

	addr := mainAddr
	if cfg.Address != "" {
		port := cfg.Port
		if port == 0 {
			if _, portStr, err := net.SplitHostPort(mainAddr); err == nil {
				if parsed, convErr := strconv.Atoi(portStr); convErr == nil {
					port = parsed
				}
			}
		}
		addr = net.JoinHostPort(cfg.Address, strconv.Itoa(port))
	}

	host := mainHost
	if cfg.XHTTPSettings.Host != "" {
		host = cfg.XHTTPSettings.Host
	} else if cfg.Address != "" {
		host = cfg.Address
	}

	path := mainPath
	if cfg.XHTTPSettings.Path != "" {
		path = cfg.XHTTPSettings.Path
	}

	serverName := mainServerName
	if cfg.TLSSettings.ServerName != "" {
		serverName = cfg.TLSSettings.ServerName
	} else if host != "" {
		serverName = host
	}

	alpn := mainALPN
	if len(cfg.TLSSettings.ALPN) > 0 {
		alpn = strings.Join(cfg.TLSSettings.ALPN, ",")
	}

	utlsImitate := mainUtlsImitate
	if cfg.TLSSettings.Fingerprint != "" {
		utlsImitate = cfg.TLSSettings.Fingerprint
	}

	allowInsecure := mainAllowInsecure || cfg.TLSSettings.AllowInsecure

	ep, err := newTLSEndpoint(option, nextDialer, addr, host, path, serverName, allowInsecure, alpn, utlsImitate)
	if err != nil {
		return nil, err
	}
	return &ep, nil
}

func (d *Dialer) openH2Conn(ctx context.Context, ep endpoint) (netproxy.Conn, *http2.ClientConn, error) {
	rawConn, err := ep.dialer.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		return nil, nil, err
	}
	netConn := &netproxy.FakeNetConn{Conn: rawConn}

	h2Transport := &http2.Transport{}
	h2ClientConn, err := h2Transport.NewClientConn(netConn)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}
	return rawConn, h2ClientConn, nil
}

type requestRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

type requestClient struct {
	rawConn netproxy.Conn
	rt      requestRoundTripper
	closeFn func() error
}

func (c *requestClient) Close() error {
	if c.closeFn != nil {
		return c.closeFn()
	}
	if c.rawConn != nil {
		return c.rawConn.Close()
	}
	return nil
}

func (d *Dialer) openRequestClient(ctx context.Context, ep endpoint, network string) (*requestClient, error) {
	if !ep.useH3 {
		rawConn, h2Conn, err := d.openH2Conn(ctx, ep)
		if err != nil {
			return nil, err
		}
		return &requestClient{
			rawConn: rawConn,
			rt:      h2Conn,
			closeFn: func() error { return rawConn.Close() },
		}, nil
	}

	rAddr, err := net.ResolveUDPAddr("udp", ep.addr)
	if err != nil {
		return nil, err
	}
	var fakeConn net.PacketConn
	tlsCfg := &tls.Config{
		ServerName:         ep.serverName,
		InsecureSkipVerify: ep.allowInsecure,
		NextProtos:         []string{"h3"},
	}
	quicCfg := &quic.Config{
		EnableDatagrams: true,
	}
	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicCfg,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpNetwork := netproxy.MagicNetwork{Network: "udp"}.Encode()
			if magicNetwork, err := netproxy.ParseMagicNetwork(network); err == nil {
				udpNetwork = netproxy.MagicNetwork{Network: "udp", Mark: magicNetwork.Mark}.Encode()
			}
			conn, err := ep.nextDialer.DialContext(ctx, udpNetwork, ep.addr)
			if err != nil {
				return nil, err
			}
			pc, ok := conn.(netproxy.PacketConn)
			if !ok {
				conn.Close()
				return nil, fmt.Errorf("xhttp: H3 requires PacketConn for %s", ep.addr)
			}
			fakeConn = netproxy.NewFakeNetPacketConn(
				pc,
				net.UDPAddrFromAddrPort(tuiccommon.GetUniqueFakeAddrPort()),
				rAddr,
			)
			return quic.DialEarly(ctx, fakeConn, rAddr, tlsCfg, cfg)
		},
	}
	return &requestClient{
		rt: rt,
		closeFn: func() error {
			err := rt.Close()
			if fakeConn != nil {
				_ = fakeConn.Close()
			}
			return err
		},
	}, nil
}

func endpointPoolKey(ep endpoint) string {
	return ep.addr + "|" + ep.host + "|" + ep.path
}

func (p *h2Pool) acquire(ctx context.Context, ep endpoint, opts xmuxOptions, opener func(context.Context, endpoint) (netproxy.Conn, *http2.ClientConn, error)) (*pooledH2Lease, error) {
	if !opts.enabled {
		rawConn, h2Conn, err := opener(ctx, ep)
		if err != nil {
			return nil, err
		}
		return &pooledH2Lease{
			rawConn: rawConn,
			h2Conn:  h2Conn,
			release: func() error { return rawConn.Close() },
		}, nil
	}

	key := endpointPoolKey(ep)
	p.mu.Lock()
	for _, entry := range p.entries[key] {
		if !entry.h2Conn.CanTakeNewRequest() {
			continue
		}
		if entry.maxConcurrency > 0 && entry.active >= entry.maxConcurrency {
			continue
		}
		if entry.maxReuseTimes > 0 && entry.reuseCount >= entry.maxReuseTimes {
			continue
		}
		entry.active++
		entry.reuseCount++
		p.mu.Unlock()
		return &pooledH2Lease{
			rawConn: entry.rawConn,
			h2Conn:  entry.h2Conn,
			release: func() error { return p.release(key, entry) },
		}, nil
	}
	p.mu.Unlock()

	rawConn, h2Conn, err := opener(ctx, ep)
	if err != nil {
		return nil, err
	}
	entry := &h2PoolEntry{
		rawConn:        rawConn,
		h2Conn:         h2Conn,
		active:         1,
		reuseCount:     1,
		maxConcurrency: opts.maxConcurrency,
		maxReuseTimes:  opts.maxReuseTimes,
	}
	p.mu.Lock()
	p.entries[key] = append(p.entries[key], entry)
	p.mu.Unlock()
	return &pooledH2Lease{
		rawConn: rawConn,
		h2Conn:  h2Conn,
		release: func() error { return p.release(key, entry) },
	}, nil
}

func (p *h2Pool) release(key string, entry *h2PoolEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.active > 0 {
		entry.active--
	}
	shouldClose := !entry.h2Conn.CanTakeNewRequest() || (entry.maxReuseTimes > 0 && entry.reuseCount >= entry.maxReuseTimes && entry.active == 0)
	if shouldClose && entry.active == 0 {
		entries := p.entries[key]
		for i, candidate := range entries {
			if candidate == entry {
				p.entries[key] = append(entries[:i], entries[i+1:]...)
				break
			}
		}
		if len(p.entries[key]) == 0 {
			delete(p.entries, key)
		}
		return entry.rawConn.Close()
	}
	return nil
}

func NewDialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	mode, err := normalizeMode(query.Get("mode"), u.Scheme)
	if err != nil {
		return nil, err
	}
	extra, err := parseExtra(query.Get("extra"))
	if err != nil {
		return nil, err
	}

	host := query.Get("host")
	if host == "" {
		host = u.Hostname()
	}
	serverName := query.Get("sni")
	if serverName == "" {
		serverName = host
	}
	alpn := query.Get("alpn")
	if alpn == "" {
		alpn = "h2"
	}

	allowInsecure := query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1"
	utlsImitate := query.Get("utlsImitate")

	uploadEndpoint, err := newTLSEndpoint(option, nextDialer, u.Host, host, u.Path, serverName, allowInsecure, alpn, utlsImitate)
	if err != nil {
		return nil, err
	}
	downloadEndpoint, err := buildDownloadEndpoint(option, nextDialer, u.Host, host, u.Path, serverName, allowInsecure, alpn, utlsImitate, extra.DownloadSettings)
	if err != nil {
		return nil, err
	}

	headers := make(http.Header)
	for key, value := range extra.Headers {
		headers.Set(key, value)
	}

	contentType := "application/grpc"
	if extra.NoGRPCHeader {
		contentType = ""
	}

	return &Dialer{
		uploadEndpoint:   uploadEndpoint,
		downloadEndpoint: downloadEndpoint,
		mode:             mode,
		contentType:      contentType,
		headers:          headers,
		packetMaxBytes:   extra.ScMaxEachPostBytes.Pick(),
		packetMinGap:     time.Duration(extra.ScMinPostsIntervalMs.Pick()) * time.Millisecond,
		xmux:             parseXmux(extra.Xmux),
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, fmt.Errorf("%w: xhttp+%s", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
	uploadClient, err := d.openRequestClient(ctx, d.uploadEndpoint, network)
	if err != nil {
		return nil, err
	}
	downloadEndpoint := d.uploadEndpoint
	if d.downloadEndpoint != nil {
		downloadEndpoint = *d.downloadEndpoint
	}

	sessionID := uuid.NewString()
	uploadTargetURL := (&url.URL{
		Scheme: "https",
		Host:   d.uploadEndpoint.addr,
		Path:   strings.TrimRight(d.uploadEndpoint.path, "/") + "/" + sessionID,
	}).String()
	downloadTargetURL := (&url.URL{
		Scheme: "https",
		Host:   downloadEndpoint.addr,
		Path:   strings.TrimRight(downloadEndpoint.path, "/") + "/" + sessionID,
	}).String()

	switch d.mode {
	case "stream-up":
		downloadClient := uploadClient
		if d.downloadEndpoint != nil {
			downloadClient, err = d.openRequestClient(ctx, downloadEndpoint, network)
			if err != nil {
				_ = uploadClient.Close()
				return nil, err
			}
		}

		downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		downloadReq.Header = d.headers.Clone()
		downloadResp, err := downloadClient.rt.RoundTrip(downloadReq)
		if err != nil {
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, err
		}
		if downloadResp.StatusCode != http.StatusOK {
			downloadResp.Body.Close()
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, fmt.Errorf("xhttp: download path returned %s", downloadResp.Status)
		}

		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadTargetURL, pr)
		if err != nil {
			downloadResp.Body.Close()
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		uploadReq.Header = d.headers.Clone()
		if d.contentType != "" {
			uploadReq.Header.Set("Content-Type", d.contentType)
		}

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: downloadClient.rawConn,
			uploadRelease: uploadClient.Close,
			downloadRelease: downloadClient.Close,
			sharedRelease: uploadClient == downloadClient,
			uploadBody:   pw,
			downloadBody: downloadResp.Body,
		}
		go conn.finishUpload(uploadClient.rt, uploadReq)
		return conn, nil
	case "stream-one":
		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadTargetURL, pr)
		if err != nil {
			_ = uploadClient.Close()
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		uploadReq.Header = d.headers.Clone()
		if d.contentType != "" {
			uploadReq.Header.Set("Content-Type", d.contentType)
		}

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: uploadClient.rawConn,
			uploadRelease: uploadClient.Close,
			downloadRelease: uploadClient.Close,
			sharedRelease: true,
			uploadBody:   pw,
			respCh:       make(chan responseResult, 1),
		}
		go conn.startStreamOne(uploadClient.rt, uploadReq)
		return conn, nil
	case "packet-up":
		downloadClient := uploadClient
		if d.downloadEndpoint != nil {
			downloadClient, err = d.openRequestClient(ctx, downloadEndpoint, network)
			if err != nil {
				_ = uploadClient.Close()
				return nil, err
			}
		}

		downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		downloadReq.Header = d.headers.Clone()
		downloadResp, err := downloadClient.rt.RoundTrip(downloadReq)
		if err != nil {
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, err
		}
		if downloadResp.StatusCode != http.StatusOK {
			downloadResp.Body.Close()
			_ = uploadClient.Close()
			if downloadClient != uploadClient {
				_ = downloadClient.Close()
			}
			return nil, fmt.Errorf("xhttp: download path returned %s", downloadResp.Status)
		}

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: downloadClient.rawConn,
			uploadRelease: uploadClient.Close,
			downloadRelease: downloadClient.Close,
			sharedRelease: uploadClient == downloadClient,
			downloadBody: downloadResp.Body,
			packetUpload: d.buildPacketUploader(uploadClient.rt, uploadTargetURL),
		}
		if d.xmux.enabled && !d.uploadEndpoint.useH3 {
			_ = uploadClient.Close()
			lease, err := globalPacketUploadPool.acquire(ctx, d.uploadEndpoint, d.xmux, d.openH2Conn)
			if err != nil {
				conn.Close()
				return nil, err
			}
			conn.uploadConn = nil
			conn.uploadRelease = lease.release
			conn.packetUpload = d.buildPacketUploader(lease.h2Conn, uploadTargetURL)
		}
		return conn, nil
	default:
		_ = uploadClient.Close()
		return nil, fmt.Errorf("xhttp: mode %q is not supported yet", d.mode)
	}
}

func (d *Dialer) buildPacketUploader(uploadRT requestRoundTripper, uploadTargetURL string) func([]byte) error {
	return func(p []byte) error {
		chunks := [][]byte{p}
		if d.packetMaxBytes > 0 && len(p) > d.packetMaxBytes {
			chunks = make([][]byte, 0, (len(p)+d.packetMaxBytes-1)/d.packetMaxBytes)
			for start := 0; start < len(p); start += d.packetMaxBytes {
				end := start + d.packetMaxBytes
				if end > len(p) {
					end = len(p)
				}
				chunks = append(chunks, p[start:end])
			}
		}

		for i, chunk := range chunks {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, uploadTargetURL, bytes.NewReader(chunk))
			if err != nil {
				return err
			}
			req.Host = d.uploadEndpoint.host
			req.Header = d.headers.Clone()
			if d.contentType != "" {
				req.Header.Set("Content-Type", d.contentType)
			}
				resp, err := uploadRT.RoundTrip(req)
			if err != nil {
				return err
			}
			func() {
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
			}()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("xhttp: packet-up path returned %s", resp.Status)
			}
			if i != len(chunks)-1 && d.packetMinGap > 0 {
				time.Sleep(d.packetMinGap)
			}
		}
		return nil
	}
}

type Conn struct {
	uploadConn   netproxy.Conn
	downloadConn netproxy.Conn
	uploadRelease func() error
	downloadRelease func() error
	sharedRelease bool
	uploadBody   *io.PipeWriter
	downloadBody io.ReadCloser
	packetUpload func([]byte) error

	closeOnce sync.Once
	uploadErr error
	respCh    chan responseResult
	writeMu   sync.Mutex
}

type responseResult struct {
	body io.ReadCloser
	err  error
}

func (c *Conn) finishUpload(rt requestRoundTripper, req *http.Request) {
	resp, err := rt.RoundTrip(req)
	if err != nil {
		c.uploadErr = err
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		c.uploadErr = fmt.Errorf("xhttp: upload path returned %s", resp.Status)
	}
}

func (c *Conn) startStreamOne(rt requestRoundTripper, req *http.Request) {
	resp, err := rt.RoundTrip(req)
	if err != nil {
		c.respCh <- responseResult{err: err}
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		c.respCh <- responseResult{err: fmt.Errorf("xhttp: stream-one path returned %s", resp.Status)}
		return
	}
	c.respCh <- responseResult{body: resp.Body}
}

func (c *Conn) ensureDownloadBody() error {
	if c.downloadBody != nil || c.respCh == nil {
		return nil
	}
	result := <-c.respCh
	if result.err != nil {
		c.uploadErr = result.err
		return result.err
	}
	c.downloadBody = result.body
	return nil
}

func (c *Conn) Read(p []byte) (n int, err error) {
	if err := c.ensureDownloadBody(); err != nil {
		return 0, err
	}
	return c.downloadBody.Read(p)
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if c.uploadErr != nil {
		return 0, c.uploadErr
	}
	if c.packetUpload != nil {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		buf := append([]byte(nil), p...)
		if err := c.packetUpload(buf); err != nil {
			c.uploadErr = err
			return 0, err
		}
		return len(p), nil
	}
	return c.uploadBody.Write(p)
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.uploadBody != nil {
			_ = c.uploadBody.Close()
		}
		if c.downloadBody != nil {
			_ = c.downloadBody.Close()
		}
		if c.uploadRelease != nil {
			err = c.uploadRelease()
		} else if c.uploadConn != nil {
			err = c.uploadConn.Close()
		}
			if c.downloadRelease != nil && !c.sharedRelease {
				_ = c.downloadRelease()
			} else if c.downloadConn != nil && c.downloadConn != c.uploadConn {
				_ = c.downloadConn.Close()
		}
	})
	return err
}

func (c *Conn) SetDeadline(t time.Time) error {
	var err error
	if c.uploadConn != nil {
		err = c.uploadConn.SetDeadline(t)
	}
	if c.downloadConn != nil && c.downloadConn != c.uploadConn {
		if derr := c.downloadConn.SetDeadline(t); err == nil {
			err = derr
		}
	}
	return err
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.downloadConn == nil {
		return nil
	}
	return c.downloadConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.uploadConn == nil {
		return nil
	}
	return c.uploadConn.SetWriteDeadline(t)
}
