package xhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	transporttls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
)

type Dialer struct {
	uploadEndpoint   endpoint
	downloadEndpoint *endpoint
	mode             string
	contentType      string
	headers          http.Header
}

type extraConfig struct {
	Headers          map[string]string       `json:"headers"`
	NoGRPCHeader     bool                    `json:"noGRPCHeader"`
	DownloadSettings *downloadSettingsConfig `json:"downloadSettings"`
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
	dialer netproxy.Dialer
	addr   string
	host   string
	path   string
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
		dialer: tlsDialer,
		addr:   addr,
		host:   host,
		path:   normalizePath(path),
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
	uploadRawConn, uploadH2Conn, err := d.openH2Conn(ctx, d.uploadEndpoint)
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
		downloadRawConn := uploadRawConn
		downloadH2Conn := uploadH2Conn
		if d.downloadEndpoint != nil {
			downloadRawConn, downloadH2Conn, err = d.openH2Conn(ctx, downloadEndpoint)
			if err != nil {
				uploadRawConn.Close()
				return nil, err
			}
		}

		downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		downloadReq.Header = d.headers.Clone()
		downloadResp, err := downloadH2Conn.RoundTrip(downloadReq)
		if err != nil {
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, err
		}
		if downloadResp.StatusCode != http.StatusOK {
			downloadResp.Body.Close()
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, fmt.Errorf("xhttp: download path returned %s", downloadResp.Status)
		}

		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadTargetURL, pr)
		if err != nil {
			downloadResp.Body.Close()
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		uploadReq.Header = d.headers.Clone()
		if d.contentType != "" {
			uploadReq.Header.Set("Content-Type", d.contentType)
		}

		conn := &Conn{
			uploadConn:   uploadRawConn,
			downloadConn: downloadRawConn,
			uploadBody:   pw,
			downloadBody: downloadResp.Body,
		}
		go conn.finishUpload(uploadH2Conn, uploadReq)
		return conn, nil
	case "stream-one":
		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadTargetURL, pr)
		if err != nil {
			uploadRawConn.Close()
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		uploadReq.Header = d.headers.Clone()
		if d.contentType != "" {
			uploadReq.Header.Set("Content-Type", d.contentType)
		}

		conn := &Conn{
			uploadConn:   uploadRawConn,
			downloadConn: uploadRawConn,
			uploadBody:   pw,
			respCh:       make(chan responseResult, 1),
		}
		go conn.startStreamOne(uploadH2Conn, uploadReq)
		return conn, nil
	case "packet-up":
		downloadRawConn := uploadRawConn
		downloadH2Conn := uploadH2Conn
		if d.downloadEndpoint != nil {
			downloadRawConn, downloadH2Conn, err = d.openH2Conn(ctx, downloadEndpoint)
			if err != nil {
				uploadRawConn.Close()
				return nil, err
			}
		}

		downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		downloadReq.Header = d.headers.Clone()
		downloadResp, err := downloadH2Conn.RoundTrip(downloadReq)
		if err != nil {
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, err
		}
		if downloadResp.StatusCode != http.StatusOK {
			downloadResp.Body.Close()
			uploadRawConn.Close()
			if downloadRawConn != uploadRawConn {
				downloadRawConn.Close()
			}
			return nil, fmt.Errorf("xhttp: download path returned %s", downloadResp.Status)
		}

		conn := &Conn{
			uploadConn:   uploadRawConn,
			downloadConn: downloadRawConn,
			downloadBody: downloadResp.Body,
			packetUpload: func(p []byte) error {
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, uploadTargetURL, bytes.NewReader(p))
				if err != nil {
					return err
				}
				req.Host = d.uploadEndpoint.host
				req.Header = d.headers.Clone()
				if d.contentType != "" {
					req.Header.Set("Content-Type", d.contentType)
				}
				resp, err := uploadH2Conn.RoundTrip(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("xhttp: packet-up path returned %s", resp.Status)
				}
				return nil
			},
		}
		return conn, nil
	default:
		uploadRawConn.Close()
		return nil, fmt.Errorf("xhttp: mode %q is not supported yet", d.mode)
	}
}

type Conn struct {
	uploadConn   netproxy.Conn
	downloadConn netproxy.Conn
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

func (c *Conn) finishUpload(h2 *http2.ClientConn, req *http.Request) {
	resp, err := h2.RoundTrip(req)
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

func (c *Conn) startStreamOne(h2 *http2.ClientConn, req *http.Request) {
	resp, err := h2.RoundTrip(req)
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
		if c.uploadConn != nil {
			err = c.uploadConn.Close()
		}
		if c.downloadConn != nil && c.downloadConn != c.uploadConn {
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
