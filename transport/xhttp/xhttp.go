package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
	xmux             xmuxOptions
	noSSEHeader      bool
	scMaxBufferedPosts int
	xPaddingBytes    rangedInt
	xPaddingObfsMode bool
	xPaddingKey      string
	xPaddingHeader   string
	xPaddingPlacement string
	xPaddingMethod   string
	uplinkHTTPMethod string
	sessionPlacement string
	sessionKey       string
	seqPlacement     string
	seqKey           string
	uplinkDataPlacement string
	uplinkDataKey       string
	uplinkChunkSize     rangedInt
}

type XHTTPOptions struct {
	Mode                 string
	Headers              http.Header
	ContentType          string
	DownloadSettings     *downloadSettingsConfig
	PacketMaxBytes       int
	PacketMinGap         time.Duration
	Xmux                 xmuxOptions
	NoSSEHeader          bool
	ScMaxBufferedPosts   int
	XPaddingBytes        rangedInt
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      rangedInt
}

func (o *XHTTPOptions) validate() error {
	if o == nil {
		return nil
	}
	if o.Mode == "stream-one" && o.DownloadSettings != nil {
		return fmt.Errorf("xhttp: stream-one does not support downloadSettings")
	}
	if o.NoSSEHeader {
		return fmt.Errorf("xhttp: noSSEHeader is not supported yet")
	}
	if o.ScMaxBufferedPosts > 0 {
		return fmt.Errorf("xhttp: scMaxBufferedPosts is not supported yet")
	}
	if o.DownloadSettings != nil && o.DownloadSettings.XHTTPSettings.Mode != "" {
		return fmt.Errorf("xhttp: downloadSettings.xhttpSettings.mode is not supported yet")
	}
	if o.DownloadSettings != nil && strings.TrimSpace(o.DownloadSettings.XHTTPSettings.Extra) != "" {
		return fmt.Errorf("xhttp: downloadSettings.xhttpSettings.extra is not supported yet")
	}
	return nil
}

type extraConfig struct {
	Headers          map[string]string       `json:"headers"`
	NoGRPCHeader     bool                    `json:"noGRPCHeader"`
	DownloadSettings *downloadSettingsConfig `json:"downloadSettings"`
	ScMaxEachPostBytes rangedInt             `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs rangedInt           `json:"scMinPostsIntervalMs"`
	Xmux             *xmuxConfig             `json:"xmux"`
	XPaddingBytes    rangedInt               `json:"xPaddingBytes"`
	XPaddingObfsMode bool                    `json:"xPaddingObfsMode"`
	XPaddingKey      string                  `json:"xPaddingKey"`
	XPaddingHeader   string                  `json:"xPaddingHeader"`
	XPaddingPlacement string                 `json:"xPaddingPlacement"`
	XPaddingMethod   string                  `json:"xPaddingMethod"`
	NoSSEHeader      bool                    `json:"noSSEHeader"`
	ScMaxBufferedPosts int                   `json:"scMaxBufferedPosts"`
	UplinkHTTPMethod string                  `json:"uplinkHTTPMethod"`
	SessionPlacement string                  `json:"sessionPlacement"`
	SessionKey       string                  `json:"sessionKey"`
	SeqPlacement     string                  `json:"seqPlacement"`
	SeqKey           string                  `json:"seqKey"`
	UplinkDataPlacement string               `json:"uplinkDataPlacement"`
	UplinkDataKey       string               `json:"uplinkDataKey"`
	UplinkChunkSize     rangedInt            `json:"uplinkChunkSize"`
}

type downloadSettingsConfig struct {
	Address       string               `json:"address"`
	Port          int                  `json:"port"`
	Network       string               `json:"network"`
	Security      string               `json:"security"`
	TLSSettings   tlsSettingsConfig    `json:"tlsSettings"`
	RealitySettings realitySettingsConfig `json:"realitySettings"`
	XHTTPSettings xhttpSettingsConfig  `json:"xhttpSettings"`
}

type tlsSettingsConfig struct {
	ServerName    string   `json:"serverName"`
	AllowInsecure bool     `json:"allowInsecure"`
	ALPN          []string `json:"alpn"`
	Fingerprint   string   `json:"fingerprint"`
}

type realitySettingsConfig struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
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
	security        string
	alpn            string
	utlsImitate     string
	publicKey       string
	shortID         string
	spiderX         string
	useH3           bool
}

type xmuxConfig struct {
	MaxConnections rangedInt `json:"maxConnections"`
	MaxConcurrency rangedInt `json:"maxConcurrency"`
	CMaxReuseTimes rangedInt `json:"cMaxReuseTimes"`
	HMaxRequestTimes rangedInt `json:"hMaxRequestTimes"`
	HMaxReusableSecs rangedInt `json:"hMaxReusableSecs"`
}

type xmuxOptions struct {
	enabled        bool
	maxConnections int
	maxConcurrency int
	maxReuseTimes  int
	hMaxRequestTimes int
	hMaxReusableSecs int
}

type h2PoolEntry struct {
	rawConn        netproxy.Conn
	h2Conn         *http2.ClientConn
	active         int
	reuseCount     int
	maxConcurrency int
	maxReuseTimes  int
	leftRequests   int
	unreusableAt   time.Time
	lastUsed       time.Time
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

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const requestClientIdleTimeout = 2 * time.Minute
const (
	placementQueryInHeader = "queryinheader"
	placementCookie        = "cookie"
	placementHeader        = "header"
	placementQuery         = "query"
	placementPath          = "path"
	placementBody          = "body"
	placementAuto          = "auto"
)

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

func normalizeMode(mode, scheme, security string, hasDownloadSettings bool) (string, error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "", "auto":
		if scheme != "https" {
			return "", fmt.Errorf("xhttp: auto mode without tls is not supported yet")
		}
		if strings.EqualFold(security, "reality") {
			if hasDownloadSettings {
				return "stream-up", nil
			}
			return "stream-one", nil
		}
		return "stream-up", nil
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

func buildXHTTPOptions(scheme, security, rawMode, rawExtra string) (*XHTTPOptions, error) {
	extra, err := parseExtra(rawExtra)
	if err != nil {
		return nil, err
	}

	mode, err := normalizeMode(rawMode, scheme, security, extra.DownloadSettings != nil)
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

	options := &XHTTPOptions{
		Mode:                mode,
		Headers:             headers,
		ContentType:         contentType,
		DownloadSettings:    extra.DownloadSettings,
		PacketMaxBytes:      extra.ScMaxEachPostBytes.Pick(),
		PacketMinGap:        time.Duration(extra.ScMinPostsIntervalMs.Pick()) * time.Millisecond,
		Xmux:                parseXmux(extra.Xmux),
		NoSSEHeader:         extra.NoSSEHeader,
		ScMaxBufferedPosts:  extra.ScMaxBufferedPosts,
		XPaddingBytes:       extra.XPaddingBytes,
		XPaddingObfsMode:    extra.XPaddingObfsMode,
		XPaddingKey:         extra.XPaddingKey,
		XPaddingHeader:      extra.XPaddingHeader,
		XPaddingPlacement:   extra.XPaddingPlacement,
		XPaddingMethod:      extra.XPaddingMethod,
		UplinkHTTPMethod:    extra.UplinkHTTPMethod,
		SessionPlacement:    extra.SessionPlacement,
		SessionKey:          extra.SessionKey,
		SeqPlacement:        extra.SeqPlacement,
		SeqKey:              extra.SeqKey,
		UplinkDataPlacement: extra.UplinkDataPlacement,
		UplinkDataKey:       extra.UplinkDataKey,
		UplinkChunkSize:     extra.UplinkChunkSize,
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return options, nil
}

func parseXmux(cfg *xmuxConfig) xmuxOptions {
	if cfg == nil {
		return xmuxOptions{}
	}
	maxConnections := cfg.MaxConnections.Pick()
	maxConcurrency := cfg.MaxConcurrency.Pick()
	maxReuseTimes := cfg.CMaxReuseTimes.Pick()
	hMaxRequestTimes := cfg.HMaxRequestTimes.Pick()
	hMaxReusableSecs := cfg.HMaxReusableSecs.Pick()
	if maxConnections <= 0 && maxConcurrency <= 0 && maxReuseTimes <= 0 && hMaxRequestTimes <= 0 && hMaxReusableSecs <= 0 {
		return xmuxOptions{}
	}
	return xmuxOptions{
		enabled:        true,
		maxConnections: maxConnections,
		maxConcurrency: maxConcurrency,
		maxReuseTimes:  maxReuseTimes,
		hMaxRequestTimes: hMaxRequestTimes,
		hMaxReusableSecs: hMaxReusableSecs,
	}
}

func (d *Dialer) normalizedUplinkHTTPMethod() string {
	if d.uplinkHTTPMethod == "" {
		return http.MethodPost
	}
	return d.uplinkHTTPMethod
}

func (d *Dialer) normalizedSessionPlacement() string {
	if d.sessionPlacement == "" {
		return placementPath
	}
	return strings.ToLower(d.sessionPlacement)
}

func (d *Dialer) normalizedSeqPlacement() string {
	if d.seqPlacement == "" {
		return placementPath
	}
	return strings.ToLower(d.seqPlacement)
}

func (d *Dialer) normalizedUplinkDataPlacement() string {
	if d.uplinkDataPlacement == "" {
		return placementBody
	}
	return strings.ToLower(d.uplinkDataPlacement)
}

func (d *Dialer) normalizedSessionKey() string {
	if d.sessionKey != "" {
		return d.sessionKey
	}
	switch d.normalizedSessionPlacement() {
	case placementHeader:
		return "X-Session"
	case placementCookie, placementQuery:
		return "x_session"
	default:
		return ""
	}
}

func (d *Dialer) normalizedSeqKey() string {
	if d.seqKey != "" {
		return d.seqKey
	}
	switch d.normalizedSeqPlacement() {
	case placementHeader:
		return "X-Seq"
	case placementCookie, placementQuery:
		return "x_seq"
	default:
		return ""
	}
}

func (d *Dialer) normalizedUplinkDataKey() string {
	if d.uplinkDataKey != "" {
		return d.uplinkDataKey
	}
	return "X-Data"
}

func (d *Dialer) normalizedUplinkChunkSize() rangedInt {
	if !d.uplinkChunkSize.set || d.uplinkChunkSize.max == 0 {
		switch d.normalizedUplinkDataPlacement() {
		case placementCookie:
			return rangedInt{set: true, min: 2 * 1024, max: 3 * 1024}
		case placementHeader:
			return rangedInt{set: true, min: 3 * 1000, max: 4 * 1000}
		default:
			return rangedInt{set: true, min: d.packetMaxBytes, max: d.packetMaxBytes}
		}
	}
	if d.uplinkChunkSize.min < 64 {
		maxV := d.uplinkChunkSize.max
		if maxV < 64 {
			maxV = 64
		}
		return rangedInt{set: true, min: 64, max: maxV}
	}
	return d.uplinkChunkSize
}

func appendToPathValue(pathValue, suffix string) string {
	if strings.HasSuffix(pathValue, "/") {
		return pathValue + suffix
	}
	return pathValue + "/" + suffix
}

func (d *Dialer) applyMetaToRequest(req *http.Request, sessionID, seqStr string) {
	if req == nil {
		return
	}
	if sessionID != "" {
		switch d.normalizedSessionPlacement() {
		case placementPath:
			req.URL.Path = appendToPathValue(req.URL.Path, sessionID)
		case placementQuery:
			q := req.URL.Query()
			q.Set(d.normalizedSessionKey(), sessionID)
			req.URL.RawQuery = q.Encode()
		case placementHeader:
			req.Header.Set(d.normalizedSessionKey(), sessionID)
		case placementCookie:
			req.AddCookie(&http.Cookie{Name: d.normalizedSessionKey(), Value: sessionID})
		}
	}
	if seqStr != "" {
		switch d.normalizedSeqPlacement() {
		case placementPath:
			req.URL.Path = appendToPathValue(req.URL.Path, seqStr)
		case placementQuery:
			q := req.URL.Query()
			q.Set(d.normalizedSeqKey(), seqStr)
			req.URL.RawQuery = q.Encode()
		case placementHeader:
			req.Header.Set(d.normalizedSeqKey(), seqStr)
		case placementCookie:
			req.AddCookie(&http.Cookie{Name: d.normalizedSeqKey(), Value: seqStr})
		}
	}
}

func (d *Dialer) applyPayloadToRequest(req *http.Request, payload []byte) error {
	switch d.normalizedUplinkDataPlacement() {
	case placementBody, placementAuto:
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
	case placementHeader:
		key := d.normalizedUplinkDataKey()
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		chunkRange := d.normalizedUplinkChunkSize()
		for i := 0; len(encoded) > 0; i++ {
			size := chunkRange.Pick()
			if size <= 0 || size > len(encoded) {
				size = len(encoded)
			}
			chunk := encoded[:size]
			encoded = encoded[size:]
			req.Header.Set(fmt.Sprintf("%s-%d", key, i), chunk)
		}
	case placementCookie:
		key := d.normalizedUplinkDataKey()
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		chunkRange := d.normalizedUplinkChunkSize()
		for i := 0; len(encoded) > 0; i++ {
			size := chunkRange.Pick()
			if size <= 0 || size > len(encoded) {
				size = len(encoded)
			}
			chunk := encoded[:size]
			encoded = encoded[size:]
			req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", key, i), Value: chunk, Path: "/"})
		}
	default:
		return fmt.Errorf("xhttp: unsupported uplink data placement %q", d.uplinkDataPlacement)
	}
	return nil
}

func (d *Dialer) prepareStreamRequest(req *http.Request, sessionID string) {
	req.Header = d.headers.Clone()
	d.applyXPaddingToRequest(req)
	d.applyMetaToRequest(req, sessionID, "")
	if req.Body != nil && d.contentType != "" {
		req.Header.Set("Content-Type", d.contentType)
	}
}

func (d *Dialer) preparePacketRequest(req *http.Request, sessionID, seqStr string, payload []byte) error {
	req.Header = d.headers.Clone()
	if err := d.applyPayloadToRequest(req, payload); err != nil {
		return err
	}
	d.applyXPaddingToRequest(req)
	d.applyMetaToRequest(req, sessionID, seqStr)
	return nil
}

func normalizedXPaddingRange(r rangedInt) rangedInt {
	if !r.set || r.max == 0 {
		return rangedInt{set: true, min: 100, max: 1000}
	}
	return r
}

func dialerIdentityKey(d netproxy.Dialer) string {
	if d == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T:%p", d, d)
}

func requestClientIdleExpired(lastUsed, now time.Time) bool {
	return !lastUsed.IsZero() && now.Sub(lastUsed) > requestClientIdleTimeout
}

func randomStringFromCharset(n int, charset string) string {
	if n <= 0 || len(charset) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(charset[rand.IntN(len(charset))])
	}
	return b.String()
}

func generatePadding(length int, method string) string {
	if length <= 0 {
		return ""
	}
	switch strings.ToLower(method) {
	case "", "repeat-x":
		return strings.Repeat("X", length)
	case "tokenish":
		return randomStringFromCharset(length, charsetBase62)
	default:
		return strings.Repeat("X", length)
	}
}

func (d *Dialer) applyXPaddingToRequest(req *http.Request) {
	if req == nil {
		return
	}
	padding := generatePadding(normalizedXPaddingRange(d.xPaddingBytes).Pick(), d.xPaddingMethod)
	if padding == "" {
		return
	}
	if !d.xPaddingObfsMode {
		u := *req.URL
		q := u.Query()
		q.Set("x_padding", padding)
		u.RawQuery = q.Encode()
		req.Header.Set("Referer", u.String())
		return
	}

	switch strings.ToLower(d.xPaddingPlacement) {
	case "header":
		header := d.xPaddingHeader
		if header == "" {
			header = "X-Padding"
		}
		req.Header.Set(header, padding)
	case "cookie":
		key := d.xPaddingKey
		if key == "" {
			key = "x_padding"
		}
		req.AddCookie(&http.Cookie{Name: key, Value: padding, Path: "/"})
	case "query":
		key := d.xPaddingKey
		if key == "" {
			key = "x_padding"
		}
		q := req.URL.Query()
		q.Set(key, padding)
		req.URL.RawQuery = q.Encode()
	default:
		u := *req.URL
		q := u.Query()
		q.Set("x_padding", padding)
		u.RawQuery = q.Encode()
		req.Header.Set("Referer", u.String())
	}
}

func newSecureEndpoint(
	option *dialer.ExtraOption,
	nextDialer netproxy.Dialer,
	addr string,
	host string,
	path string,
	security string,
	serverName string,
	allowInsecure bool,
	alpn string,
	utlsImitate string,
	publicKey string,
	shortID string,
	spiderX string,
) (endpoint, error) {
	useH3 := strings.EqualFold(security, "tls") && shouldUseH3(alpn)
	if useH3 {
		return endpoint{
			nextDialer:    nextDialer,
			addr:          addr,
			host:          host,
			path:          normalizePath(path),
			serverName:    serverName,
			allowInsecure: allowInsecure,
			security:      security,
			alpn:          alpn,
			utlsImitate:   utlsImitate,
			publicKey:     publicKey,
			shortID:       shortID,
			spiderX:       spiderX,
			useH3:         true,
		}, nil
	}
	if strings.EqualFold(security, "reality") {
		if shouldUseH3(alpn) {
			return endpoint{}, fmt.Errorf("xhttp: reality with h3 is not supported")
		}
		realityURL := url.URL{
			Scheme: "reality",
			Host:   addr,
			RawQuery: url.Values{
				"sni": []string{serverName},
				"fp":  []string{utlsImitate},
				"sid": []string{shortID},
				"pbk": []string{publicKey},
				"spx": []string{spiderX},
			}.Encode(),
		}
		realityDialer, err := transporttls.NewReality(realityURL.String(), nextDialer)
		if err != nil {
			return endpoint{}, err
		}
		return endpoint{
			dialer:        realityDialer,
			nextDialer:    nextDialer,
			addr:          addr,
			host:          host,
			path:          normalizePath(path),
			serverName:    serverName,
			allowInsecure: allowInsecure,
			security:      security,
			alpn:          alpn,
			utlsImitate:   utlsImitate,
			publicKey:     publicKey,
			shortID:       shortID,
			spiderX:       spiderX,
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
		security:      security,
		alpn:          alpn,
		utlsImitate:   utlsImitate,
		publicKey:     publicKey,
		shortID:       shortID,
		spiderX:       spiderX,
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
	mainPublicKey string,
	mainShortID string,
	mainSpiderX string,
	cfg *downloadSettingsConfig,
) (*endpoint, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Network != "" && !strings.EqualFold(cfg.Network, "xhttp") {
		return nil, fmt.Errorf("xhttp: downloadSettings network %q is not supported", cfg.Network)
	}
	if cfg.Security != "" && !strings.EqualFold(cfg.Security, "tls") && !strings.EqualFold(cfg.Security, "reality") {
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
	if strings.EqualFold(cfg.Security, "reality") {
		if cfg.RealitySettings.Fingerprint != "" {
			utlsImitate = cfg.RealitySettings.Fingerprint
		}
	} else if cfg.TLSSettings.Fingerprint != "" {
		utlsImitate = cfg.TLSSettings.Fingerprint
	}

	allowInsecure := mainAllowInsecure || cfg.TLSSettings.AllowInsecure
	if strings.EqualFold(cfg.Security, "reality") {
		allowInsecure = mainAllowInsecure
	}

	security := cfg.Security
	if security == "" {
		security = "tls"
	}

	publicKey := mainPublicKey
	shortID := mainShortID
	spiderX := mainSpiderX
	if strings.EqualFold(security, "reality") {
		if cfg.RealitySettings.PublicKey != "" {
			publicKey = cfg.RealitySettings.PublicKey
		}
		if cfg.RealitySettings.ShortID != "" {
			shortID = cfg.RealitySettings.ShortID
		}
		if cfg.RealitySettings.SpiderX != "" {
			spiderX = cfg.RealitySettings.SpiderX
		}
		if cfg.RealitySettings.ServerName != "" {
			serverName = cfg.RealitySettings.ServerName
		}
	}

	ep, err := newSecureEndpoint(option, nextDialer, addr, host, path, security, serverName, allowInsecure, alpn, utlsImitate, publicKey, shortID, spiderX)
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
	closed  bool
	mu      sync.Mutex
}

func (c *requestClient) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(req)
	if err != nil {
		_ = c.Close()
	}
	return resp, err
}

func (c *requestClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.closeFn != nil {
		return c.closeFn()
	}
	if c.rawConn != nil {
		return c.rawConn.Close()
	}
	return nil
}

func (c *requestClient) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type requestClientLease struct {
	client  *requestClient
	release func() error
	consumeRequest func()
}

type h3ClientEntry struct {
	client        *requestClient
	active        int
	leftUsage     int
	leftRequests  int
	unreusableAt  time.Time
	lastUsed      time.Time
}

type h3ClientPool struct {
	mu      sync.Mutex
	entries map[string][]*h3ClientEntry
}

var globalH3RequestPool = &h3ClientPool{
	entries: make(map[string][]*h3ClientEntry),
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
		EnableDatagrams:    true,
		MaxIdleTimeout:     300 * time.Second,
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: -1,
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

func requestClientReuseKey(ep endpoint, network string) string {
	return strings.Join([]string{
		dialerIdentityKey(ep.nextDialer),
		dialerIdentityKey(ep.dialer),
		ep.addr,
		ep.host,
		ep.path,
		ep.serverName,
		ep.security,
		ep.alpn,
		network,
	}, "|")
}

func newH3ClientEntry(client *requestClient, opts xmuxOptions) *h3ClientEntry {
	entry := &h3ClientEntry{
		client:       client,
		leftUsage:    -1,
		leftRequests: math.MaxInt32,
		lastUsed:     time.Now(),
	}
	if opts.maxReuseTimes > 0 {
		entry.leftUsage = opts.maxReuseTimes - 1
	}
	if opts.hMaxRequestTimes > 0 {
		entry.leftRequests = opts.hMaxRequestTimes
	}
	if opts.hMaxReusableSecs > 0 {
		entry.unreusableAt = time.Now().Add(time.Duration(opts.hMaxReusableSecs) * time.Second)
	}
	return entry
}

func (e *h3ClientEntry) reusable(now time.Time) bool {
	if e == nil || e.client == nil || e.client.IsClosed() {
		return false
	}
	if e.active == 0 && requestClientIdleExpired(e.lastUsed, now) {
		return false
	}
	if e.leftUsage == 0 {
		return false
	}
	if e.leftRequests <= 0 {
		return false
	}
	if !e.unreusableAt.IsZero() && now.After(e.unreusableAt) {
		return false
	}
	return true
}

func (p *h3ClientPool) release(key string, entry *h3ClientEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	entries := p.entries[key]
	for i, candidate := range entries {
		if candidate != entry {
			continue
		}
		if candidate.active > 0 {
			candidate.active--
		}
		candidate.lastUsed = time.Now()
		if candidate.active == 0 && !candidate.reusable(time.Now()) {
			_ = candidate.client.Close()
			p.entries[key] = append(entries[:i], entries[i+1:]...)
			if len(p.entries[key]) == 0 {
				delete(p.entries, key)
			}
		}
		return nil
	}
	return nil
}

func (d *Dialer) acquireRequestClient(ctx context.Context, ep endpoint, network string, opts xmuxOptions) (*requestClientLease, error) {
	if !ep.useH3 {
		client, err := d.openRequestClient(ctx, ep, network)
		if err != nil {
			return nil, err
		}
		return &requestClientLease{
			client:         client,
			release:        client.Close,
			consumeRequest: func() {},
		}, nil
	}

	key := requestClientReuseKey(ep, network)
	globalH3RequestPool.mu.Lock()
	defer globalH3RequestPool.mu.Unlock()
	now := time.Now()
	entries := globalH3RequestPool.entries[key]
	filtered := entries[:0]
	eligible := make([]*h3ClientEntry, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.client == nil {
			continue
		}
		retired := !entry.reusable(now)
		if entry.active == 0 && retired {
			_ = entry.client.Close()
			continue
		}
		filtered = append(filtered, entry)
		if retired {
			continue
		}
		if opts.maxConcurrency > 0 && entry.active >= opts.maxConcurrency {
			continue
		}
		eligible = append(eligible, entry)
	}
	globalH3RequestPool.entries[key] = filtered

	shouldCreate := len(filtered) == 0
	if !shouldCreate && opts.maxConnections > 0 && len(filtered) < opts.maxConnections {
		shouldCreate = true
	}
	if !shouldCreate && len(eligible) == 0 {
		shouldCreate = true
	}
	if shouldCreate {
		client, err := d.openRequestClient(ctx, ep, network)
		if err != nil {
			return nil, err
		}
		entry := newH3ClientEntry(client, opts)
		entry.active = 1
		entry.lastUsed = now
		if entry.leftUsage > 0 {
			entry.leftUsage--
		}
		globalH3RequestPool.entries[key] = append(globalH3RequestPool.entries[key], entry)
		return &requestClientLease{
			client:  client,
			release: func() error { return globalH3RequestPool.release(key, entry) },
			consumeRequest: func() {
				globalH3RequestPool.mu.Lock()
				defer globalH3RequestPool.mu.Unlock()
				if entry.leftRequests > 0 && entry.leftRequests != math.MaxInt32 {
					entry.leftRequests--
				}
			},
		}, nil
	}
	entry := eligible[0]
	entry.active++
	entry.lastUsed = now
	if entry.leftUsage > 0 {
		entry.leftUsage--
	}
	return &requestClientLease{
		client:  entry.client,
		release: func() error { return globalH3RequestPool.release(key, entry) },
		consumeRequest: func() {
			globalH3RequestPool.mu.Lock()
			defer globalH3RequestPool.mu.Unlock()
			if entry.leftRequests > 0 && entry.leftRequests != math.MaxInt32 {
				entry.leftRequests--
			}
		},
	}, nil
}

func packetUploadReuseKey(ep endpoint) string {
	return strings.Join([]string{
		dialerIdentityKey(ep.nextDialer),
		dialerIdentityKey(ep.dialer),
		ep.addr,
		ep.host,
		ep.path,
		ep.serverName,
		ep.security,
		ep.alpn,
	}, "|")
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

	key := packetUploadReuseKey(ep)
	p.mu.Lock()
	for _, entry := range p.entries[key] {
		if entry.active == 0 && requestClientIdleExpired(entry.lastUsed, time.Now()) {
			continue
		}
		if !entry.h2Conn.CanTakeNewRequest() {
			continue
		}
		if entry.leftRequests == 0 {
			continue
		}
		if !entry.unreusableAt.IsZero() && time.Now().After(entry.unreusableAt) {
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
		entry.lastUsed = time.Now()
		if entry.leftRequests > 0 {
			entry.leftRequests--
		}
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if opts.maxConnections > 0 && len(p.entries[key]) >= opts.maxConnections {
		return &pooledH2Lease{
			rawConn: rawConn,
			h2Conn:  h2Conn,
			release: func() error { return rawConn.Close() },
		}, nil
	}
	entry := &h2PoolEntry{
		rawConn:        rawConn,
		h2Conn:         h2Conn,
		active:         1,
		reuseCount:     1,
		maxConcurrency: opts.maxConcurrency,
		maxReuseTimes:  opts.maxReuseTimes,
		leftRequests:   opts.hMaxRequestTimes,
		lastUsed:       time.Now(),
	}
	if opts.hMaxReusableSecs > 0 {
		entry.unreusableAt = time.Now().Add(time.Duration(opts.hMaxReusableSecs) * time.Second)
	}
	p.entries[key] = append(p.entries[key], entry)
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
	entry.lastUsed = time.Now()
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
	security := query.Get("security")
	if security == "" && u.Scheme == "https" {
		security = "tls"
	}
	options, err := buildXHTTPOptions(u.Scheme, security, query.Get("mode"), query.Get("extra"))
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
	publicKey := query.Get("pbk")
	shortID := query.Get("sid")
	spiderX := query.Get("spx")

	uploadEndpoint, err := newSecureEndpoint(option, nextDialer, u.Host, host, u.Path, security, serverName, allowInsecure, alpn, utlsImitate, publicKey, shortID, spiderX)
	if err != nil {
		return nil, err
	}
	downloadEndpoint, err := buildDownloadEndpoint(option, nextDialer, u.Host, host, u.Path, serverName, allowInsecure, alpn, utlsImitate, publicKey, shortID, spiderX, options.DownloadSettings)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		uploadEndpoint:   uploadEndpoint,
		downloadEndpoint: downloadEndpoint,
		mode:             options.Mode,
		contentType:      options.ContentType,
		headers:          options.Headers,
		packetMaxBytes:   options.PacketMaxBytes,
		packetMinGap:     options.PacketMinGap,
		xmux:             options.Xmux,
		xPaddingBytes:    options.XPaddingBytes,
		xPaddingObfsMode: options.XPaddingObfsMode,
		xPaddingKey:      options.XPaddingKey,
		xPaddingHeader:   options.XPaddingHeader,
		xPaddingPlacement: options.XPaddingPlacement,
		xPaddingMethod:   options.XPaddingMethod,
		uplinkHTTPMethod: options.UplinkHTTPMethod,
		sessionPlacement: options.SessionPlacement,
		sessionKey:       options.SessionKey,
		seqPlacement:     options.SeqPlacement,
		seqKey:           options.SeqKey,
		uplinkDataPlacement: options.UplinkDataPlacement,
		uplinkDataKey:       options.UplinkDataKey,
		uplinkChunkSize:     options.UplinkChunkSize,
		noSSEHeader:         options.NoSSEHeader,
		scMaxBufferedPosts:  options.ScMaxBufferedPosts,
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
	uploadLease, err := d.acquireRequestClient(ctx, d.uploadEndpoint, network, d.xmux)
	if err != nil {
		return nil, err
	}
	uploadClient := uploadLease.client
	downloadEndpoint := d.uploadEndpoint
	if d.downloadEndpoint != nil {
		downloadEndpoint = *d.downloadEndpoint
	}

	sessionID := uuid.NewString()
	uploadTargetURL := (&url.URL{
		Scheme: "https",
		Host:   d.uploadEndpoint.addr,
		Path:   d.uploadEndpoint.path,
	}).String()
	downloadTargetURL := (&url.URL{
		Scheme: "https",
		Host:   downloadEndpoint.addr,
		Path:   downloadEndpoint.path,
	}).String()
	requestCtx := context.WithoutCancel(ctx)

	switch d.mode {
	case "stream-up":
		downloadClient := uploadClient
		downloadLease := uploadLease
		if d.downloadEndpoint != nil {
			downloadLease, err = d.acquireRequestClient(ctx, downloadEndpoint, network, d.xmux)
			if err != nil {
				_ = uploadLease.release()
				return nil, err
			}
			downloadClient = downloadLease.client
		}

		downloadReq, err := http.NewRequestWithContext(requestCtx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			_ = uploadLease.release()
			if downloadClient != uploadClient {
				_ = downloadLease.release()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		d.prepareStreamRequest(downloadReq, sessionID)
		downloadLease.consumeRequest()
		downloadResp, err := downloadClient.RoundTrip(downloadReq)
		if err != nil {
			_ = uploadLease.release()
			if downloadClient != uploadClient {
				_ = downloadLease.release()
			}
			return nil, err
		}
		if downloadResp.StatusCode != http.StatusOK {
			downloadResp.Body.Close()
			_ = uploadLease.release()
			if downloadClient != uploadClient {
				_ = downloadLease.release()
			}
			return nil, fmt.Errorf("xhttp: download path returned %s", downloadResp.Status)
		}

		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(requestCtx, d.normalizedUplinkHTTPMethod(), uploadTargetURL, pr)
		if err != nil {
			downloadResp.Body.Close()
			_ = uploadLease.release()
			if downloadClient != uploadClient {
				_ = downloadLease.release()
			}
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		d.prepareStreamRequest(uploadReq, sessionID)
		uploadLease.consumeRequest()

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: downloadClient.rawConn,
			uploadRelease: uploadLease.release,
			downloadRelease: downloadLease.release,
			sharedRelease: uploadClient == downloadClient,
			uploadBody:   pw,
			releaseWithBodies: true,
		}
		if uploadClient == downloadClient {
			releaseGroup := newSharedReleaseGroup(2, uploadLease.release)
			conn.downloadBody = wrapManagedReadCloser(downloadResp.Body, releaseGroup.Done)
			go conn.finishUpload(uploadClient, uploadReq, releaseGroup.Done)
		} else {
			conn.downloadBody = wrapManagedReadCloser(downloadResp.Body, func() { _ = downloadLease.release() })
			go conn.finishUpload(uploadClient, uploadReq, func() { _ = uploadLease.release() })
		}
		return conn, nil
	case "stream-one":
		pr, pw := io.Pipe()
		uploadReq, err := http.NewRequestWithContext(requestCtx, d.normalizedUplinkHTTPMethod(), uploadTargetURL, pr)
		if err != nil {
			_ = uploadLease.release()
			return nil, err
		}
		uploadReq.Host = d.uploadEndpoint.host
		d.prepareStreamRequest(uploadReq, sessionID)
		uploadLease.consumeRequest()

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: uploadClient.rawConn,
			uploadRelease: uploadLease.release,
			downloadRelease: uploadLease.release,
			sharedRelease: true,
			releaseWithBodies: true,
			uploadBody:   pw,
			respCh:       make(chan responseResult, 1),
		}
		go conn.startStreamOne(uploadClient, uploadReq, func() { _ = uploadLease.release() })
		return conn, nil
	case "packet-up":
		downloadClient := uploadClient
		downloadLease := uploadLease
		if d.downloadEndpoint != nil {
			downloadLease, err = d.acquireRequestClient(ctx, downloadEndpoint, network, d.xmux)
			if err != nil {
				_ = uploadLease.release()
				return nil, err
			}
			downloadClient = downloadLease.client
		}

		downloadReq, err := http.NewRequestWithContext(requestCtx, http.MethodGet, downloadTargetURL, nil)
		if err != nil {
			_ = uploadLease.release()
			if downloadClient != uploadClient {
				_ = downloadLease.release()
			}
			return nil, err
		}
		downloadReq.Host = downloadEndpoint.host
		d.prepareStreamRequest(downloadReq, sessionID)
		downloadLease.consumeRequest()

		conn := &Conn{
			uploadConn:   uploadClient.rawConn,
			downloadConn: downloadClient.rawConn,
			uploadRelease: uploadLease.release,
			downloadRelease: downloadLease.release,
			sharedRelease: uploadClient == downloadClient,
			releaseWithBodies: true,
			respCh:        make(chan responseResult, 1),
		}
		packetFlushDelay := 15 * time.Millisecond
		usePerRequestH3Upload := d.uploadEndpoint.useH3
		var acquireUpload func() (*requestClientLease, error)
		if usePerRequestH3Upload {
			acquireUpload = func() (*requestClientLease, error) {
				return d.acquireRequestClient(requestCtx, d.uploadEndpoint, network, d.xmux)
			}
		}
		if uploadClient == downloadClient {
			uploader := newPacketBatchUploader(
				requestCtx,
				uploadClient,
				acquireUpload,
				uploadTargetURL,
				d.uploadEndpoint.host,
				d,
				sessionID,
				d.packetMaxBytes,
				d.packetMinGap,
				packetFlushDelay,
			)
			conn.packetUpload = uploader.enqueue
			if usePerRequestH3Upload {
				conn.packetClose = func() error { return uploader.close() }
				go conn.startDownload(downloadClient, downloadReq, func() { _ = downloadLease.release() })
			} else {
				releaseGroup := newSharedReleaseGroup(2, uploadLease.release)
				conn.packetClose = func() error {
					err := uploader.close()
					releaseGroup.Done()
					return err
				}
				go conn.startDownload(downloadClient, downloadReq, releaseGroup.Done)
			}
		} else {
			if usePerRequestH3Upload {
				_ = uploadLease.release()
			}
			uploader := newPacketBatchUploader(
				requestCtx,
				uploadClient,
				acquireUpload,
				uploadTargetURL,
				d.uploadEndpoint.host,
				d,
				sessionID,
				d.packetMaxBytes,
				d.packetMinGap,
				packetFlushDelay,
			)
			conn.packetUpload = uploader.enqueue
			conn.packetClose = func() error {
				err := uploader.close()
				if !usePerRequestH3Upload {
					_ = uploadLease.release()
				}
				return err
			}
			go conn.startDownload(downloadClient, downloadReq, func() { _ = downloadLease.release() })
		}
		if d.xmux.enabled && !d.uploadEndpoint.useH3 {
			_ = uploadLease.release()
			lease, err := globalPacketUploadPool.acquire(ctx, d.uploadEndpoint, d.xmux, d.openH2Conn)
			if err != nil {
				conn.Close()
				return nil, err
			}
			conn.uploadConn = nil
			conn.uploadRelease = lease.release
			xmuxUploader := newPacketBatchUploader(
				requestCtx,
				lease.h2Conn,
				nil,
				uploadTargetURL,
				d.uploadEndpoint.host,
				d,
				sessionID,
				d.packetMaxBytes,
				d.packetMinGap,
				packetFlushDelay,
			)
			conn.packetUpload = xmuxUploader.enqueue
			conn.packetClose = func() error {
				closeErr := xmuxUploader.close()
				releaseErr := lease.release()
				if closeErr != nil {
					return closeErr
				}
				return releaseErr
			}
		}
		return conn, nil
	default:
		_ = uploadLease.release()
		return nil, fmt.Errorf("xhttp: mode %q is not supported yet", d.mode)
	}
}

func (d *Dialer) buildPacketUploader(reqCtx context.Context, uploadRT requestRoundTripper, uploadTargetURL string, sessionID string) func([]byte) error {
	var seq uint64
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
			req, err := http.NewRequestWithContext(reqCtx, d.normalizedUplinkHTTPMethod(), uploadTargetURL, nil)
			if err != nil {
				return err
			}
			req.Host = d.uploadEndpoint.host
			seqStr := strconv.FormatUint(seq, 10)
			seq++
			if err := d.preparePacketRequest(req, sessionID, seqStr, chunk); err != nil {
				return err
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
	releaseWithBodies bool
	uploadBody   *io.PipeWriter
	downloadBody io.ReadCloser
	packetUpload func([]byte) error
	packetClose  func() error

	closeOnce sync.Once
	uploadErr error
	respCh    chan responseResult
	writeMu   sync.Mutex
}

type responseResult struct {
	body io.ReadCloser
	err  error
}

type managedReadCloser struct {
	io.ReadCloser
	once    sync.Once
	onClose func()
}

func (m *managedReadCloser) Close() error {
	err := m.ReadCloser.Close()
	m.once.Do(func() {
		if m.onClose != nil {
			m.onClose()
		}
	})
	return err
}

type sharedReleaseGroup struct {
	mu        sync.Mutex
	remaining int
	release   func() error
}

func newSharedReleaseGroup(remaining int, release func() error) *sharedReleaseGroup {
	return &sharedReleaseGroup{remaining: remaining, release: release}
}

func (g *sharedReleaseGroup) Done() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.remaining <= 0 {
		return
	}
	g.remaining--
	if g.remaining == 0 && g.release != nil {
		_ = g.release()
	}
}

func wrapManagedReadCloser(rc io.ReadCloser, onClose func()) io.ReadCloser {
	if rc == nil {
		return nil
	}
	return &managedReadCloser{
		ReadCloser: rc,
		onClose:    onClose,
	}
}

type packetBatchUploader struct {
	mu            sync.Mutex
	cond          *sync.Cond
	buf           bytes.Buffer
	closed        bool
	err           error
	wg            sync.WaitGroup
	flushDelay    time.Duration
	maxUploadSize int
	minGap        time.Duration
	seq           uint64
	reqCtx        context.Context
	uploadRT      requestRoundTripper
	acquireUpload func() (*requestClientLease, error)
	uploadTargetURL string
	host          string
	dialer        *Dialer
	sessionID     string
}

func newPacketBatchUploader(
	reqCtx context.Context,
	uploadRT requestRoundTripper,
	acquireUpload func() (*requestClientLease, error),
	uploadTargetURL string,
	host string,
	dialer *Dialer,
	sessionID string,
	maxUploadSize int,
	minGap time.Duration,
	flushDelay time.Duration,
) *packetBatchUploader {
	u := &packetBatchUploader{
		flushDelay:      flushDelay,
		maxUploadSize:   maxUploadSize,
		minGap:          minGap,
		reqCtx:          reqCtx,
		uploadRT:        uploadRT,
		acquireUpload:   acquireUpload,
		uploadTargetURL: uploadTargetURL,
		host:            host,
		dialer:          dialer,
		sessionID:       sessionID,
	}
	u.cond = sync.NewCond(&u.mu)
	u.wg.Add(1)
	go u.run()
	return u
}

func (u *packetBatchUploader) enqueue(p []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return u.err
	}
	if u.closed {
		return io.ErrClosedPipe
	}
	_, _ = u.buf.Write(p)
	u.cond.Signal()
	return nil
}

func (u *packetBatchUploader) close() error {
	u.mu.Lock()
	u.closed = true
	u.cond.Broadcast()
	u.mu.Unlock()
	u.wg.Wait()
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

func (u *packetBatchUploader) run() {
	defer u.wg.Done()
	for {
		u.mu.Lock()
		for u.buf.Len() == 0 && !u.closed && u.err == nil {
			u.cond.Wait()
		}
		if u.err != nil || (u.closed && u.buf.Len() == 0) {
			u.mu.Unlock()
			return
		}
		u.mu.Unlock()

		if u.flushDelay > 0 {
			time.Sleep(u.flushDelay)
		}

		u.mu.Lock()
		if u.buf.Len() == 0 {
			u.mu.Unlock()
			continue
		}
		size := u.buf.Len()
		if u.maxUploadSize > 0 && size > u.maxUploadSize {
			size = u.maxUploadSize
		}
		chunk := make([]byte, size)
		_, _ = io.ReadFull(&u.buf, chunk)
		seqStr := strconv.FormatUint(u.seq, 10)
		u.seq++
		u.mu.Unlock()

		req, err := http.NewRequestWithContext(u.reqCtx, u.dialer.normalizedUplinkHTTPMethod(), u.uploadTargetURL, nil)
		if err != nil {
			u.setErr(err)
			return
		}
		req.Host = u.host
		if err := u.dialer.preparePacketRequest(req, u.sessionID, seqStr, chunk); err != nil {
			u.setErr(err)
			return
		}
		rt := u.uploadRT
		var lease *requestClientLease
		if u.acquireUpload != nil {
			lease, err = u.acquireUpload()
			if err != nil {
				u.setErr(err)
				return
			}
			lease.consumeRequest()
			rt = lease.client
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			if lease != nil {
				_ = lease.release()
			}
			u.setErr(err)
			return
		}
		func() {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
		if lease != nil {
			_ = lease.release()
		}
		if resp.StatusCode != http.StatusOK {
			u.setErr(fmt.Errorf("xhttp: packet-up path returned %s", resp.Status))
			return
		}
		if u.minGap > 0 {
			time.Sleep(u.minGap)
		}
	}
}

func (u *packetBatchUploader) setErr(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err == nil {
		u.err = err
	}
	u.closed = true
	u.cond.Broadcast()
}

func (c *Conn) finishUpload(rt requestRoundTripper, req *http.Request, onDone func()) {
	if onDone != nil {
		defer onDone()
	}
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

func (c *Conn) startStreamOne(rt requestRoundTripper, req *http.Request, onDone func()) {
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if onDone != nil {
			onDone()
		}
		c.respCh <- responseResult{err: err}
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if onDone != nil {
			onDone()
		}
		c.respCh <- responseResult{err: fmt.Errorf("xhttp: stream-one path returned %s", resp.Status)}
		return
	}
	c.respCh <- responseResult{body: wrapManagedReadCloser(resp.Body, onDone)}
}

func (c *Conn) startDownload(rt requestRoundTripper, req *http.Request, onDone func()) {
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if onDone != nil {
			onDone()
		}
		c.respCh <- responseResult{err: err}
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if onDone != nil {
			onDone()
		}
		c.respCh <- responseResult{err: fmt.Errorf("xhttp: download path returned %s", resp.Status)}
		return
	}
	c.respCh <- responseResult{body: wrapManagedReadCloser(resp.Body, onDone)}
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

func (c *Conn) CloseWrite() error {
	if c.packetClose != nil {
		return c.packetClose()
	}
	if c.uploadBody == nil {
		return nil
	}
	return c.uploadBody.Close()
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.packetClose != nil {
			err = c.packetClose()
		}
		if c.uploadBody != nil {
			_ = c.uploadBody.Close()
		}
		if c.downloadBody != nil {
			_ = c.downloadBody.Close()
		}
		if c.releaseWithBodies {
			return
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
	// Match Xray's splitConn behavior: per-stream deadlines don't map cleanly
	// onto the underlying shared HTTP transport, so treat them as best-effort no-ops.
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
