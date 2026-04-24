package xhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

type h3Session struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		scheme  string
		want    string
		wantErr bool
	}{
		{name: "auto over https", mode: "auto", scheme: "https", want: "packet-up"},
		{name: "empty over https", mode: "", scheme: "https", want: "packet-up"},
		{name: "stream-up", mode: "stream-up", scheme: "https", want: "stream-up"},
		{name: "stream-one over https", mode: "stream-one", scheme: "https", want: "stream-one"},
		{name: "packet-up over https", mode: "packet-up", scheme: "https", want: "packet-up"},
		{name: "auto over reality without download", mode: "auto", scheme: "https", want: "stream-one", wantErr: false},
		{name: "auto over reality with download", mode: "auto", scheme: "https", want: "stream-up", wantErr: false},
		{name: "auto over http unsupported", mode: "auto", scheme: "http", wantErr: true},
		{name: "stream-one over http unsupported", mode: "stream-one", scheme: "http", wantErr: true},
		{name: "packet-up over http unsupported", mode: "packet-up", scheme: "http", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			security := "tls"
			if tt.scheme == "http" {
				security = "none"
			}
			hasDownload := false
			if strings.Contains(tt.name, "reality") {
				security = "reality"
			}
			if strings.Contains(tt.name, "with download") {
				hasDownload = true
			}
			got, err := normalizeMode(tt.mode, tt.scheme, security, hasDownload)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParseExtra(t *testing.T) {
	cfg, err := parseExtra(`{"headers":{"User-Agent":"xray","X-Test":"1"},"noGRPCHeader":true,"scMaxEachPostBytes":"16-32","scMinPostsIntervalMs":25}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Headers["User-Agent"] != "xray" {
		t.Fatalf("expected User-Agent header, got %#v", cfg.Headers)
	}
	if !cfg.NoGRPCHeader {
		t.Fatalf("expected noGRPCHeader to be true")
	}
	if got := cfg.ScMaxEachPostBytes.Pick(); got < 16 || got > 32 {
		t.Fatalf("expected scMaxEachPostBytes pick in range [16,32], got %d", got)
	}
	if got := cfg.ScMinPostsIntervalMs.Pick(); got != 25 {
		t.Fatalf("expected scMinPostsIntervalMs to be 25, got %d", got)
	}
}

func TestParseExtraInvalidJSON(t *testing.T) {
	if _, err := parseExtra(`{invalid`); err == nil {
		t.Fatalf("expected parseExtra to fail for invalid json")
	}
}

func TestBuildXHTTPOptions(t *testing.T) {
	opts, err := buildXHTTPOptions("https", "tls", "auto", `{"headers":{"User-Agent":"xray"},"noGRPCHeader":true,"scMaxEachPostBytes":"16-32","scMinPostsIntervalMs":25,"sessionPlacement":"header"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Mode != "packet-up" {
		t.Fatalf("expected normalized mode packet-up, got %q", opts.Mode)
	}
	if opts.ContentType != "" {
		t.Fatalf("expected noGRPCHeader to clear content type, got %q", opts.ContentType)
	}
	if opts.Headers.Get("User-Agent") != "xray" {
		t.Fatalf("expected User-Agent header to be preserved")
	}
	if opts.PacketMaxBytes < 16 || opts.PacketMaxBytes > 32 {
		t.Fatalf("expected packet max bytes in range [16,32], got %d", opts.PacketMaxBytes)
	}
	if opts.PacketMinGap != 25*time.Millisecond {
		t.Fatalf("expected packet min gap 25ms, got %v", opts.PacketMinGap)
	}
	if opts.SessionPlacement != "header" {
		t.Fatalf("expected session placement to be kept, got %q", opts.SessionPlacement)
	}
}

func TestBuildXHTTPOptionsPacketUpDefaults(t *testing.T) {
	opts, err := buildXHTTPOptions("https", "tls", "packet-up", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.PacketMaxBytes != defaultPacketMaxBytes {
		t.Fatalf("expected default packet max bytes %d, got %d", defaultPacketMaxBytes, opts.PacketMaxBytes)
	}
	if opts.PacketMinGap != defaultPacketMinGap {
		t.Fatalf("expected default packet min gap %v, got %v", defaultPacketMinGap, opts.PacketMinGap)
	}
}

func TestBuildXHTTPOptionsRejectsUnsupportedCombinations(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		extra string
		want  string
	}{
		{
			name:  "stream-one with download settings",
			mode:  "stream-one",
			extra: `{"downloadSettings":{"address":"example.com","port":443,"network":"xhttp","security":"tls","xhttpSettings":{"host":"example.com","path":"/download"}}}`,
			want:  "stream-one does not support downloadSettings",
		},
		{
			name:  "download settings mode override",
			mode:  "stream-up",
			extra: `{"downloadSettings":{"address":"example.com","port":443,"network":"xhttp","security":"tls","xhttpSettings":{"host":"example.com","path":"/download","mode":"packet-up"}}}`,
			want:  "downloadSettings.xhttpSettings.mode is not supported yet",
		},
		{
			name:  "no sse header unsupported",
			mode:  "stream-up",
			extra: `{"noSSEHeader":true}`,
			want:  "noSSEHeader is not supported yet",
		},
		{
			name:  "max buffered posts unsupported",
			mode:  "stream-up",
			extra: `{"scMaxBufferedPosts":2}`,
			want:  "scMaxBufferedPosts is not supported yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildXHTTPOptions("https", "tls", tt.mode, tt.extra)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestBuildXHTTPOptionsErrorsAreTypedByStage(t *testing.T) {
	_, err := buildXHTTPOptions("http", "none", "auto", "")
	if err == nil {
		t.Fatal("expected config error")
	}
	if !strings.Contains(err.Error(), "xhttp/config:") {
		t.Fatalf("expected config-prefixed error, got %v", err)
	}
}

func TestBuildDownloadEndpointRejectsRealityH3(t *testing.T) {
	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	_, err := buildDownloadEndpoint(
		&dialer.ExtraOption{},
		nextDialer,
		"example.com:443",
		"example.com",
		"/download",
		"example.com",
		false,
		"h2",
		"",
		"public-key",
		"short-id",
		"/",
		&downloadSettingsConfig{
			Address:  "example.com",
			Port:     443,
			Network:  "xhttp",
			Security: "reality",
			TLSSettings: tlsSettingsConfig{
				ALPN: []string{"h3"},
			},
			RealitySettings: realitySettingsConfig{
				ServerName:  "example.com",
				Fingerprint: "chrome",
				PublicKey:   "public-key",
				ShortID:     "short-id",
			},
			XHTTPSettings: xhttpSettingsConfig{
				Host: "example.com",
				Path: "/download",
			},
		},
	)
	if err == nil {
		t.Fatal("expected reality+h3 download endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "reality with h3 is not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShouldUseH3(t *testing.T) {
	tests := []struct {
		alpn string
		want bool
	}{
		{alpn: "h3", want: true},
		{alpn: "H3", want: true},
		{alpn: "h2,h3", want: false},
		{alpn: "h3,http/1.1", want: false},
		{alpn: "h2", want: false},
		{alpn: "", want: false},
	}

	for _, tt := range tests {
		if got := shouldUseH3(tt.alpn); got != tt.want {
			t.Fatalf("shouldUseH3(%q) = %v, want %v", tt.alpn, got, tt.want)
		}
	}
}

func TestRequestClientReuseKeySeparatesDialers(t *testing.T) {
	dialerA := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	dialerB := direct.NewDirectDialerLaddr(netip.MustParseAddr("127.0.0.2"), direct.Option{})
	epBase := endpoint{
		addr:       "example.com:443",
		host:       "example.com",
		path:       "/xhttp",
		serverName: "example.com",
		security:   "tls",
		alpn:       "h2",
	}
	keyA := requestClientReuseKey(endpoint{
		nextDialer: dialerA,
		dialer:     dialerA,
		addr:       epBase.addr,
		host:       epBase.host,
		path:       epBase.path,
		serverName: epBase.serverName,
		security:   epBase.security,
		alpn:       epBase.alpn,
	}, "tcp")
	keyB := requestClientReuseKey(endpoint{
		nextDialer: dialerB,
		dialer:     dialerB,
		addr:       epBase.addr,
		host:       epBase.host,
		path:       epBase.path,
		serverName: epBase.serverName,
		security:   epBase.security,
		alpn:       epBase.alpn,
	}, "tcp")
	if keyA == keyB {
		t.Fatal("expected reuse key to distinguish dialer identity")
	}
}

func TestH3ClientEntryReusableExpiresWhenIdle(t *testing.T) {
	entry := &h3ClientEntry{
		client:       &requestClient{},
		leftUsage:    -1,
		leftRequests: math.MaxInt32,
		lastUsed:     time.Now().Add(-requestClientIdleTimeout - time.Second),
	}
	if entry.reusable(time.Now()) {
		t.Fatal("expected idle h3 entry to be non-reusable")
	}
}

func TestApplyMetaToRequestPlacements(t *testing.T) {
	t.Run("header placement", func(t *testing.T) {
		d := &Dialer{sessionPlacement: "header", seqPlacement: "header"}
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
		req.Header = make(http.Header)
		d.applyMetaToRequest(req, "sess", "7")
		if got := req.Header.Get("X-Session"); got != "sess" {
			t.Fatalf("expected X-Session=sess, got %q", got)
		}
		if got := req.Header.Get("X-Seq"); got != "7" {
			t.Fatalf("expected X-Seq=7, got %q", got)
		}
	})

	t.Run("query placement", func(t *testing.T) {
		d := &Dialer{sessionPlacement: "query", seqPlacement: "query"}
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
		req.Header = make(http.Header)
		d.applyMetaToRequest(req, "sess", "7")
		if got := req.URL.Query().Get("x_session"); got != "sess" {
			t.Fatalf("expected x_session=sess, got %q", got)
		}
		if got := req.URL.Query().Get("x_seq"); got != "7" {
			t.Fatalf("expected x_seq=7, got %q", got)
		}
	})

	t.Run("cookie placement", func(t *testing.T) {
		d := &Dialer{sessionPlacement: "cookie", seqPlacement: "cookie"}
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
		req.Header = make(http.Header)
		d.applyMetaToRequest(req, "sess", "7")
		cookies := req.Cookies()
		if len(cookies) != 2 {
			t.Fatalf("expected 2 cookies, got %d", len(cookies))
		}
	})

	t.Run("path placement", func(t *testing.T) {
		d := &Dialer{}
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
		req.Header = make(http.Header)
		d.applyMetaToRequest(req, "sess", "7")
		if got := req.URL.Path; got != "/x/sess/7" {
			t.Fatalf("expected path /x/sess/7, got %q", got)
		}
	})
}

func TestPreparePacketRequestPlacements(t *testing.T) {
	payload := []byte("hello-world")

	t.Run("header data placement", func(t *testing.T) {
		d := &Dialer{
			headers:             make(http.Header),
			uplinkDataPlacement: "header",
			uplinkDataKey:       "X-Data",
			uplinkChunkSize:     rangedInt{set: true, min: 5, max: 5},
		}
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/x", nil)
		if err := d.preparePacketRequest(req, "sess", "3", payload); err != nil {
			t.Fatalf("preparePacketRequest error: %v", err)
		}
		if req.Body != nil {
			t.Fatalf("expected header placement to avoid request body")
		}
		if req.Header.Get("X-Data-0") == "" {
			t.Fatalf("expected X-Data-0 header to be set")
		}
		if req.URL.Path != "/x/sess/3" {
			t.Fatalf("expected path placement to apply metadata, got %q", req.URL.Path)
		}
	})

	t.Run("cookie data placement", func(t *testing.T) {
		d := &Dialer{
			headers:             make(http.Header),
			uplinkDataPlacement: "cookie",
			uplinkDataKey:       "x_data",
			uplinkChunkSize:     rangedInt{set: true, min: 5, max: 5},
		}
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/x", nil)
		if err := d.preparePacketRequest(req, "sess", "3", payload); err != nil {
			t.Fatalf("preparePacketRequest error: %v", err)
		}
		if len(req.Cookies()) == 0 {
			t.Fatalf("expected cookies to be set")
		}
	})
}

func TestAcquireRequestClientReusesH3Transport(t *testing.T) {
	globalH3RequestPool.mu.Lock()
	globalH3RequestPool.entries = make(map[string][]*h3ClientEntry)
	globalH3RequestPool.mu.Unlock()

	d := &Dialer{}
	ep := endpoint{
		addr:       "example.com:443",
		host:       "example.com",
		path:       "/xhttp",
		serverName: "example.com",
		security:   "tls",
		alpn:       "h3",
		useH3:      true,
	}
	client := &requestClient{closeFn: func() error { return nil }}
	key := requestClientReuseKey(ep, "tcp")
	globalH3RequestPool.mu.Lock()
	globalH3RequestPool.entries[key] = []*h3ClientEntry{newH3ClientEntry(client, xmuxOptions{})}
	globalH3RequestPool.mu.Unlock()

	lease1, err := d.acquireRequestClient(context.Background(), ep, "tcp", xmuxOptions{})
	if err != nil {
		t.Fatalf("first acquireRequestClient failed: %v", err)
	}
	lease2, err := d.acquireRequestClient(context.Background(), ep, "tcp", xmuxOptions{})
	if err != nil {
		t.Fatalf("second acquireRequestClient failed: %v", err)
	}
	if lease1.client != lease2.client {
		t.Fatalf("expected H3 request client reuse, got distinct clients")
	}
	if err := lease1.release(); err != nil {
		t.Fatalf("first release failed: %v", err)
	}
	if lease1.client.IsClosed() {
		t.Fatalf("shared H3 client should stay open after lease release")
	}
	if err := lease2.release(); err != nil {
		t.Fatalf("second release failed: %v", err)
	}
	if lease1.client.IsClosed() {
		t.Fatalf("shared H3 client should stay open after all lease releases")
	}
	if err := lease1.client.Close(); err != nil {
		t.Fatalf("final client close failed: %v", err)
	}
}

func TestAcquireRequestClientRotatesH3ClientAfterRequestBudget(t *testing.T) {
	globalH3RequestPool.mu.Lock()
	globalH3RequestPool.entries = make(map[string][]*h3ClientEntry)
	globalH3RequestPool.mu.Unlock()

	d := &Dialer{}
	ep := endpoint{
		addr:       "example.com:444",
		host:       "example.com",
		path:       "/xhttp",
		serverName: "example.com",
		security:   "tls",
		alpn:       "h3",
		useH3:      true,
	}
	opts := xmuxOptions{enabled: true, hMaxRequestTimes: 1}
	client := &requestClient{closeFn: func() error { return nil }}
	key := requestClientReuseKey(ep, "tcp")
	globalH3RequestPool.mu.Lock()
	globalH3RequestPool.entries[key] = []*h3ClientEntry{newH3ClientEntry(client, opts)}
	globalH3RequestPool.mu.Unlock()

	lease1, err := d.acquireRequestClient(context.Background(), ep, "tcp", opts)
	if err != nil {
		t.Fatalf("first acquireRequestClient failed: %v", err)
	}
	lease1.consumeRequest()
	if err := lease1.release(); err != nil {
		t.Fatalf("first release failed: %v", err)
	}
	if !lease1.client.IsClosed() {
		t.Fatalf("expected exhausted H3 client to close on release")
	}
	globalH3RequestPool.mu.Lock()
	defer globalH3RequestPool.mu.Unlock()
	if got := len(globalH3RequestPool.entries[key]); got != 0 {
		t.Fatalf("expected exhausted H3 client to be removed from pool, got %d entries", got)
	}
}

type errorRoundTripper struct{}

func (errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("boom")
}

func TestRequestClientClosesOnRoundTripError(t *testing.T) {
	closed := false
	client := &requestClient{
		rt: errorRoundTripper{},
		closeFn: func() error {
			closed = true
			return nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if _, err := client.RoundTrip(req); err == nil {
		t.Fatalf("expected round trip error")
	}
	if !closed {
		t.Fatalf("expected client to close itself on round trip error")
	}
	if !client.IsClosed() {
		t.Fatalf("expected client closed flag after round trip error")
	}
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}

func TestH3StreamOneIntegration(t *testing.T) {
	cert := generateSelfSignedCert(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Logf("server copy error: %v", err)
		}
	})

	server := &http3.Server{
		Handler:   handler,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", server.TLSConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("listen h3: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ServeListener(ln)
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
	}()

	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	link := "https://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.UDPAddr).Port) + "/echo?host=127.0.0.1&sni=127.0.0.1&allowInsecure=true&alpn=h3&mode=stream-one"
	dialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over h3 xhttp")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if xc, ok := conn.(*Conn); ok && xc.uploadBody != nil {
		if err := xc.uploadBody.Close(); err != nil {
			t.Fatalf("close upload body: %v", err)
		}
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}

func TestH3AutoStreamUpIntegration(t *testing.T) {
	cert := generateSelfSignedCert(t)

	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	sessionKeyFromPath := func(rawPath string) string {
		trimmed := strings.Trim(rawPath, "/")
		if trimmed == "" {
			return ""
		}
		parts := strings.Split(trimmed, "/")
		if len(parts) >= 3 {
			return parts[len(parts)-2]
		}
		return parts[len(parts)-1]
	}
	getSession := func(key string) *h3Session {
		key = sessionKeyFromPath(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			defer sess.writer.Close()
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("server copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := &http3.Server{
		Handler:   handler,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", server.TLSConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("listen h3: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ServeListener(ln)
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
	}()

	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	link := "https://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.UDPAddr).Port) + "/echo?host=127.0.0.1&sni=127.0.0.1&allowInsecure=true&alpn=h3&mode=auto"
	dialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over h3 xhttp packet-up")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}

func TestH3AutoSupportsSequentialConnections(t *testing.T) {
	cert := generateSelfSignedCert(t)

	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	sessionKeyFromPath := func(rawPath string) string {
		trimmed := strings.Trim(rawPath, "/")
		if trimmed == "" {
			return ""
		}
		parts := strings.Split(trimmed, "/")
		if len(parts) >= 3 {
			return parts[len(parts)-2]
		}
		return parts[len(parts)-1]
	}
	getSession := func(key string) *h3Session {
		key = sessionKeyFromPath(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			defer sess.writer.Close()
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("server copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := &http3.Server{
		Handler:   handler,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", server.TLSConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("listen h3: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ServeListener(ln)
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
	}()

	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	link := "https://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.UDPAddr).Port) + "/echo?host=127.0.0.1&sni=127.0.0.1&allowInsecure=true&alpn=h3&mode=auto"
	xDialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := xDialer.DialContext(ctx, "tcp", "example.com:443")
		cancel()
		if err != nil {
			t.Fatalf("dial context %d: %v", i, err)
		}

		payload := []byte("hello over h3 auto seq " + strconv.Itoa(i))
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			t.Fatalf("write payload %d: %v", i, err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			t.Fatalf("read payload %d: %v", i, err)
		}
		if string(buf) != string(payload) {
			conn.Close()
			t.Fatalf("unexpected echo %d: got %q want %q", i, string(buf), string(payload))
		}
		_ = conn.Close()
	}
}

func TestDownloadSettingsSplitStreamUpIntegration(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
		postHits int
		getHits  int
	)
	getSession := func(key string) *h3Session {
		key = path.Base(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	downloadHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		getHits++
		mu.Unlock()
		sess := getSession(r.URL.Path)
		flusher, _ := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		if flusher != nil {
			flusher.Flush()
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := sess.reader.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})

	uploadHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		postHits++
		mu.Unlock()
		sess := getSession(r.URL.Path)
		defer sess.writer.Close()
		if _, err := io.Copy(sess.writer, r.Body); err != nil {
			t.Logf("upload copy error: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	uploadServer := httptest.NewUnstartedServer(uploadHandler)
	uploadServer.EnableHTTP2 = true
	uploadServer.StartTLS()
	defer uploadServer.Close()

	downloadServer := httptest.NewUnstartedServer(downloadHandler)
	downloadServer.EnableHTTP2 = true
	downloadServer.StartTLS()
	defer downloadServer.Close()

	uploadURL, err := url.Parse(uploadServer.URL)
	if err != nil {
		t.Fatalf("parse upload server url: %v", err)
	}
	downloadURL, err := url.Parse(downloadServer.URL)
	if err != nil {
		t.Fatalf("parse download server url: %v", err)
	}

	extraJSON := `{"downloadSettings":{"address":"` + downloadURL.Hostname() + `","port":` + downloadURL.Port() + `,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"` + downloadURL.Hostname() + `","allowInsecure":true,"alpn":["h2"]},"xhttpSettings":{"host":"` + downloadURL.Hostname() + `","path":"/download"}}}`
	link := "https://" + uploadURL.Host + "/upload?host=" + uploadURL.Hostname() + "&sni=" + uploadURL.Hostname() + "&allowInsecure=true&alpn=h2&mode=stream-up&extra=" + url.QueryEscape(extraJSON)

	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	xDialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := xDialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over split downloadSettings")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if xc, ok := conn.(*Conn); ok && xc.uploadBody != nil {
		if err := xc.uploadBody.Close(); err != nil {
			t.Fatalf("close upload body: %v", err)
		}
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		mu.Lock()
		t.Logf("postHits=%d getHits=%d", postHits, getHits)
		mu.Unlock()
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}

func TestStreamUpSurvivesDialContextCancellation(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	getSession := func(key string) *h3Session {
		key = path.Base(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			defer sess.writer.Close()
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("stream-up copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	link := "https://" + serverURL.Host + "/echo?host=" + serverURL.Hostname() + "&sni=" + serverURL.Hostname() + "&allowInsecure=true&alpn=h2&mode=stream-up"

	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	xDialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := xDialer.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		cancel()
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	cancel()

	payload := []byte("hello after dial context cancellation")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if xc, ok := conn.(*Conn); ok && xc.uploadBody != nil {
		if err := xc.uploadBody.Close(); err != nil {
			t.Fatalf("close upload body: %v", err)
		}
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}

func TestConnDeadlinesAreNoop(t *testing.T) {
	c := &Conn{}
	if err := c.SetDeadline(time.Now()); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := c.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
}

func TestStreamUpSupportsSequentialHTTPRequests(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	getSession := func(key string) *h3Session {
		key = path.Base(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			defer sess.writer.Close()
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("stream-up copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	link := "https://" + serverURL.Host + "/echo?host=" + serverURL.Hostname() + "&sni=" + serverURL.Hostname() + "&allowInsecure=true&alpn=h2&mode=stream-up"
	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	xDialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := xDialer.DialContext(ctx, "tcp", serverURL.Host)
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	chunks := []string{
		"first request bytes",
		"second request bytes",
	}
	expected := strings.Join(chunks, "")

	for i, chunk := range chunks {
		if _, err := io.WriteString(conn, chunk); err != nil {
			t.Fatalf("write chunk %d: %v", i, err)
		}
	}
	if xc, ok := conn.(*Conn); ok && xc.uploadBody != nil {
		if err := xc.uploadBody.Close(); err != nil {
			t.Fatalf("close upload body: %v", err)
		}
	}

	buf := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != expected {
		t.Fatalf("unexpected payload: got %q want %q", string(buf), expected)
	}
}

func TestPacketUpH2Integration(t *testing.T) {
	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	getSession := func(key string) *h3Session {
		key = strings.Trim(strings.TrimPrefix(key, "/echo"), "/")
		if sessionID, _, ok := strings.Cut(key, "/"); ok {
			key = sessionID
		}
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("packet-up copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	link := "https://" + serverURL.Host + "/echo?host=" + serverURL.Hostname() + "&sni=" + serverURL.Hostname() + "&allowInsecure=true&alpn=h2&mode=packet-up"
	nextDialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	xDialer, err := NewDialer(&dialer.ExtraOption{}, nextDialer, link)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := xDialer.DialContext(ctx, "tcp", serverURL.Host)
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello over h2 packet-up")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}
