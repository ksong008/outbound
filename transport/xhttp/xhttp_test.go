package xhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
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
		{name: "auto over https", mode: "auto", scheme: "https", want: "stream-up"},
		{name: "empty over https", mode: "", scheme: "https", want: "stream-up"},
		{name: "stream-up", mode: "stream-up", scheme: "https", want: "stream-up"},
		{name: "stream-one over https", mode: "stream-one", scheme: "https", want: "stream-one"},
		{name: "packet-up over https", mode: "packet-up", scheme: "https", want: "packet-up"},
		{name: "auto over http unsupported", mode: "auto", scheme: "http", wantErr: true},
		{name: "stream-one over http unsupported", mode: "stream-one", scheme: "http", wantErr: true},
		{name: "packet-up over http unsupported", mode: "packet-up", scheme: "http", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMode(tt.mode, tt.scheme)
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
	getSession := func(key string) *h3Session {
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

	payload := []byte("hello over h3 xhttp stream-up")
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
