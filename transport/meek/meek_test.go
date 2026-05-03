package meek

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type recordingDialer struct {
	lastNetwork string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.lastNetwork = network
	return &recordingConn{}, nil
}

type recordingConn struct{}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, nil }
func (c *recordingConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func TestNewDialerPreservesTLSConfig(t *testing.T) {
	d, err := NewDialer("meek://proxy.example:443?url=https://front.example/meek&serverName=cover.example&allowInsecure=1&alpn=h2,http/1.1", &recordingDialer{})
	if err != nil {
		t.Fatalf("NewDialer returned error: %v", err)
	}
	if d.serverName != "cover.example" {
		t.Fatalf("expected serverName cover.example, got %q", d.serverName)
	}
	if !d.tlsConfig.InsecureSkipVerify {
		t.Fatalf("expected allowInsecure to propagate into tlsConfig")
	}
	if len(d.tlsConfig.NextProtos) != 2 || d.tlsConfig.NextProtos[0] != "h2" || d.tlsConfig.NextProtos[1] != "http/1.1" {
		t.Fatalf("expected ALPN to propagate into tlsConfig, got %#v", d.tlsConfig.NextProtos)
	}
}

func TestGetRoundTripperPreservesMagicNetwork(t *testing.T) {
	CleanGlobalRoundTripperCache()
	dialer := &recordingDialer{}
	client := &httpTripperClient{
		addr:         "proxy.example:443",
		nextDialer:   dialer,
		tlsConfig:    dummytlsConfig(),
		url:          "https://front.example/meek",
		magicNetwork: "tcp|mark=9",
	}

	rt := client.getRoundTripper()
	transport, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	_ = conn.Close()
	if dialer.lastNetwork != "tcp|mark=9" {
		t.Fatalf("expected magic network to be preserved, got %q", dialer.lastNetwork)
	}
}

func TestGetRoundTripperSeparatesRouteCaches(t *testing.T) {
	CleanGlobalRoundTripperCache()
	dialer := &recordingDialer{}
	base := &httpTripperClient{
		addr:         "proxy.example:443",
		nextDialer:   dialer,
		tlsConfig:    dummytlsConfig(),
		url:          "https://front.example/meek",
		magicNetwork: "tcp|mark=1",
	}
	same := &httpTripperClient{
		addr:         base.addr,
		nextDialer:   base.nextDialer,
		tlsConfig:    dummytlsConfig(),
		url:          base.url,
		magicNetwork: "tcp|mark=1",
	}
	other := &httpTripperClient{
		addr:         base.addr,
		nextDialer:   base.nextDialer,
		tlsConfig:    dummytlsConfig(),
		url:          base.url,
		magicNetwork: "tcp|mark=2",
	}

	first := base.getRoundTripper()
	if same.getRoundTripper() != first {
		t.Fatalf("expected identical route context to reuse the same round tripper")
	}
	if other.getRoundTripper() == first {
		t.Fatalf("expected different route context to use a different round tripper")
	}
}

func dummytlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         "cover.example",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
}
