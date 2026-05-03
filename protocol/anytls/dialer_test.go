package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type stubAnyTLSDialer struct{}

func (d *stubAnyTLSDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewDialerInitializesConfig(t *testing.T) {
	tlsConfig := &tls.Config{ServerName: "server.example"}
	d, err := NewDialer(&stubAnyTLSDialer{}, protocol.Header{
		ProxyAddress: "proxy.example:443",
		Password:     "secret",
		TlsConfig:    tlsConfig,
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("NewDialer returned error: %v", err)
	}
	anytlsDialer, ok := d.(*Dialer)
	if !ok {
		t.Fatalf("expected *Dialer, got %T", d)
	}
	if anytlsDialer.proxyAddress != "proxy.example:443" {
		t.Fatalf("unexpected proxyAddress: %q", anytlsDialer.proxyAddress)
	}
	if anytlsDialer.tlsConfig != tlsConfig {
		t.Fatal("expected tlsConfig to be preserved")
	}
	expected := sha256.Sum256([]byte("secret"))
	if string(anytlsDialer.key) != string(expected[:]) {
		t.Fatal("expected password to be hashed into key")
	}
	if !anytlsDialer.metadata.IsClient {
		t.Fatal("expected client metadata to be preserved")
	}
}
