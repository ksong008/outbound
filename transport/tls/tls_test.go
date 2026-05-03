package tls

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type stubTLSDialer struct{}

func (d *stubTLSDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewTlsParsesAllowInsecureAliasesAndALPN(t *testing.T) {
	d, prop, err := NewTls(&dialer.ExtraOption{}, &stubTLSDialer{}, "tls://example.com:443?sni=server.example&allow_insecure=true&alpn=h2,http/1.1#node")
	if err != nil {
		t.Fatalf("NewTls returned error: %v", err)
	}
	tlsDialer, ok := d.(*Tls)
	if !ok {
		t.Fatalf("expected *Tls, got %T", d)
	}
	if !tlsDialer.skipVerify {
		t.Fatal("expected allow_insecure alias to enable skipVerify")
	}
	if tlsDialer.tlsConfig.ServerName != "server.example" {
		t.Fatalf("expected serverName server.example, got %q", tlsDialer.tlsConfig.ServerName)
	}
	if len(tlsDialer.tlsConfig.NextProtos) != 2 || tlsDialer.tlsConfig.NextProtos[0] != "h2" || tlsDialer.tlsConfig.NextProtos[1] != "http/1.1" {
		t.Fatalf("unexpected ALPN list: %#v", tlsDialer.tlsConfig.NextProtos)
	}
	if prop == nil || prop.Address != "example.com:443" {
		t.Fatalf("unexpected property: %#v", prop)
	}
}

func TestNewTlsUsesOptionImplementationAndFingerprint(t *testing.T) {
	d, _, err := NewTls(&dialer.ExtraOption{TlsImplementation: "utls", UtlsImitate: "chrome"}, &stubTLSDialer{}, "tls://example.com:443")
	if err != nil {
		t.Fatalf("NewTls returned error: %v", err)
	}
	tlsDialer := d.(*Tls)
	if tlsDialer.tlsImplentation != "utls" {
		t.Fatalf("expected tls implementation utls, got %q", tlsDialer.tlsImplentation)
	}
	if tlsDialer.utlsImitate != "chrome" {
		t.Fatalf("expected utls fingerprint chrome, got %q", tlsDialer.utlsImitate)
	}
}
