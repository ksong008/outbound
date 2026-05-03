package ws

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type stubWSDialer struct{}

func (d *stubWSDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewWsParsesWSSSettings(t *testing.T) {
	d, prop, err := NewWs(&dialer.ExtraOption{}, &stubWSDialer{}, "wss://example.com:443/ws?host=cover.example&sni=server.example&allowinsecure=1&alpn=h2,http/1.1#node")
	if err != nil {
		t.Fatalf("NewWs returned error: %v", err)
	}
	wsDialer, ok := d.(*Ws)
	if !ok {
		t.Fatalf("expected *Ws, got %T", d)
	}
	if wsDialer.wsAddr != "wss://example.com:443/ws" {
		t.Fatalf("unexpected wsAddr: %q", wsDialer.wsAddr)
	}
	if wsDialer.header.Get("Host") != "cover.example" {
		t.Fatalf("expected Host header cover.example, got %#v", wsDialer.header)
	}
	if wsDialer.tlsClientConfig == nil || !wsDialer.tlsClientConfig.InsecureSkipVerify {
		t.Fatal("expected allowinsecure alias to enable tls skip verify")
	}
	if wsDialer.tlsClientConfig.ServerName != "server.example" {
		t.Fatalf("expected serverName server.example, got %q", wsDialer.tlsClientConfig.ServerName)
	}
	if len(wsDialer.tlsClientConfig.NextProtos) != 2 || wsDialer.tlsClientConfig.NextProtos[0] != "h2" || wsDialer.tlsClientConfig.NextProtos[1] != "http/1.1" {
		t.Fatalf("unexpected ALPN list: %#v", wsDialer.tlsClientConfig.NextProtos)
	}
	if prop == nil || prop.Protocol != "wss" {
		t.Fatalf("unexpected property: %#v", prop)
	}
}

func TestNewWsFallsBackHostHeaderToHostname(t *testing.T) {
	d, _, err := NewWs(&dialer.ExtraOption{}, &stubWSDialer{}, "ws://example.com:80/ws")
	if err != nil {
		t.Fatalf("NewWs returned error: %v", err)
	}
	wsDialer := d.(*Ws)
	if wsDialer.header.Get("Host") != "example.com" {
		t.Fatalf("expected Host header example.com, got %#v", wsDialer.header)
	}
}
