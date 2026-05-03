package httpupgrade

import "testing"

func TestNewDialerParsesHTTPSSettings(t *testing.T) {
	d, err := NewDialer("https://proxy.example:443?path=upgrade&host=cover.example&skipVerify=1", nil)
	if err != nil {
		t.Fatalf("NewDialer returned error: %v", err)
	}
	if d.path != "/upgrade" {
		t.Fatalf("expected normalized path /upgrade, got %q", d.path)
	}
	if d.host != "cover.example" {
		t.Fatalf("expected host cover.example, got %q", d.host)
	}
	if !d.skipVerify {
		t.Fatal("expected skipVerify alias to be preserved")
	}
	if d.tlsConfig == nil {
		t.Fatal("expected TLS config for https")
	}
	if d.tlsConfig.ServerName != "proxy.example" {
		t.Fatalf("expected serverName proxy.example, got %q", d.tlsConfig.ServerName)
	}
	if len(d.tlsConfig.NextProtos) != 1 || d.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("unexpected ALPN list: %#v", d.tlsConfig.NextProtos)
	}
}

func TestNewDialerUsesExplicitServerName(t *testing.T) {
	d, err := NewDialer("https://proxy.example:443?path=/ws&serverName=server.example", nil)
	if err != nil {
		t.Fatalf("NewDialer returned error: %v", err)
	}
	if d.serverName != "server.example" {
		t.Fatalf("expected explicit serverName, got %q", d.serverName)
	}
}
