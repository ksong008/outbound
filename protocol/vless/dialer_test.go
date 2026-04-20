package vless

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestNewDialerAcceptsVisionFlow(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "00000000-0000-0000-0000-000000000000",
		IsClient:     true,
		Feature1:     XRV,
	})
	if err != nil {
		t.Fatalf("NewDialer returned error: %v", err)
	}

	typed, ok := d.(*Dialer)
	if !ok {
		t.Fatalf("expected *Dialer, got %T", d)
	}
	if typed.flow != XRV {
		t.Fatalf("expected flow %q, got %q", XRV, typed.flow)
	}
	if !typed.xudp {
		t.Fatal("expected xudp to be enabled for xtls-rprx-vision")
	}
}

func TestNewDialerRejectsVisionFlowForServerMode(t *testing.T) {
	_, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "00000000-0000-0000-0000-000000000000",
		IsClient:     false,
		Feature1:     XRV,
	})
	if err == nil {
		t.Fatal("expected server-mode vision flow to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported server mode xtls flow type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialerRejectsUnsupportedFlow(t *testing.T) {
	_, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "00000000-0000-0000-0000-000000000000",
		IsClient:     true,
		Feature1:     "xtls-rprx-vision-udp443",
	})
	if err == nil {
		t.Fatal("expected unsupported flow to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported xtls flow type") {
		t.Fatalf("unexpected error: %v", err)
	}
}
