package v2ray

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol/vless"
)

func TestParseVlessURLVisionFlow(t *testing.T) {
	cfg, err := ParseVlessURL("vless://uuid@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=server.example&fp=chrome&alpn=h2,http/1.1#node")
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}
	if cfg.Protocol != "vless" {
		t.Fatalf("expected protocol vless, got %q", cfg.Protocol)
	}
	if cfg.Flow != vless.XRV {
		t.Fatalf("expected flow %q, got %q", vless.XRV, cfg.Flow)
	}
	if cfg.TLS != "tls" {
		t.Fatalf("expected security tls, got %q", cfg.TLS)
	}
	if cfg.Fingerprint != "chrome" {
		t.Fatalf("expected fingerprint chrome, got %q", cfg.Fingerprint)
	}
	if cfg.Alpn != "h2,http/1.1" {
		t.Fatalf("expected alpn h2,http/1.1, got %q", cfg.Alpn)
	}
}

func TestExportVlessURLVisionFlow(t *testing.T) {
	cfg := &V2Ray{
		Ps:          "node",
		Add:         "example.com",
		Port:        "443",
		ID:          "uuid",
		Net:         "tcp",
		Type:        "none",
		TLS:         "tls",
		SNI:         "server.example",
		Fingerprint: "chrome",
		Alpn:        "h2,http/1.1",
		Flow:        vless.XRV,
		Protocol:    "vless",
	}

	exported := cfg.ExportToURL()
	if !strings.Contains(exported, "flow=xtls-rprx-vision") {
		t.Fatalf("expected exported URL to contain xtls-rprx-vision flow, got %q", exported)
	}
	if !strings.Contains(exported, "fp=chrome") {
		t.Fatalf("expected exported URL to contain fp=chrome, got %q", exported)
	}
	if !strings.Contains(exported, "alpn=h2%2Chttp%2F1.1") {
		t.Fatalf("expected exported URL to contain encoded alpn, got %q", exported)
	}
}
