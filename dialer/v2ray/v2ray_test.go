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

func TestParseVlessURLXHTTP(t *testing.T) {
	cfg, err := ParseVlessURL("vless://uuid@example.com:443?type=xhttp&security=tls&host=example.com&path=%2Fx&mode=auto&extra=seed&sni=sni.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1#xhttp")
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}
	if cfg.Net != "xhttp" {
		t.Fatalf("expected network xhttp, got %q", cfg.Net)
	}
	if cfg.XHTTPMode != "auto" {
		t.Fatalf("expected xhttp mode auto, got %q", cfg.XHTTPMode)
	}
	if cfg.XHTTPExtra != "seed" {
		t.Fatalf("expected xhttp extra seed, got %q", cfg.XHTTPExtra)
	}
	if cfg.Path != "/x" {
		t.Fatalf("expected xhttp path /x, got %q", cfg.Path)
	}
	if !cfg.AllowInsecure {
		t.Fatalf("expected allowInsecure to be true")
	}
}

func TestExportVlessURLXHTTP(t *testing.T) {
	cfg := &V2Ray{
		Ps:         "xhttp",
		Add:        "example.com",
		Port:       "443",
		ID:         "uuid",
		Net:        "xhttp",
		Host:       "example.com",
		Path:       "/x",
		TLS:        "tls",
		SNI:        "sni.example.com",
		Alpn:       "h2,http/1.1",
		AllowInsecure: true,
		XHTTPMode:  "auto",
		XHTTPExtra: "seed",
		Protocol:   "vless",
	}

	exported := cfg.ExportToURL()
	if !strings.Contains(exported, "type=xhttp") {
		t.Fatalf("expected exported URL to contain type=xhttp, got %q", exported)
	}
	if strings.Contains(exported, "mode=auto") {
		t.Fatalf("expected exported URL to omit default auto mode, got %q", exported)
	}
	if !strings.Contains(exported, "extra=seed") {
		t.Fatalf("expected exported URL to contain extra=seed, got %q", exported)
	}
	if !strings.Contains(exported, "allowInsecure=1") {
		t.Fatalf("expected exported URL to contain allowInsecure=1, got %q", exported)
	}
}

func TestExportVlessURLXHTTPCanonicalExtra(t *testing.T) {
	cfg := &V2Ray{
		Ps:         "xhttp",
		Add:        "example.com",
		Port:       "443",
		ID:         "uuid",
		Net:        "xhttp",
		Host:       "example.com",
		Path:       "/x",
		TLS:        "tls",
		SNI:        "sni.example.com",
		XHTTPExtra: "{\n  \"b\":2,\n  \"a\":1\n}",
		Protocol:   "vless",
	}

	exported := cfg.ExportToURL()
	if !strings.Contains(exported, "extra=%7B%22a%22%3A1%2C%22b%22%3A2%7D") {
		t.Fatalf("expected canonicalized extra JSON, got %q", exported)
	}
}

func TestParseVlessURLXHTTPReality(t *testing.T) {
	cfg, err := ParseVlessURL("vless://uuid@example.com:443?type=xhttp&security=reality&host=example.com&path=%2Fx&mode=auto&sni=server.example&fp=chrome&pbk=pubkey&sid=abcd&spx=%2F#xhttp-reality")
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}
	if cfg.TLS != "reality" {
		t.Fatalf("expected security reality, got %q", cfg.TLS)
	}
	if cfg.XHTTPMode != "auto" {
		t.Fatalf("expected xhttp mode auto, got %q", cfg.XHTTPMode)
	}
	if cfg.Fingerprint != "chrome" {
		t.Fatalf("expected fingerprint chrome, got %q", cfg.Fingerprint)
	}
	if cfg.PublicKey != "pubkey" {
		t.Fatalf("expected public key pubkey, got %q", cfg.PublicKey)
	}
	if cfg.ShortId != "abcd" {
		t.Fatalf("expected short id abcd, got %q", cfg.ShortId)
	}
	if cfg.SpiderX != "/" {
		t.Fatalf("expected spider x /, got %q", cfg.SpiderX)
	}
}

func TestExportVlessURLXHTTPReality(t *testing.T) {
	cfg := &V2Ray{
		Ps:          "xhttp-reality",
		Add:         "example.com",
		Port:        "443",
		ID:          "uuid",
		Net:         "xhttp",
		Host:        "example.com",
		Path:        "/x",
		TLS:         "reality",
		SNI:         "server.example",
		Fingerprint: "chrome",
		PublicKey:   "pubkey",
		ShortId:     "abcd",
		SpiderX:     "/",
		XHTTPMode:   "auto",
		Protocol:    "vless",
	}

	exported := cfg.ExportToURL()
	for _, fragment := range []string{"type=xhttp", "security=reality", "fp=chrome", "pbk=pubkey", "sid=abcd", "spx=%2F"} {
		if !strings.Contains(exported, fragment) {
			t.Fatalf("expected exported URL to contain %q, got %q", fragment, exported)
		}
	}
}
