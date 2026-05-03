package v2ray

import (
	"strings"
	"testing"

	outbounddialer "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
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

func TestParseVlessURLTreatsNoneFlowAsEmpty(t *testing.T) {
	cfg, err := ParseVlessURL("vless://7c12c745-63a5-433d-9e60-022e469b5bd4@156.246.90.2:18447?type=xhttp&security=tls&host=office.mitsuha.me&headerType=none&sni=office.mitsuha.me&flow=none&allowInsecure=false&path=%2Fxhttp&mode=packet-up&alpn=h3&fp=chrome#xhttp-h3-packet-up-18447")
	if err != nil {
		t.Fatalf("ParseVlessURL returned error: %v", err)
	}
	if cfg.Flow != "" {
		t.Fatalf("expected flow none to be treated as empty, got %q", cfg.Flow)
	}
}

func TestNewV2RayAcceptsNoneFlow(t *testing.T) {
	link := "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@156.246.90.2:18447?type=xhttp&security=tls&host=office.mitsuha.me&headerType=none&sni=office.mitsuha.me&flow=none&allowInsecure=false&path=%2Fxhttp&mode=packet-up&alpn=h3&fp=chrome#xhttp-h3-packet-up-18447"
	_, property, err := NewV2Ray(&outbounddialer.ExtraOption{}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewV2Ray returned error: %v", err)
	}
	if strings.Contains(property.Link, "flow=none") || strings.Contains(property.Link, "flow=") {
		t.Fatalf("expected exported property link to omit placeholder flow, got %q", property.Link)
	}
}

func TestExportVlessURLOmitsNoneFlow(t *testing.T) {
	cfg := &V2Ray{
		Ps:       "node",
		Add:      "example.com",
		Port:     "443",
		ID:       "uuid",
		Net:      "xhttp",
		Host:     "example.com",
		Path:     "/xhttp",
		TLS:      "tls",
		SNI:      "server.example",
		Flow:     "none",
		Protocol: "vless",
	}

	exported := cfg.ExportToURL()
	if strings.Contains(exported, "flow=none") || strings.Contains(exported, "flow=") {
		t.Fatalf("expected exported URL to omit placeholder flow, got %q", exported)
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

func TestParseVlessURLAllowInsecureAliases(t *testing.T) {
	for _, raw := range []string{
		"vless://uuid@example.com:443?type=tcp&security=tls&skipVerify=1#node",
		"vless://uuid@example.com:443?type=tcp&security=tls&allow_insecure=true#node",
		"vless://uuid@example.com:443?type=tcp&security=tls&allowinsecure=1#node",
	} {
		cfg, err := ParseVlessURL(raw)
		if err != nil {
			t.Fatalf("ParseVlessURL returned error: %v", err)
		}
		if !cfg.AllowInsecure {
			t.Fatalf("expected allowInsecure to be true for %q", raw)
		}
	}
}

func TestExportVlessURLXHTTP(t *testing.T) {
	cfg := &V2Ray{
		Ps:            "xhttp",
		Add:           "example.com",
		Port:          "443",
		ID:            "uuid",
		Net:           "xhttp",
		Host:          "example.com",
		Path:          "/x",
		TLS:           "tls",
		SNI:           "sni.example.com",
		Alpn:          "h2,http/1.1",
		AllowInsecure: true,
		XHTTPMode:     "auto",
		XHTTPExtra:    "seed",
		Protocol:      "vless",
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

func TestExportVlessURLMeekPreservesURLField(t *testing.T) {
	cfg := &V2Ray{
		Ps:       "meek",
		Add:      "example.com",
		Port:     "443",
		ID:       "uuid",
		Net:      "meek",
		Path:     "https://front.example/meek",
		TLS:      "tls",
		SNI:      "front.example",
		Protocol: "vless",
	}

	exported := cfg.ExportToURL()
	if !strings.Contains(exported, "url=https%3A%2F%2Ffront.example%2Fmeek") {
		t.Fatalf("expected exported URL to preserve meek url field, got %q", exported)
	}
}
