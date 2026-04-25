package shadowsocks

import (
	"strings"
	"testing"

	dialerpkg "github.com/daeuniverse/outbound/dialer"
)

const testSS2022PSK128 = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

func TestParseSSURL2022(t *testing.T) {
	link := "ss://2022-blake3-aes-128-gcm:" + testSS2022PSK128 + "@example.com:443#node"

	ss, err := ParseSSURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Cipher != "2022-blake3-aes-128-gcm" {
		t.Fatalf("unexpected cipher: %q", ss.Cipher)
	}
	if ss.Password != testSS2022PSK128 {
		t.Fatalf("unexpected password: %q", ss.Password)
	}
	if ss.Server != "example.com" || ss.Port != 443 {
		t.Fatalf("unexpected target: %s:%d", ss.Server, ss.Port)
	}
}

func TestExportToURL2022UsesPlainUserInfo(t *testing.T) {
	ss := &Shadowsocks{
		Name:     "node",
		Server:   "example.com",
		Port:     443,
		Password: testSS2022PSK128,
		Cipher:   "2022-blake3-aes-128-gcm",
		Protocol: "shadowsocks",
	}

	link := ss.ExportToURL()
	if !strings.HasPrefix(link, "ss://2022-blake3-aes-128-gcm:") {
		t.Fatalf("unexpected exported prefix: %s", link)
	}

	parsed, err := ParseSSURL(link)
	if err != nil {
		t.Fatalf("failed to parse exported link: %v", err)
	}
	if parsed.Cipher != ss.Cipher || parsed.Password != ss.Password {
		t.Fatalf("unexpected round-trip result: cipher=%q password=%q", parsed.Cipher, parsed.Password)
	}
}

func TestShadowsocksDialer2022Registration(t *testing.T) {
	ss := &Shadowsocks{
		Name:     "node",
		Server:   "example.com",
		Port:     443,
		Password: testSS2022PSK128,
		Cipher:   "2022-blake3-aes-128-gcm",
		Protocol: "shadowsocks",
	}

	if _, _, err := ss.Dialer(&dialerpkg.ExtraOption{}, nil); err != nil {
		t.Fatalf("expected shadowsocks_2022 dialer to be registered, got error: %v", err)
	}
}

func TestParseSip003WithoutOptions(t *testing.T) {
	plugin := ParseSip003("v2ray-plugin")
	if plugin.Name != "v2ray-plugin" {
		t.Fatalf("unexpected plugin name: %q", plugin.Name)
	}
}

func TestParseSSURL2022Chacha20(t *testing.T) {
	psk := "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY="
	link := "ss://2022-blake3-chacha20-poly1305:" + psk + "@example.com:443#node"

	ss, err := ParseSSURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Cipher != "2022-blake3-chacha20-poly1305" {
		t.Fatalf("unexpected cipher: %q", ss.Cipher)
	}
	if _, _, err := ss.Dialer(&dialerpkg.ExtraOption{}, nil); err != nil {
		t.Fatalf("expected chacha20 ss2022 dialer to be registered, got error: %v", err)
	}
}
