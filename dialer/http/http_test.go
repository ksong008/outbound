package http

import "testing"

func TestParseHTTPURLAllowInsecureAliases(t *testing.T) {
	for _, raw := range []string{
		"https://proxy.example:443?skipVerify=1#node",
		"https://proxy.example:443?allow_insecure=true#node",
		"https://proxy.example:443?allowinsecure=1#node",
	} {
		cfg, err := ParseHTTPURL(raw)
		if err != nil {
			t.Fatalf("ParseHTTPURL returned error: %v", err)
		}
		if !cfg.AllowInsecure {
			t.Fatalf("expected allowInsecure to be true for %q", raw)
		}
	}
}

func TestHTTPExportPreservesAllowInsecureWithoutSNI(t *testing.T) {
	cfg := &HTTP{
		Name:          "node",
		Server:        "proxy.example",
		Port:          443,
		Protocol:      "https",
		AllowInsecure: true,
	}

	exported := cfg.ExportToURL()
	if exported != "https://proxy.example:443?allowInsecure=1#node" {
		t.Fatalf("unexpected exported URL: %q", exported)
	}
}
