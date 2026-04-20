package xhttp

import (
	"testing"
)

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		scheme  string
		want    string
		wantErr bool
	}{
		{name: "auto over https", mode: "auto", scheme: "https", want: "stream-up"},
		{name: "empty over https", mode: "", scheme: "https", want: "stream-up"},
		{name: "stream-up", mode: "stream-up", scheme: "https", want: "stream-up"},
		{name: "stream-one over https", mode: "stream-one", scheme: "https", want: "stream-one"},
		{name: "packet-up over https", mode: "packet-up", scheme: "https", want: "packet-up"},
		{name: "auto over http unsupported", mode: "auto", scheme: "http", wantErr: true},
		{name: "stream-one over http unsupported", mode: "stream-one", scheme: "http", wantErr: true},
		{name: "packet-up over http unsupported", mode: "packet-up", scheme: "http", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMode(tt.mode, tt.scheme)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParseExtra(t *testing.T) {
	cfg, err := parseExtra(`{"headers":{"User-Agent":"xray","X-Test":"1"},"noGRPCHeader":true}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Headers["User-Agent"] != "xray" {
		t.Fatalf("expected User-Agent header, got %#v", cfg.Headers)
	}
	if !cfg.NoGRPCHeader {
		t.Fatalf("expected noGRPCHeader to be true")
	}
}

func TestParseExtraInvalidJSON(t *testing.T) {
	if _, err := parseExtra(`{invalid`); err == nil {
		t.Fatalf("expected parseExtra to fail for invalid json")
	}
}
