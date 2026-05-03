package simpleobfs

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type stubSimpleObfsDialer struct{}

func (d *stubSimpleObfsDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewSimpleObfsParsesHTTPConfig(t *testing.T) {
	d, prop, err := NewSimpleObfs(&dialer.ExtraOption{}, &stubSimpleObfsDialer{}, "simple-obfs://example.com:443?obfs=http&host=cover.example&uri=/cdn#node")
	if err != nil {
		t.Fatalf("NewSimpleObfs returned error: %v", err)
	}
	obfs, ok := d.(*SimpleObfs)
	if !ok {
		t.Fatalf("expected *SimpleObfs, got %T", d)
	}
	if obfs.obfstype != HTTP {
		t.Fatalf("expected HTTP obfs type, got %v", obfs.obfstype)
	}
	if obfs.host != "cover.example" || obfs.path != "/cdn" {
		t.Fatalf("unexpected parsed config: host=%q path=%q", obfs.host, obfs.path)
	}
	if prop == nil || prop.Protocol != "simpleobfs(http)" {
		t.Fatalf("unexpected property: %#v", prop)
	}
}

func TestNewSimpleObfsParsesTLSConfig(t *testing.T) {
	d, _, err := NewSimpleObfs(&dialer.ExtraOption{}, &stubSimpleObfsDialer{}, "simple-obfs://example.com:443?type=tls")
	if err != nil {
		t.Fatalf("NewSimpleObfs returned error: %v", err)
	}
	obfs := d.(*SimpleObfs)
	if obfs.obfstype != TLS {
		t.Fatalf("expected TLS obfs type, got %v", obfs.obfstype)
	}
}
