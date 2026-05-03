package http

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type stubDialer struct {
	dial func(ctx context.Context, network, addr string) (netproxy.Conn, error)
}

func (d stubDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.dial(ctx, network, addr)
}

type stubConn struct {
	closeErr error
	closed   bool
}

func (c *stubConn) Read([]byte) (int, error)         { return 0, nil }
func (c *stubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stubConn) Close() error                     { c.closed = true; return c.closeErr }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestNewHTTPProxyPreservesHTTPSFlags(t *testing.T) {
	u, err := url.Parse("https://proxy.example:443?allowInsecure=1&utlsImitate=chrome&sni=server.example&alpn=h2,http/1.1")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	dialer, err := NewHTTPProxy(u, stubDialer{})
	if err != nil {
		t.Fatalf("NewHTTPProxy returned error: %v", err)
	}

	proxy := dialer.(*HttpProxy)
	tlsValue := reflect.Indirect(reflect.ValueOf(proxy.dialer))
	if !tlsValue.FieldByName("skipVerify").Bool() {
		t.Fatalf("expected nested TLS dialer to preserve allowInsecure")
	}
	if got := tlsValue.FieldByName("utlsImitate").String(); got != "chrome" {
		t.Fatalf("expected nested TLS dialer to preserve utlsImitate, got %q", got)
	}
	tlsConfig := tlsValue.FieldByName("tlsConfig")
	if got := tlsConfig.Elem().FieldByName("ServerName").String(); got != "server.example" {
		t.Fatalf("expected nested TLS dialer to preserve serverName, got %q", got)
	}
	nextProtos := tlsConfig.Elem().FieldByName("NextProtos")
	if nextProtos.Len() != 2 || nextProtos.Index(0).String() != "h2" || nextProtos.Index(1).String() != "http/1.1" {
		t.Fatalf("expected nested TLS dialer to preserve ALPN, got %#v", nextProtos.Interface())
	}
}

func TestConnCloseClosesUnderlyingHTTP1Conn(t *testing.T) {
	raw := &stubConn{closeErr: errors.New("boom")}
	conn := &Conn{
		conn:                raw,
		cancelShakeFinished: func() {},
	}

	err := conn.Close()
	if !raw.closed {
		t.Fatalf("expected Close to close the underlying connection")
	}
	if !errors.Is(err, raw.closeErr) {
		t.Fatalf("expected Close to return underlying error, got %v", err)
	}
}

func TestH2PoolGetClientConnUsesRouteContext(t *testing.T) {
	pool := newH2ConnsPool()
	wantErr := errors.New("route-b")
	pool.routes["route-a"] = h2Route{
		dialer: stubDialer{dial: func(ctx context.Context, network, addr string) (netproxy.Conn, error) {
			return nil, errors.New("route-a")
		}},
		magicNetwork: "route-a",
	}
	pool.routes["route-b"] = h2Route{
		dialer: stubDialer{dial: func(ctx context.Context, network, addr string) (netproxy.Conn, error) {
			return nil, wantErr
		}},
		magicNetwork: "route-b",
	}

	req, err := http.NewRequestWithContext(context.WithValue(context.Background(), h2RouteContextKey{}, "route-b"), http.MethodConnect, "https://proxy.example", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext returned error: %v", err)
	}

	_, err = pool.GetClientConn(req, "proxy.example:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected route-b dialer error, got %v", err)
	}
}
