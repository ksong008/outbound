package mux

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type stubMuxDialer struct {
	lastNetwork string
	lastAddr    string
	conn        netproxy.Conn
}

func (d *stubMuxDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.lastNetwork = network
	d.lastAddr = addr
	return d.conn, nil
}

type stubMuxConn struct{}

func (c *stubMuxConn) Read([]byte) (int, error)         { return 0, nil }
func (c *stubMuxConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stubMuxConn) Close() error                     { return nil }
func (c *stubMuxConn) SetDeadline(time.Time) error      { return nil }
func (c *stubMuxConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubMuxConn) SetWriteDeadline(time.Time) error { return nil }

func TestMuxDialContextWrapsTCP(t *testing.T) {
	parent := &stubMuxDialer{conn: &stubMuxConn{}}
	d := &Mux{NextDialer: parent, Addr: "proxy.example:443"}
	conn, err := d.DialContext(context.Background(), "tcp", "target.example:80")
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	if _, ok := conn.(*Conn); !ok {
		t.Fatalf("expected mux connection wrapper, got %T", conn)
	}
	if parent.lastNetwork != "tcp" || parent.lastAddr != "target.example:80" {
		t.Fatalf("unexpected parent dial call: network=%q addr=%q", parent.lastNetwork, parent.lastAddr)
	}
}

func TestMuxDialContextPassthroughUDP(t *testing.T) {
	parentConn := &stubMuxConn{}
	parent := &stubMuxDialer{conn: parentConn}
	d := &Mux{NextDialer: parent, Addr: "proxy.example:443", PassthroughUdp: true}
	conn, err := d.DialContext(context.Background(), "udp", "target.example:53")
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	if conn != parentConn {
		t.Fatalf("expected passthrough UDP conn, got %T", conn)
	}
}
