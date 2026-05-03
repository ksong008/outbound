package hysteria2

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	hclient "github.com/daeuniverse/outbound/protocol/hysteria2/client"
)

type fakeHysteriaClient struct{}

func (fakeHysteriaClient) TCP(addr string, ctx context.Context) (netproxy.Conn, error) {
	return &fakePacketConn{}, nil
}

func (fakeHysteriaClient) UDP(addr string, ctx context.Context) (netproxy.Conn, error) {
	return &fakePacketConn{}, nil
}

type fakePacketConn struct{}

func (c *fakePacketConn) Read([]byte) (int, error)    { return 0, nil }
func (c *fakePacketConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakePacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *fakePacketConn) WriteTo(b []byte, addr string) (int, error) { return len(b), nil }
func (c *fakePacketConn) Close() error                               { return nil }
func (c *fakePacketConn) SetDeadline(time.Time) error                { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error            { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error           { return nil }

type recordingNextDialer struct {
	lastNetwork string
	lastAddr    string
}

func (d *recordingNextDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	d.lastNetwork = network
	d.lastAddr = addr
	return &fakePacketConn{}, nil
}

func TestGetClientForRouteCachesByUnderlayNetwork(t *testing.T) {
	prev := newHysteriaClient
	defer func() { newHysteriaClient = prev }()

	calls := 0
	newHysteriaClient = func(cfg *hclient.Config) (hclient.Client, error) {
		calls++
		return fakeHysteriaClient{}, nil
	}

	d := &Dialer{
		baseConfig: hclient.Config{
			ServerAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		},
		clients: make(map[string]hclient.Client),
	}

	if _, err := d.getClientForRoute("route-a"); err != nil {
		t.Fatalf("getClientForRoute returned error: %v", err)
	}
	if _, err := d.getClientForRoute("route-a"); err != nil {
		t.Fatalf("getClientForRoute returned error: %v", err)
	}
	if _, err := d.getClientForRoute("route-b"); err != nil {
		t.Fatalf("getClientForRoute returned error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected one client per route, got %d factory calls", calls)
	}
}

func TestNewConnFactoryPreservesUnderlayNetwork(t *testing.T) {
	dialer := &recordingNextDialer{}
	d := &Dialer{
		nextDialer: dialer,
		baseConfig: hclient.Config{
			ServerAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
		},
	}

	underlay := netproxy.MagicNetwork{Network: "udp", Mark: 7, Mptcp: true}.Encode()
	factory := d.newConnFactory(underlay)
	conn, err := factory.New(context.Background())
	if err != nil {
		t.Fatalf("factory.New returned error: %v", err)
	}
	_ = conn.Close()

	got, err := netproxy.ParseMagicNetwork(dialer.lastNetwork)
	if err != nil {
		t.Fatalf("ParseMagicNetwork returned error: %v", err)
	}
	if got.Network != "udp" || got.Mark != 7 || !got.Mptcp {
		t.Fatalf("unexpected underlay network: %+v", got)
	}
	if dialer.lastAddr != "127.0.0.1:8443" {
		t.Fatalf("expected server address to be preserved, got %q", dialer.lastAddr)
	}
}
