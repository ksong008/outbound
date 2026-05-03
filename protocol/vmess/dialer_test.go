package vmess

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	grpcdialer "github.com/daeuniverse/outbound/transport/grpc"
)

type stubParentDialer struct{}

func (d *stubParentDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestTransportDialerForVMessTLSGrpcWrapsParentDialer(t *testing.T) {
	parent := &stubParentDialer{}
	d := &Dialer{
		protocol:        protocol.ProtocolVMessTlsGrpc,
		proxySNI:        "server.example",
		grpcServiceName: "svc",
		nextDialer:      parent,
	}

	got, ok := d.transportDialer().(*grpcdialer.Dialer)
	if !ok {
		t.Fatalf("expected grpc dialer wrapper, got %T", d.transportDialer())
	}
	if got.NextDialer != parent {
		t.Fatalf("expected grpc wrapper to use parent dialer, got %T", got.NextDialer)
	}
	if got.NextDialer == d {
		t.Fatal("grpc wrapper must not recurse back into vmess dialer itself")
	}
	if got.ServiceName != "svc" || got.ServerName != "server.example" {
		t.Fatalf("unexpected grpc wrapper config: %#v", got)
	}
}

func TestTransportDialerForRegularVMessReturnsParentDialer(t *testing.T) {
	parent := &stubParentDialer{}
	d := &Dialer{
		protocol:   protocol.ProtocolVMessTCP,
		nextDialer: parent,
	}
	if got := d.transportDialer(); got != parent {
		t.Fatalf("expected plain vmess to keep parent dialer, got %T", got)
	}
}
