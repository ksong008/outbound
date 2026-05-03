package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type cacheKeyDialer struct{}

func (cacheKeyDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

func TestClientConnCacheKeyIncludesRouteAndTLSContext(t *testing.T) {
	dialer := cacheKeyDialer{}
	base := newClientConnCacheKey(dialer, "server-a", "proxy.example:443", false, 1, false)
	if base == newClientConnCacheKey(dialer, "server-a", "proxy.example:443", false, 1, false) {
	} else {
		t.Fatalf("expected identical inputs to produce identical cache keys")
	}
	if base == newClientConnCacheKey(dialer, "server-b", "proxy.example:443", false, 1, false) {
		t.Fatalf("expected serverName to affect cache key")
	}
	if base == newClientConnCacheKey(dialer, "server-a", "proxy.example:443", true, 1, false) {
		t.Fatalf("expected allowInsecure to affect cache key")
	}
	if base == newClientConnCacheKey(dialer, "server-a", "proxy.example:443", false, 2, false) {
		t.Fatalf("expected mark to affect cache key")
	}
	if base == newClientConnCacheKey(dialer, "server-a", "proxy.example:443", false, 1, true) {
		t.Fatalf("expected mptcp to affect cache key")
	}
}

func TestDetachedStreamContextStopsFollowingAfterSetup(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	streamCtx, streamCancel, _ := newDetachedStreamContext(parent)
	defer streamCancel()

	cancelParent()
	select {
	case <-streamCtx.Done():
	case <-time.After(time.Second):
		t.Fatalf("expected parent cancellation to propagate before stopFollowing")
	}

	parent2, cancelParent2 := context.WithCancel(context.Background())
	streamCtx2, streamCancel2, stopFollowing2 := newDetachedStreamContext(parent2)
	stopFollowing2()
	cancelParent2()
	defer streamCancel2()

	select {
	case <-streamCtx2.Done():
		t.Fatalf("expected detached stream context to ignore parent cancellation after stopFollowing")
	case <-time.After(50 * time.Millisecond):
	}
}
