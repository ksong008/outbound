package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

var (
	globalRoundTripperCacheMap    map[roundTripperCacheKey]http.RoundTripper
	globalRoundTripperCacheAccess sync.Mutex
)

type roundTripperCacheKey struct {
	addr         string
	url          string
	magicNetwork string
	serverName   string
	alpn         string
	dialer       string
	skipVerify   bool
}

type httpTripperClient struct {
	addr         string
	nextDialer   netproxy.Dialer
	tlsConfig    *tls.Config
	url          string
	magicNetwork string
}

func CleanGlobalRoundTripperCache() {
	globalRoundTripperCacheAccess.Lock()
	old := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = make(map[roundTripperCacheKey]http.RoundTripper)
	globalRoundTripperCacheAccess.Unlock()

	for _, rt := range old {
		if closer, ok := rt.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	roundTripper := c.getRoundTripper()

	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer httpResp.Body.Close()

	result, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}

func (c *httpTripperClient) getRoundTripper() http.RoundTripper {
	key := roundTripperCacheKey{
		addr:         c.addr,
		url:          c.url,
		magicNetwork: c.magicNetwork,
		serverName:   c.tlsConfig.ServerName,
		alpn:         strings.Join(c.tlsConfig.NextProtos, ","),
		dialer:       common.IdentityKey(c.nextDialer),
		skipVerify:   c.tlsConfig.InsecureSkipVerify,
	}

	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if globalRoundTripperCacheMap == nil {
		globalRoundTripperCacheMap = make(map[roundTripperCacheKey]http.RoundTripper)
	}
	if _, ok := globalRoundTripperCacheMap[key]; !ok {
		globalRoundTripperCacheMap[key] = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rc, err := c.nextDialer.DialContext(ctx, c.magicNetwork, addr)
				if err != nil {
					return nil, fmt.Errorf("[Meek]: dial to %s: %w", c.addr, err)
				}
				return &netproxy.FakeNetConn{
					Conn:  rc,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: c.tlsConfig,
		}
	}
	return globalRoundTripperCacheMap[key]
}
