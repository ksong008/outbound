package http

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	https     bool
	transport bool
	Addr      string
	Host      string
	Path      string
	HaveAuth  bool
	Username  string
	Password  string
	dialer    netproxy.Dialer
	h2Pool    *h2ConnsPool
}

func NewHTTPProxy(u *url.URL, forward netproxy.Dialer) (netproxy.Dialer, error) {
	s := new(HttpProxy)
	s.Addr = u.Host
	s.Path = u.Path
	if !strings.HasPrefix(s.Path, "/") {
		s.Path = "/" + s.Path
	}
	s.Host = u.Query().Get("host")
	s.dialer = forward
	s.h2Pool = newH2ConnsPool()
	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	s.transport, _ = strconv.ParseBool(u.Query().Get("transport"))
	if u.Scheme == "https" {
		s.https = true
		serverName := u.Query().Get("sni")
		if serverName == "" {
			serverName = u.Hostname()
		}

		tlsImplementation := "tls"
		if u.Query().Get("tlsImplementation") != "" {
			tlsImplementation = u.Query().Get("tlsImplementation")
		}
		alpn := []string{"h2,http/1.1"}
		if u.Query().Get("alpn") != "" {
			alpn = []string{u.Query().Get("alpn")}
		}
		tlsURL := url.URL{
			Host: s.Addr,
			RawQuery: url.Values{
				"sni":           []string{serverName},
				"alpn":          alpn,
				"allowInsecure": []string{strconv.FormatBool(common.ParseAllowInsecure(u.Query()))},
				"utlsImitate":   []string{u.Query().Get("utlsImitate")},
			}.Encode(),
		}
		var err error
		s.dialer, _, err = tls2.NewTls(&dialer.ExtraOption{
			AllowInsecure:     common.ParseAllowInsecure(u.Query()),
			TlsImplementation: tlsImplementation,
			UtlsImitate:       u.Query().Get("utlsImitate"),
		}, s.dialer, tlsURL.String())
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *HttpProxy) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return NewConn(s.dialer, s, addr, network), nil
	case "udp":
		return nil, netproxy.UnsupportedTunnelTypeError
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
