package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/anytls"
	_ "github.com/daeuniverse/outbound/dialer/http"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/juicity"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocksr"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/tuic"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/anytls"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/hysteria2"
	_ "github.com/daeuniverse/outbound/protocol/juicity"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	_ "github.com/daeuniverse/outbound/protocol/tuic"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
	_ "github.com/daeuniverse/outbound/transport/grpc"
	_ "github.com/daeuniverse/outbound/transport/httpupgrade"
	_ "github.com/daeuniverse/outbound/transport/meek"
	_ "github.com/daeuniverse/outbound/transport/simpleobfs"
	_ "github.com/daeuniverse/outbound/transport/tls"
	_ "github.com/daeuniverse/outbound/transport/ws"
	_ "github.com/daeuniverse/outbound/transport/xhttp"
)

type result struct {
	Name    string
	Mode    string
	ALPN    string
	Result  string
	Phase   string
	Latency time.Duration
	Note    string
}

type smokeTarget struct {
	Addr       string
	Host       string
	ServerName string
	Path       string
	TLS        bool
	Method     string
}

func parseLinks() ([]string, error) {
	if raw := strings.TrimSpace(os.Getenv("XHTTP_SMOKE_LINKS")); raw != "" {
		lines := strings.Split(raw, "\n")
		links := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			links = append(links, line)
		}
		return links, nil
	}

	file := strings.TrimSpace(os.Getenv("XHTTP_SMOKE_FILE"))
	if file == "" {
		return nil, fmt.Errorf("set XHTTP_SMOKE_LINKS or XHTTP_SMOKE_FILE")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var links []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		links = append(links, line)
	}
	return links, scanner.Err()
}

func parseMetadata(link string) (name, mode, alpn string) {
	u, err := url.Parse(link)
	if err != nil {
		return "", "", ""
	}
	return u.Fragment, u.Query().Get("mode"), u.Query().Get("alpn")
}

func parseSmokeTarget() (smokeTarget, error) {
	method := strings.ToUpper(strings.TrimSpace(os.Getenv("XHTTP_SMOKE_METHOD")))
	if method == "" {
		method = "HEAD"
	}
	rawURL := strings.TrimSpace(os.Getenv("XHTTP_SMOKE_URL"))
	rawTarget := strings.TrimSpace(os.Getenv("XHTTP_SMOKE_TARGET"))
	if rawURL == "" {
		if rawTarget == "" {
			rawTarget = "clients3.google.com:80"
		}
		return smokeTarget{
			Addr:       rawTarget,
			Host:       "clients3.google.com",
			ServerName: "clients3.google.com",
			Path:       "/generate_204",
			Method:     method,
		}, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return smokeTarget{}, err
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return smokeTarget{}, fmt.Errorf("unsupported smoke URL scheme %q", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	requestURI := u.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	return smokeTarget{
		Addr:       net.JoinHostPort(u.Hostname(), port),
		Host:       u.Host,
		ServerName: u.Hostname(),
		Path:       requestURI,
		TLS:        u.Scheme == "https",
		Method:     method,
	}, nil
}

func smokeLink(link string, target smokeTarget) result {
	name, mode, alpn := parseMetadata(link)
	start := time.Now()

	d, prop, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &D.ExtraOption{}, link)
	if err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "parse", Note: err.Error()}
	}
	if name == "" && prop != nil {
		name = prop.Name
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target.Addr)
	if err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "dial", Note: err.Error()}
	}
	defer conn.Close()

	rw := io.ReadWriter(conn)
	if target.TLS {
		tlsConn := tls.Client(&netproxy.FakeNetConn{Conn: conn}, &tls.Config{
			ServerName: target.ServerName,
			NextProtos: []string{
				"http/1.1",
			},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "tls", Note: err.Error()}
		}
		defer tlsConn.Close()
		rw = tlsConn
	}

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 xhttp-smoke\r\nAccept: */*\r\nConnection: close\r\n\r\n", target.Method, target.Path, target.Host)
	if _, err := io.WriteString(rw, req); err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "write", Note: err.Error()}
	}
	buf := make([]byte, 256)
	n, err := rw.Read(buf)
	if err != nil && err != io.EOF {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "read", Note: err.Error()}
	}
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if !strings.Contains(line, "HTTP/") {
		note := fmt.Sprintf("no HTTP status line: %q", string(buf[:n]))
		if n == 0 {
			note = "no HTTP status line: empty response"
		}
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Phase: "read", Note: note}
	}
	return result{
		Name:    name,
		Mode:    mode,
		ALPN:    alpn,
		Result:  "OK",
		Phase:   "read",
		Latency: time.Since(start),
		Note:    line,
	}
}

func main() {
	direct.InitDirectDialers("8.8.8.8:53")

	links, err := parseLinks()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "error: no links provided")
		os.Exit(1)
	}

	target, err := parseSmokeTarget()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tMODE\tALPN\tRESULT\tPHASE\tLATENCY\tNOTE")
	for _, link := range links {
		r := smokeLink(link, target)
		latency := "-"
		if r.Latency > 0 {
			latency = r.Latency.Round(time.Millisecond).String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Mode, r.ALPN, r.Result, r.Phase, latency, r.Note)
	}
	_ = tw.Flush()
}
