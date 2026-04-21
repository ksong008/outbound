package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
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
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/anytls"
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
	Latency time.Duration
	Note    string
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

func smokeLink(link, target string) result {
	name, mode, alpn := parseMetadata(link)
	start := time.Now()

	d, prop, err := D.NewNetproxyDialerFromLink(direct.SymmetricDirect, &D.ExtraOption{}, link)
	if err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Note: err.Error()}
	}
	if name == "" && prop != nil {
		name = prop.Name
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Note: err.Error()}
	}
	defer conn.Close()

	req := "HEAD /generate_204 HTTP/1.1\r\nHost: clients3.google.com\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Note: err.Error()}
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Note: err.Error()}
	}
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if !strings.Contains(line, "HTTP/") {
		return result{Name: name, Mode: mode, ALPN: alpn, Result: "FAIL", Note: "no HTTP status line"}
	}
	return result{
		Name:    name,
		Mode:    mode,
		ALPN:    alpn,
		Result:  "OK",
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

	target := strings.TrimSpace(os.Getenv("XHTTP_SMOKE_TARGET"))
	if target == "" {
		target = "clients3.google.com:80"
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tMODE\tALPN\tRESULT\tLATENCY\tNOTE")
	for _, link := range links {
		r := smokeLink(link, target)
		latency := "-"
		if r.Latency > 0 {
			latency = r.Latency.Round(time.Millisecond).String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Mode, r.ALPN, r.Result, latency, r.Note)
	}
	_ = tw.Flush()
}
