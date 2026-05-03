package socks5

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestAddressFromString(t *testing.T) {
	tests := []struct {
		addr     string
		wantType AddressType
		wantHost string
		wantIP   string
		wantPort uint16
	}{
		{addr: "example.com:443", wantType: AddressTypeDomain, wantHost: "example.com", wantPort: 443},
		{addr: "1.2.3.4:53", wantType: AddressTypeIPv4, wantIP: "1.2.3.4", wantPort: 53},
		{addr: "[2001:db8::1]:8443", wantType: AddressTypeIPv6, wantIP: "2001:db8::1", wantPort: 8443},
	}
	for _, tt := range tests {
		info, err := AddressFromString(tt.addr)
		if err != nil {
			t.Fatalf("AddressFromString(%q) returned error: %v", tt.addr, err)
		}
		if info.Type != tt.wantType || info.Port != tt.wantPort {
			t.Fatalf("AddressFromString(%q) = %#v", tt.addr, info)
		}
		if tt.wantHost != "" && info.Hostname != tt.wantHost {
			t.Fatalf("expected hostname %q, got %q", tt.wantHost, info.Hostname)
		}
		if tt.wantIP != "" && info.IP != netip.MustParseAddr(tt.wantIP) {
			t.Fatalf("expected ip %q, got %v", tt.wantIP, info.IP)
		}
	}
}

func TestWriteAndReadAddrInfoRoundTrip(t *testing.T) {
	original := &AddressInfo{
		Type:     AddressTypeDomain,
		Hostname: "example.com",
		Port:     443,
	}
	buf := &bytes.Buffer{}
	if err := WriteAddrInfo(original, buf); err != nil {
		t.Fatalf("WriteAddrInfo returned error: %v", err)
	}
	decoded, err := ReadAddrInfo(buf)
	if err != nil {
		t.Fatalf("ReadAddrInfo returned error: %v", err)
	}
	if decoded.Type != original.Type || decoded.Hostname != original.Hostname || decoded.Port != original.Port {
		t.Fatalf("round trip mismatch: %#v != %#v", decoded, original)
	}
}
