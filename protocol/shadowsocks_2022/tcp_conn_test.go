package shadowsocks_2022

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

const testSS2022PSK128 = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

func TestEncodeRequestHeaderAddsPaddingWhenNoInitialPayload(t *testing.T) {
	payload := []byte{}
	addr, err := socks5.AddressFromString("example.com:443")
	if err != nil {
		t.Fatal(err)
	}

	fixedHeader, varHeader, err := EncodeRequestHeader(HeaderTypeClientStream, 1, addr, &payload)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.PutBuffer(fixedHeader)
	defer pool.PutBuffer(varHeader)

	if fixedHeader.Len() != 11 {
		t.Fatalf("unexpected fixed header length: %d", fixedHeader.Len())
	}
	if varHeader.Len() <= 0 {
		t.Fatalf("unexpected variable header length: %d", varHeader.Len())
	}
	addrBuf := pool.GetBuffer()
	defer pool.PutBuffer(addrBuf)
	if err := socks5.WriteAddrInfo(addr, addrBuf); err != nil {
		t.Fatal(err)
	}
	paddingOffset := addrBuf.Len()
	paddingLen := binary.BigEndian.Uint16(varHeader.Bytes()[paddingOffset : paddingOffset+2])
	if paddingLen == 0 {
		t.Fatal("expected non-zero padding length when initial payload is empty")
	}
}

type readCounterConn struct {
	*bytes.Reader
	readCalls int
}

func (c *readCounterConn) Read(p []byte) (int, error) {
	c.readCalls++
	return c.Reader.Read(p)
}

func (c *readCounterConn) Write([]byte) (int, error)        { return 0, nil }
func (c *readCounterConn) Close() error                     { return nil }
func (c *readCounterConn) SetDeadline(time.Time) error      { return nil }
func (c *readCounterConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readCounterConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPConnInitialReadUsesSingleReadForSaltAndFixedHeader(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	if conf == nil {
		t.Fatal("missing test cipher config")
	}
	uPSK, err := ciphers.ValidateBase64PSK(testSS2022PSK128, conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}

	responseSalt := make([]byte, conf.SaltLen)
	copy(responseSalt, []byte("1234567890123456"))
	requestSalt := make([]byte, conf.SaltLen)
	copy(requestSalt, []byte("abcdefghijklmnop"))

	aead, err := CreateCipher(uPSK, responseSalt, conf)
	if err != nil {
		t.Fatal(err)
	}
	nonce0 := make([]byte, conf.NonceLen)
	fixedHeader := make([]byte, 0, 11+conf.SaltLen)
	fixedHeader = append(fixedHeader, HeaderTypeServerStream)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	fixedHeader = append(fixedHeader, ts...)
	fixedHeader = append(fixedHeader, requestSalt...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 0)
	fixedHeader = append(fixedHeader, length...)
	encryptedFixed := aead.Seal(nil, nonce0, fixedHeader, nil)

	nonce1 := incrementNonce(nonce0)
	encryptedPayload := aead.Seal(nil, nonce1, nil, nil)

	wire := append([]byte{}, responseSalt...)
	wire = append(wire, encryptedFixed...)
	wire = append(wire, encryptedPayload...)

	conn := &readCounterConn{Reader: bytes.NewReader(wire)}
	tcpConn := NewTCPConn(conn, conf, [][]byte{uPSK}, uPSK, nil, nil, nil).(*TCPConn)
	tcpConn.requestSalt = requestSalt
	tcpConn.onceWrite = true

	buf := make([]byte, 16)
	n, err := tcpConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected empty payload, got %d bytes", n)
	}
	if conn.readCalls != 2 {
		t.Fatalf("expected 2 underlying reads, got %d", conn.readCalls)
	}
}

func TestTCPConnRejectsZeroLengthFirstResponsePayload(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	if conf == nil {
		t.Fatal("missing test cipher config")
	}
	uPSK, err := ciphers.ValidateBase64PSK(testSS2022PSK128, conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}

	responseSalt := make([]byte, conf.SaltLen)
	copy(responseSalt, []byte("1234567890123456"))
	requestSalt := make([]byte, conf.SaltLen)
	copy(requestSalt, []byte("abcdefghijklmnop"))

	aead, err := CreateCipher(uPSK, responseSalt, conf)
	if err != nil {
		t.Fatal(err)
	}
	nonce0 := make([]byte, conf.NonceLen)
	fixedHeader := make([]byte, 0, 11+conf.SaltLen)
	fixedHeader = append(fixedHeader, HeaderTypeServerStream)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	fixedHeader = append(fixedHeader, ts...)
	fixedHeader = append(fixedHeader, requestSalt...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 0)
	fixedHeader = append(fixedHeader, length...)
	encryptedFixed := aead.Seal(nil, nonce0, fixedHeader, nil)

	wire := append([]byte{}, responseSalt...)
	wire = append(wire, encryptedFixed...)

	conn := &readCounterConn{Reader: bytes.NewReader(wire)}
	tcpConn := NewTCPConn(conn, conf, [][]byte{uPSK}, uPSK, nil, nil, nil).(*TCPConn)
	tcpConn.requestSalt = requestSalt
	tcpConn.onceWrite = true

	buf := make([]byte, 16)
	if _, err := tcpConn.Read(buf); err == nil {
		t.Fatal("expected zero-length first response payload to be rejected")
	}
}

func incrementNonce(src []byte) []byte {
	dst := append([]byte(nil), src...)
	for i := 0; i < len(dst); i++ {
		dst[i]++
		if dst[i] != 0 {
			break
		}
	}
	return dst
}
