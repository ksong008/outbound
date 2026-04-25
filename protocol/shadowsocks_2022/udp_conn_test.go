package shadowsocks_2022

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type packetBufferConn struct {
	read  *bytes.Reader
	write bytes.Buffer
}

func (c *packetBufferConn) Read(p []byte) (int, error) {
	if c.read == nil {
		return 0, io.EOF
	}
	return c.read.Read(p)
}

func (c *packetBufferConn) Write(p []byte) (int, error) {
	return c.write.Write(p)
}

func (c *packetBufferConn) Close() error                     { return nil }
func (c *packetBufferConn) SetDeadline(time.Time) error      { return nil }
func (c *packetBufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *packetBufferConn) SetWriteDeadline(time.Time) error { return nil }

func TestUdpConnFirstPacketIDStartsAtZero(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	uPSK, err := ciphers.ValidateBase64PSK(testSS2022PSK128, conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		t.Fatal(err)
	}

	conn := &packetBufferConn{}
	udpConn, err := NewUdpConn(conn, "1.1.1.1:53", conf, block, block, [][]byte{uPSK}, uPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpConn.WriteTo([]byte("hello"), "1.1.1.1:53"); err != nil {
		t.Fatal(err)
	}

	header := make([]byte, 16)
	block.Decrypt(header, conn.write.Bytes()[:16])
	if packetID := binary.BigEndian.Uint64(header[8:16]); packetID != 0 {
		t.Fatalf("expected first packet ID 0, got %d", packetID)
	}
}

func TestUdpConnRejectsFutureTimestamp(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	uPSK, err := ciphers.ValidateBase64PSK(testSS2022PSK128, conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		t.Fatal(err)
	}

	conn := &packetBufferConn{}
	udpConn, err := NewUdpConn(conn, "1.1.1.1:53", conf, block, block, [][]byte{uPSK}, uPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := buildAESUDPServerPacket(t, conf, uPSK, block, udpConn.sessionID, 1, time.Now().Add(2*ciphers.TimestampTolerance), []byte("reply"))
	conn.read = bytes.NewReader(wire)

	if _, _, err := udpConn.ReadFrom(make([]byte, 64)); err != protocol.ErrReplayAttack {
		t.Fatalf("expected replay attack error, got %v", err)
	}
}

func TestUdpConnChacha20PacketRoundTrip(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	uPSK, err := ciphers.ValidateBase64PSK("MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=", conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		t.Fatal(err)
	}

	conn := &packetBufferConn{}
	udpConn, err := NewUdpConn(conn, "1.1.1.1:53", conf, block, block, [][]byte{uPSK}, uPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpConn.WriteTo([]byte("hello"), "1.1.1.1:53"); err != nil {
		t.Fatal(err)
	}

	nonce := conn.write.Bytes()[:conf.PacketNonceLen]
	ciphertext := conn.write.Bytes()[conf.PacketNonceLen:]
	payload, err := udpConn.packetCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(payload)
	var clientSessionID [8]byte
	if _, err := io.ReadFull(reader, clientSessionID[:]); err != nil {
		t.Fatal(err)
	}
	if clientSessionID != udpConn.sessionID {
		t.Fatal("unexpected client session ID")
	}
	var packetID uint64
	if err := binary.Read(reader, binary.BigEndian, &packetID); err != nil {
		t.Fatal(err)
	}
	if packetID != 0 {
		t.Fatalf("expected first packet ID 0, got %d", packetID)
	}

	wire := buildChachaUDPServerPacket(t, udpConn.packetCipher, conf, udpConn.sessionID, 1, time.Now(), []byte("reply"))
	conn.read = bytes.NewReader(wire)
	buf := make([]byte, 64)
	n, addr, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "reply" {
		t.Fatalf("unexpected payload: %q", got)
	}
	if addr.String() != "8.8.8.8:53" {
		t.Fatalf("unexpected addr: %s", addr)
	}
}

func buildAESUDPServerPacket(t *testing.T, conf *ciphers.CipherConf2022, uPSK []byte, block cipherBlock, clientSessionID [8]byte, packetID uint64, timestamp time.Time, payload []byte) []byte {
	t.Helper()
	var serverSessionID [8]byte
	copy(serverSessionID[:], []byte("server01"))

	separateHeader := make([]byte, 16)
	copy(separateHeader, serverSessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)
	encryptedHeader := make([]byte, 16)
	block.Encrypt(encryptedHeader, separateHeader)

	message := buildUDPServerMessage(t, clientSessionID, timestamp, payload)
	aead, err := CreateCipher(uPSK, separateHeader[:8], conf)
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{}, encryptedHeader...)
	wire = append(wire, aead.Seal(nil, separateHeader[4:16], message, nil)...)
	return wire
}

func buildChachaUDPServerPacket(t *testing.T, aead cipherAEAD, conf *ciphers.CipherConf2022, clientSessionID [8]byte, packetID uint64, timestamp time.Time, payload []byte) []byte {
	t.Helper()
	var serverSessionID [8]byte
	copy(serverSessionID[:], []byte("server01"))

	message := bytes.NewBuffer(nil)
	message.Write(serverSessionID[:])
	if err := binary.Write(message, binary.BigEndian, packetID); err != nil {
		t.Fatal(err)
	}
	message.Write(buildUDPServerMessage(t, clientSessionID, timestamp, payload))

	nonce := bytes.Repeat([]byte{0x7}, conf.PacketNonceLen)
	wire := append([]byte{}, nonce...)
	wire = append(wire, aead.Seal(nil, nonce, message.Bytes(), nil)...)
	return wire
}

func buildUDPServerMessage(t *testing.T, clientSessionID [8]byte, timestamp time.Time, payload []byte) []byte {
	t.Helper()
	message := bytes.NewBuffer(nil)
	message.WriteByte(HeaderTypeServerPacket)
	if err := binary.Write(message, binary.BigEndian, uint64(timestamp.Unix())); err != nil {
		t.Fatal(err)
	}
	message.Write(clientSessionID[:])
	if err := binary.Write(message, binary.BigEndian, uint16(0)); err != nil {
		t.Fatal(err)
	}
	addrInfo, err := socks5.AddressFromString("8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	if err := socks5.WriteAddrInfo(addrInfo, message); err != nil {
		t.Fatal(err)
	}
	message.Write(payload)
	return message.Bytes()
}

type cipherBlock interface {
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
	BlockSize() int
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
