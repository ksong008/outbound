package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	poolBytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"lukechampine.com/blake3"
)

type UdpConn struct {
	netproxy.Conn

	tgtAddr   string
	sessionID [8]byte
	packetID  uint64

	cipherConf         *ciphers.CipherConf2022
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	pskList [][]byte
	uPSK    []byte
	bloom   *disk_bloom.FilterGroup

	sessionMu      sync.Mutex
	serverSessions map[[8]byte]*serverSessionState
}

type serverSessionState struct {
	window   *SlidingWindowFilter
	lastSeen time.Time
}

const (
	HeaderTypeClientPacket   = 0
	HeaderTypeServerPacket   = 1
	UDPReplayWindowSize      = 4096
	ServerSessionRetention   = 60 * time.Second
)

func NewUdpConn(
	conn netproxy.Conn,
	tgtAddr string,
	conf *ciphers.CipherConf2022,
	blockCipherEncrypt cipher.Block,
	blockCipherDecrypt cipher.Block,
	pskList [][]byte,
	uPSK []byte,
	bloom *disk_bloom.FilterGroup,
) (*UdpConn, error) {
	u := &UdpConn{
		Conn:               conn,
		tgtAddr:            tgtAddr,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		uPSK:               uPSK,
		bloom:              bloom,
		serverSessions:     make(map[[8]byte]*serverSessionState),
	}
	fastrand.Read(u.sessionID[:])
	return u, nil
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgtAddr)
}

func (c *UdpConn) writeIdentityHeader(buf *poolBytes.Buffer, separateHeader []byte) error {
	identityHeader := pool.Get(aes.BlockSize)
	defer pool.Put(identityHeader)

	for i := 0; i < len(c.pskList)-1; i++ {
		hash := blake3.Sum512(c.pskList[i+1])
		subtle.XORBytes(identityHeader, hash[:aes.BlockSize], separateHeader)
		block, err := c.cipherConf.NewBlockCipher(c.pskList[i])
		if err != nil {
			return err
		}
		block.Encrypt(identityHeader, identityHeader)
		buf.Write(identityHeader)
	}
	return nil
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	separateHeader := pool.GetBuffer()
	defer pool.PutBuffer(separateHeader)

	c.packetID++
	separateHeader.Write(c.sessionID[:])
	if err := binary.Write(separateHeader, binary.BigEndian, c.packetID); err != nil {
		return 0, err
	}

	separateHeaderEncrypted := pool.Get(aes.BlockSize)
	defer pool.Put(separateHeaderEncrypted)
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted, separateHeader.Bytes())
	buf.Write(separateHeaderEncrypted)

	if err := c.writeIdentityHeader(buf, separateHeader.Bytes()); err != nil {
		return 0, fmt.Errorf("fail to write identity header: %w", err)
	}

	message, err := EncodeMessage(HeaderTypeClientPacket, uint64(time.Now().Unix()), addr, b)
	if err != nil {
		return 0, fmt.Errorf("fail to encode message: %w", err)
	}
	defer pool.PutBuffer(message)

	aead, err := CreateCipher(c.uPSK, separateHeader.Bytes()[:8], c.cipherConf)
	if err != nil {
		return 0, err
	}
	sealed := aead.Seal(nil, separateHeader.Bytes()[4:16], message.Bytes(), nil)
	buf.Write(sealed)

	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func EncodeMessage(typ uint8, timestamp uint64, address string, b []byte) (*poolBytes.Buffer, error) {
	message := pool.GetBuffer()
	message.WriteByte(typ)
	if err := binary.Write(message, binary.BigEndian, timestamp); err != nil {
		pool.PutBuffer(message)
		return nil, err
	}
	if err := binary.Write(message, binary.BigEndian, uint16(0)); err != nil {
		pool.PutBuffer(message)
		return nil, err
	}
	addrInfo, err := socks5.AddressFromString(address)
	if err != nil {
		pool.PutBuffer(message)
		return nil, err
	}
	if err := socks5.WriteAddrInfo(addrInfo, message); err != nil {
		pool.PutBuffer(message)
		return nil, err
	}
	message.Write(b)
	return message, nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(len(b) + aes.BlockSize + c.cipherConf.TagLen + 64)
	defer pool.Put(buf)

	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < aes.BlockSize {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	c.blockCipherDecrypt.Decrypt(buf[:aes.BlockSize], buf[:aes.BlockSize])
	var serverSessionID [8]byte
	copy(serverSessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])
	payload := buf[aes.BlockSize:n]

	aead, err := CreateCipher(c.uPSK, buf[:8], c.cipherConf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, err = aead.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	reader := bytes.NewReader(payload)

	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}
	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)
	if typ != HeaderTypeServerPacket {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}
	if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	var clientSessionID [8]byte
	if _, err := io.ReadFull(reader, clientSessionID[:]); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read client session ID: %w", err)
	}
	if clientSessionID != c.sessionID {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}

	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}
	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	udpAddr, ok := netAddr.(*net.UDPAddr)
	if !ok {
		return 0, netip.AddrPort{}, fmt.Errorf("unexpected address type: %T", netAddr)
	}
	ipAddr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid UDP address")
	}
	addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))

	now := time.Now()
	c.sessionMu.Lock()
	c.cleanupExpiredServerSessionsLocked(now)
	state, ok := c.serverSessions[serverSessionID]
	if !ok {
		state = &serverSessionState{
			window:   NewSlidingWindowFilter(UDPReplayWindowSize),
			lastSeen: now,
		}
		c.serverSessions[serverSessionID] = state
	}
	if !state.window.CheckAndUpdate(packetID) {
		c.sessionMu.Unlock()
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}
	state.lastSeen = now
	c.sessionMu.Unlock()

	n, err = reader.Read(b)
	return n, addr, err
}

func (c *UdpConn) cleanupExpiredServerSessionsLocked(now time.Time) {
	for sessionID, state := range c.serverSessions {
		if now.Sub(state.lastSeen) > ServerSessionRetention {
			delete(c.serverSessions, sessionID)
		}
	}
}
