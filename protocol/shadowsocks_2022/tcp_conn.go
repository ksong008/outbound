package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	poolBytes "github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"lukechampine.com/blake3"
)

const (
	TCPChunkMaxLen        = (1 << 16) - 1
	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	MaxPaddingLength      = 900
)

type TCPConn struct {
	netproxy.Conn

	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf2022
	pskList    [][]byte
	uPSK       []byte
	sg         shadowsocks.SaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex   sync.Mutex
	writeMutex  sync.Mutex
	leftToRead  pool.PB
	indexToRead int

	requestSalt []byte
	bloom *disk_bloom.FilterGroup
}

func NewTCPConn(
	conn netproxy.Conn,
	conf *ciphers.CipherConf2022,
	pskList [][]byte,
	uPSK []byte,
	sg shadowsocks.SaltGenerator,
	addr *socks5.AddressInfo,
	bloom *disk_bloom.FilterGroup,
	) netproxy.Conn {
	return &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		pskList:    pskList,
		uPSK:       uPSK,
		sg:         sg,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
		bloom:      bloom,
	}
}

func (c *TCPConn) Close() error {
	if c.leftToRead != nil {
		pool.Put(c.leftToRead)
		c.leftToRead = nil
	}
	return c.Conn.Close()
}

func (c *TCPConn) Read(b []byte) (int, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if !c.onceWrite {
		if _, err := c.Write(nil); err != nil {
			return 0, err
		}
	}

	if c.indexToRead < len(c.leftToRead) {
		n := copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			pool.Put(c.leftToRead)
			c.leftToRead = nil
			c.indexToRead = 0
		}
		return n, nil
	}

	payloadLength := 0
	if !c.onceRead {
		firstRead := pool.Get(c.cipherConf.SaltLen + 11 + c.cipherConf.SaltLen + c.cipherConf.TagLen)
		defer pool.Put(firstRead)
		n, err := c.Conn.Read(firstRead)
		if err != nil {
			return 0, err
		}
		if n < len(firstRead) {
			return 0, io.ErrUnexpectedEOF
		}
		salt := firstRead[:c.cipherConf.SaltLen]

		cipherRead, err := CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, fmt.Errorf("fail to initiate cipher: %w", err)
		}
		c.cipherRead = cipherRead

		header := firstRead[c.cipherConf.SaltLen:]
		header, err = c.cipherRead.Open(header[:0], c.nonceRead, header, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)

		offset := 0
		typ := uint8(header[offset])
		offset++
		timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[offset:offset+8])), 0)
		offset += 8
		if typ != HeaderTypeServerStream {
			return 0, fmt.Errorf("received unexpected header type: %d", typ)
		}
		if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
			return 0, protocol.ErrReplayAttack
		}
		requestSalt := header[offset : offset+c.cipherConf.SaltLen]
		offset += c.cipherConf.SaltLen
		if len(c.requestSalt) != c.cipherConf.SaltLen || !equalBytes(requestSalt, c.requestSalt) {
			return 0, protocol.ErrFailAuth
		}
		payloadLength = int(binary.BigEndian.Uint16(header[offset : offset+2]))
		if payloadLength == 0 {
			return 0, protocol.ErrFailAuth
		}
		c.onceRead = true
	} else {
		lengthBuf := pool.Get(2 + c.cipherConf.TagLen)
		defer pool.Put(lengthBuf)
		if _, err := io.ReadFull(c.Conn, lengthBuf); err != nil {
			return 0, err
		}
		lengthBuf, err := c.cipherRead.Open(lengthBuf[:0], c.nonceRead, lengthBuf, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)
		payloadLength = int(binary.BigEndian.Uint16(lengthBuf))
	}

	payload := pool.Get(payloadLength + c.cipherConf.TagLen)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		pool.Put(payload)
		return 0, err
	}
	payload, err := c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		pool.Put(payload)
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)

	n := copy(b, payload)
	if n < len(payload) {
		c.leftToRead = payload
		c.indexToRead = n
	} else {
		pool.Put(payload)
	}
	return n, nil
}

func EncodeRequestHeader(typ uint8, timestamp uint64, addressInfo *socks5.AddressInfo, b *[]byte) (*poolBytes.Buffer, *poolBytes.Buffer, error) {
	fixedHeader := pool.GetBuffer()
	varHeader := pool.GetBuffer()

	if err := socks5.WriteAddrInfo(addressInfo, varHeader); err != nil {
		pool.PutBuffer(fixedHeader)
		pool.PutBuffer(varHeader)
		return nil, nil, err
	}
	paddingLen := uint16(0)
	if len(*b) == 0 {
		paddingLen = uint16(1 + fastrand.Intn(MaxPaddingLength))
	}
	if err := binary.Write(varHeader, binary.BigEndian, paddingLen); err != nil {
		pool.PutBuffer(fixedHeader)
		pool.PutBuffer(varHeader)
		return nil, nil, err
	}
	if paddingLen > 0 {
		padding := pool.Get(int(paddingLen))
		defer pool.Put(padding)
		fastrand.Read(padding)
		varHeader.Write(padding)
	}

	initialPayloadMaxLength := TCPChunkMaxLen - varHeader.Len()
	var n int
	if len(*b) > initialPayloadMaxLength {
		varHeader.Write((*b)[:initialPayloadMaxLength])
		n = initialPayloadMaxLength
	} else {
		varHeader.Write(*b)
		n = len(*b)
	}
	*b = (*b)[n:]

	fixedHeader.WriteByte(typ)
	if err := binary.Write(fixedHeader, binary.BigEndian, timestamp); err != nil {
		pool.PutBuffer(fixedHeader)
		pool.PutBuffer(varHeader)
		return nil, nil, err
	}
	if err := binary.Write(fixedHeader, binary.BigEndian, uint16(varHeader.Len())); err != nil {
		pool.PutBuffer(fixedHeader)
		pool.PutBuffer(varHeader)
		return nil, nil, err
	}

	return fixedHeader, varHeader, nil
}

func (c *TCPConn) writeIdentityHeader(buf *poolBytes.Buffer, salt []byte) error {
	identityHeader := pool.Get(aes.BlockSize)
	defer pool.Put(identityHeader)

	for i := 0; i < len(c.pskList)-1; i++ {
		identitySubKey := GenerateSubKey(c.pskList[i], salt, Shadowsocks2022IdentityHeaderInfo)
		defer pool.Put(identitySubKey)

		plaintext := blake3.Sum512(c.pskList[i+1])
		block, err := c.cipherConf.NewBlockCipher(identitySubKey)
		if err != nil {
			return err
		}
		block.Encrypt(identityHeader, plaintext[:aes.BlockSize])
		buf.Write(identityHeader)
	}
	return nil
}

func (c *TCPConn) Write(b []byte) (int, error) {
	n := len(b)

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	if !c.onceWrite {
		salt := c.sg.Get()
		defer pool.Put(salt)
		buf.Write(salt)
		c.requestSalt = make([]byte, len(salt))
		copy(c.requestSalt, salt)

		if err := c.writeIdentityHeader(buf, salt); err != nil {
			return 0, fmt.Errorf("fail to write identity header: %w", err)
		}

		cipherWrite, err := CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, fmt.Errorf("fail to initiate cipher: %w", err)
		}
		c.cipherWrite = cipherWrite

		fixedHeader, varHeader, err := EncodeRequestHeader(HeaderTypeClientStream, uint64(time.Now().Unix()), c.addr, &b)
		if err != nil {
			return 0, fmt.Errorf("fail to encode request header: %w", err)
		}
		defer pool.PutBuffer(fixedHeader)
		defer pool.PutBuffer(varHeader)

		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, fixedHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, varHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)

		c.onceWrite = true
	}
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("cipher is not initialized")
	}

	c.seal(buf, b)
	_, err := c.Conn.Write(buf.Bytes())
	return n, err
}

func (c *TCPConn) seal(buf *poolBytes.Buffer, payload []byte) {
	chunkLengthBuf := pool.Get(2)
	defer pool.Put(chunkLengthBuf)

	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		chunkLength := common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf, uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, chunkLengthBuf, nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, payload[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
