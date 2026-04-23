package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	parentDialer       netproxy.Dialer
	proxyAddress       string
	conf               *ciphers.CipherConf2022
	pskList            [][]byte
	uPSK               []byte
	sg                 shadowsocks.SaltGenerator
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks 2022 cipher: %v", header.Cipher)
	}

	keyStrList := strings.Split(header.Password, ":")
	pskList := make([][]byte, len(keyStrList))
	for i, keyStr := range keyStrList {
		key, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen)
		if err != nil {
			return nil, err
		}
		pskList[i] = key
	}
	uPSK := pskList[len(pskList)-1]

	blockCipherEncrypt, err := conf.NewBlockCipher(pskList[0])
	if err != nil {
		return nil, err
	}
	blockCipherDecrypt, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		return nil, err
	}
	sg, err := shadowsocks.NewRandomSaltGenerator(conf.SaltLen, true)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		parentDialer:       parentDialer,
		proxyAddress:       header.ProxyAddress,
		conf:               conf,
		pskList:            pskList,
		uPSK:               uPSK,
		sg:                 sg,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewTCPConn(conn, d.conf, d.pskList, d.uPSK, d.sg, addrInfo, nil), nil
	case "udp":
		conn, err := d.parentDialer.DialContext(ctx, magicNetwork.Encode(), d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return NewUdpConn(conn, addr, d.conf, d.blockCipherEncrypt, d.blockCipherDecrypt, d.pskList, d.uPSK, nil)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
