package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherConf2022 struct {
	KeyLen          int
	SaltLen         int
	NonceLen        int
	TagLen          int
	NewCipher       func(key []byte) (cipher.AEAD, error)
	NewBlockCipher  func(key []byte) (cipher.Block, error)
	NewPacketCipher func(key []byte) (cipher.AEAD, error)
	PacketNonceLen  int
}

const (
	TimestampTolerance = 30 * time.Second
)

var (
	Aead2022CiphersConf = map[string]*CipherConf2022{
		"2022-blake3-aes-256-gcm": {
			KeyLen:         32,
			SaltLen:        32,
			NonceLen:       12,
			TagLen:         16,
			NewCipher:      NewGcm,
			NewBlockCipher: aes.NewCipher,
		},
		"2022-blake3-aes-128-gcm": {
			KeyLen:         16,
			SaltLen:        16,
			NonceLen:       12,
			TagLen:         16,
			NewCipher:      NewGcm,
			NewBlockCipher: aes.NewCipher,
		},
		"2022-blake3-chacha20-poly1305": {
			KeyLen:          chacha20poly1305.KeySize,
			SaltLen:         chacha20poly1305.KeySize,
			NonceLen:        chacha20poly1305.NonceSize,
			TagLen:          chacha20poly1305.Overhead,
			NewCipher:       chacha20poly1305.New,
			NewBlockCipher:  aes.NewCipher,
			NewPacketCipher: chacha20poly1305.NewX,
			PacketNonceLen:  chacha20poly1305.NonceSizeX,
		},
	}
)

func ValidateBase64PSK(pskBase64 string, expectedKeyLen int) ([]byte, error) {
	if pskBase64 == "" {
		return nil, fmt.Errorf("PSK cannot be empty for AEAD-2022 methods")
	}

	psk, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("PSK must be valid base64 for AEAD-2022 methods: %w", err)
	}
	if len(psk) != expectedKeyLen {
		return nil, fmt.Errorf("PSK length must be %d bytes for this method, got %d", expectedKeyLen, len(psk))
	}
	return psk, nil
}
