package shadowsocks_2022

import (
	"crypto/cipher"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"lukechampine.com/blake3"
)

const (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

func GenerateSubKey(psk []byte, salt []byte, context string) []byte {
	subKey := pool.Get(len(psk))
	keyMaterial := pool.GetBuffer()
	defer pool.PutBuffer(keyMaterial)
	keyMaterial.Write(psk)
	keyMaterial.Write(salt)
	blake3.DeriveKey(subKey, context, keyMaterial.Bytes())
	return subKey
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher.AEAD, error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	defer pool.Put(subKey)
	return cipherConf.NewCipher(subKey)
}

func timestampOutOfTolerance(timestamp time.Time, now time.Time) bool {
	return timestamp.Before(now.Add(-ciphers.TimestampTolerance)) || timestamp.After(now.Add(ciphers.TimestampTolerance))
}
