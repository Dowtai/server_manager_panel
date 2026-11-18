package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type Vault struct{ aead cipher.AEAD }

func New(key string) (*Vault, error) {
	b, e := base64.StdEncoding.DecodeString(key)
	if e != nil || len(b) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be base64 of 32 random bytes")
	}
	c, e := aes.NewCipher(b)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(c)
	return &Vault{a}, e
}
func (v *Vault) Seal(value, context string) string {
	n := make([]byte, v.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(n, n, []byte(value), []byte(context)))
}
func (v *Vault) Open(value, context string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(b) < v.aead.NonceSize() {
		return "", errors.New("invalid encrypted secret")
	}
	p, e := v.aead.Open(nil, b[:v.aead.NonceSize()], b[v.aead.NonceSize():], []byte(context))
	return string(p), e
}
