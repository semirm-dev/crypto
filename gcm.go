package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// GCM encryption
type GCM struct {
	Secret string
}

func NewGCM(secret string) *GCM {
	return &GCM{
		Secret: secret,
	}
}

// Encrypt payload using AES GCM encryption mode, returns raw, hex and base64 encoded output
func (gcmEnc *GCM) Encrypt(payload []byte) (string, string, string, error) {
	return gcmEnc.EncryptAAD(payload, nil)
}

// EncryptAAD is Encrypt with additional authenticated data, which must be passed to DecryptAAD
func (gcmEnc *GCM) EncryptAAD(payload, aad []byte) (string, string, string, error) {
	key := []byte(gcmEnc.Secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}

	encrypted := gcm.Seal(nonce, nonce, payload, aad)

	return string(encrypted), hex.EncodeToString(encrypted), base64.URLEncoding.EncodeToString(encrypted), nil
}

// Decrypt raw output of Encrypt
func (gcmEnc *GCM) Decrypt(payload string) (string, error) {
	return gcmEnc.DecryptAAD(payload, nil)
}

// DecryptHex decrypts hex encoded output of Encrypt
func (gcmEnc *GCM) DecryptHex(payload string) (string, error) {
	raw, err := hex.DecodeString(payload)
	if err != nil {
		return "", err
	}

	return gcmEnc.Decrypt(string(raw))
}

// DecryptBase64 decrypts base64 (URL encoding) output of Encrypt
func (gcmEnc *GCM) DecryptBase64(payload string) (string, error) {
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}

	return gcmEnc.Decrypt(string(raw))
}

// DecryptAAD is Decrypt with additional authenticated data
func (gcmEnc *GCM) DecryptAAD(payload string, aad []byte) (string, error) {
	key := []byte(gcmEnc.Secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	byteIn := []byte(payload)
	nonceSize := gcm.NonceSize()

	if len(byteIn) < nonceSize {
		return "", errors.New("encrypted text too short")
	}

	nonce, encrypted := byteIn[:nonceSize], byteIn[nonceSize:]

	decrypted, err := gcm.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
