package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// GCM is AES-GCM authenticated encryption. Output is nonce || ciphertext || tag.
// Nonces are random 96 bit values: rotate the key before ~2^32 messages.
type GCM struct {
	aead cipher.AEAD
}

// NewGCM returns a GCM for a 16, 24 or 32 byte key (AES-128/192/256).
func NewGCM(key []byte) (*GCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &GCM{aead: aead}, nil
}

// Encrypt plaintext, binding it to aad.
func (g *GCM) Encrypt(plaintext, aad []byte) ([]byte, error) {
	ns := g.aead.NonceSize()
	out := make([]byte, ns, ns+len(plaintext)+g.aead.Overhead())

	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}

	return g.aead.Seal(out, out[:ns], plaintext, aad), nil
}

// Decrypt output of Encrypt. aad must match the value used for encryption.
func (g *GCM) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	ns := g.aead.NonceSize()
	if len(ciphertext) < ns+g.aead.Overhead() {
		return nil, ErrDecrypt
	}

	out, err := g.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}

	return out, nil
}
