package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// CBC is AES-CBC with PKCS#7 padding and HMAC-SHA256 (encrypt-then-MAC).
// Output is iv || ciphertext || tag; the tag covers len(aad) || aad || iv || ciphertext.
// Separate encryption and MAC keys are derived from the key.
//
// Deprecated: use GCM unless CBC is required for compatibility.
type CBC struct {
	block  cipher.Block
	macKey []byte
}

// NewCBC returns a CBC for a 16, 24 or 32 byte key.
func NewCBC(key []byte) (*CBC, error) {
	if n := len(key); n != 16 && n != 24 && n != 32 {
		return nil, aes.KeySizeError(n)
	}

	block, err := aes.NewCipher(derive(key, "cbc-enc")[:len(key)])
	if err != nil {
		return nil, err
	}

	return &CBC{block: block, macKey: derive(key, "cbc-mac")}, nil
}

// Encrypt plaintext with a random IV, binding it to aad.
func (c *CBC) Encrypt(plaintext, aad []byte) ([]byte, error) {
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	out := make([]byte, aes.BlockSize+len(plaintext)+padLen, aes.BlockSize+len(plaintext)+padLen+sha256.Size)

	iv, body := out[:aes.BlockSize], out[aes.BlockSize:]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	copy(body, plaintext)
	copy(body[len(plaintext):], bytes.Repeat([]byte{byte(padLen)}, padLen))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(body, body)

	return c.mac(out, aad), nil
}

// Decrypt output of Encrypt. aad must match the value used for encryption.
func (c *CBC) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	n := len(ciphertext)
	if n < 2*aes.BlockSize+sha256.Size || (n-sha256.Size)%aes.BlockSize != 0 {
		return nil, ErrDecrypt
	}

	// full slice expression keeps mac from appending over the caller's tag
	signed, tag := ciphertext[:n-sha256.Size:n-sha256.Size], ciphertext[n-sha256.Size:]
	if !hmac.Equal(c.mac(signed, aad)[len(signed):], tag) {
		return nil, ErrDecrypt
	}

	iv, body := signed[:aes.BlockSize], signed[aes.BlockSize:]
	out := make([]byte, len(body))
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(out, body)

	out, err := pkcsUnpad(out)
	if err != nil {
		return nil, ErrDecrypt
	}

	return out, nil
}

// mac returns signed with its HMAC tag appended.
func (c *CBC) mac(signed, aad []byte) []byte {
	h := hmac.New(sha256.New, c.macKey)
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(aad))))
	h.Write(aad)
	h.Write(signed)

	return h.Sum(signed)
}

func pkcsUnpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty")
	}

	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) || !bytes.Equal(b[len(b)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("invalid padding")
	}

	return b[:len(b)-pad], nil
}

// derive returns HMAC-SHA256(key, label), used for key separation.
func derive(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))

	return h.Sum(nil)
}
