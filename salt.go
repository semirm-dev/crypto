package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const minSaltLen = 8

// GenerateSalt returns length cryptographically secure random bytes, 16 to 64 in most cases.
// It can also be used to generate encryption keys (16, 24 or 32 bytes).
func GenerateSalt(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("crypto: length must not be negative")
	}

	salt := make([]byte, length)

	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// DeriveKey derives a 32 byte AES-256 key from a passphrase using Argon2id (RFC 9106 recommended
// parameters). Store the salt next to the ciphertext; it is not secret.
func DeriveKey(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) < minSaltLen {
		return nil, errors.New("crypto: salt must be at least 8 bytes")
	}

	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32), nil
}

// newSalt generates salt with gen (GenerateSalt if nil), enforcing minimum length.
func newSalt(length int, gen func(int) ([]byte, error)) ([]byte, error) {
	if length < minSaltLen {
		return nil, errors.New("crypto: salt length must be at least 8")
	}
	if gen == nil {
		gen = GenerateSalt
	}

	return gen(length)
}
