package crypto

import (
	"crypto/rand"
	"errors"
	"io"
)

const minSaltLen = 8

// ErrMismatch is returned by Validate when plain does not match hashed
var ErrMismatch = errors.New("invalid hash")

// GenerateSalt with given length, 32 or 64 in most cases
func GenerateSalt(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("salt length must not be negative")
	}

	salt := make([]byte, length)

	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// newSalt generates salt with gen (GenerateSalt if nil), enforcing minimum length
func newSalt(length int, gen func(int) ([]byte, error)) ([]byte, error) {
	if length < minSaltLen {
		return nil, errors.New("salt length must be at least 8")
	}
	if gen == nil {
		gen = GenerateSalt
	}

	return gen(length)
}
