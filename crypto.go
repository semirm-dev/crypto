// Package crypto provides password hashing (Argon2id, scrypt, bcrypt) and
// authenticated encryption (AES-GCM) with safe defaults.
//
// Hashers validate every parameter before doing work, so hashes from untrusted
// sources cannot trigger panics or unbounded memory use. Ciphers are immutable
// after construction and safe for concurrent use.
package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	// ErrMismatch is returned by Validate when the password does not match.
	ErrMismatch = errors.New("crypto: password does not match hash")
	// ErrInvalidHash is returned when a hash is malformed or its parameters are out of bounds.
	ErrInvalidHash = errors.New("crypto: invalid hash")
	// ErrDecrypt is returned for any decryption failure, deliberately without detail.
	ErrDecrypt = errors.New("crypto: decryption failed")
)

// Hasher hashes and validates passwords.
type Hasher interface {
	// Hash returns a self-describing, salted hash of plain.
	Hash(plain string) (string, error)
	// Validate returns nil if plain matches hashed, ErrMismatch if not,
	// or an error wrapping ErrInvalidHash for unusable hashes.
	Validate(hashed, plain string) error
	// NeedsRehash reports whether hashed was not produced with the current parameters.
	NeedsRehash(hashed string) bool
}

// Cipher is an authenticated encryption scheme. aad is authenticated but not encrypted.
type Cipher interface {
	Encrypt(plaintext, aad []byte) ([]byte, error)
	Decrypt(ciphertext, aad []byte) ([]byte, error)
}

var (
	_ Hasher = (*Argon2)(nil)
	_ Hasher = (*SCrypt)(nil)
	_ Hasher = (*BCrypt)(nil)
	_ Cipher = (*GCM)(nil)
)

// EncryptString encrypts s with c and returns unpadded URL-safe base64.
func EncryptString(c Cipher, s string, aad []byte) (string, error) {
	out, err := c.Encrypt([]byte(s), aad)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// DecryptString is the inverse of EncryptString.
func DecryptString(c Cipher, s string, aad []byte) (string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return "", ErrDecrypt
	}

	out, err := c.Decrypt(raw, aad)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func invalidHash(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidHash, fmt.Sprintf(format, args...))
}
