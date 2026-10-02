// Package crypto provides password hashing (Argon2id, scrypt) and
// authenticated encryption (AES-GCM) with safe defaults.
//
// Hashers validate every parameter before doing work, so hashes from untrusted
// sources cannot trigger panics or unbounded memory use. GCM is immutable
// after construction and safe for concurrent use.
package crypto

import (
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

func invalidHash(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidHash, fmt.Sprintf(format, args...))
}
