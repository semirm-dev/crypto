package crypto

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// BCrypt hashes passwords with bcrypt. Passwords longer than 72 bytes are rejected, not truncated.
type BCrypt struct {
	Cost int // 4-31
}

// NewBCrypt returns a BCrypt with cost 12.
func NewBCrypt() *BCrypt {
	return &BCrypt{Cost: 12}
}

// Hash returns the bcrypt hash of value.
func (b *BCrypt) Hash(value string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(value), b.Cost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

// Validate plain against hashed.
func (b *BCrypt) Validate(hashed, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return ErrMismatch
	default:
		return invalidHash("%v", err)
	}
}

// NeedsRehash reports whether hashed is unparsable or uses another cost than b.
func (b *BCrypt) NeedsRehash(hashed string) bool {
	cost, err := bcrypt.Cost([]byte(hashed))

	return err != nil || cost != b.Cost
}
