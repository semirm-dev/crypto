package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// generated with Python bcrypt
const bcryptRef = "$2b$10$cfbrCNkE/jOpUw8oDO6rWORakBkVoI1XW9TX1bQ2wbLmmeBmua03O"

func TestBCrypt(t *testing.T) {
	b := NewBCrypt()
	assert.Equal(t, 12, b.Cost)

	assert.NoError(t, b.Validate(bcryptRef, "test-123"))
	assert.ErrorIs(t, b.Validate(bcryptRef, "x"), ErrMismatch)
	assert.ErrorIs(t, b.Validate("garbage", "x"), ErrInvalidHash)
	assert.ErrorIs(t, b.Validate("", "x"), ErrInvalidHash)
}

func TestBCrypt_RoundTrip(t *testing.T) {
	b := &BCrypt{Cost: 4}

	hashed, err := b.Hash("x")
	assert.NoError(t, err)
	assert.NoError(t, b.Validate(hashed, "x"))
	assert.False(t, b.NeedsRehash(hashed))
	assert.True(t, NewBCrypt().NeedsRehash(hashed))
	assert.True(t, b.NeedsRehash("garbage"))
}

func TestBCrypt_Hash_Errors(t *testing.T) {
	_, err := (&BCrypt{Cost: 9999}).Hash("x")
	assert.Error(t, err)

	_, err = (&BCrypt{Cost: 4}).Hash(string(make([]byte, 73)))
	assert.Error(t, err)
}
