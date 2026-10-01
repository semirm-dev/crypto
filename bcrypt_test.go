package crypto_test

import (
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewBCrypt(t *testing.T) {
	bcrypt := crypto.NewBCrypt()
	assert.Equal(t, 10, bcrypt.Cost)
}

func TestBCrypt_Hash(t *testing.T) {
	bcrypt := crypto.NewBCrypt()

	hashed, err := bcrypt.Hash("test-123")
	assert.NoError(t, err)
	assert.NotEmpty(t, hashed)
}

func TestBCrypt_Hash_InvalidCost(t *testing.T) {
	bcrypt := crypto.NewBCrypt()
	bcrypt.Cost = 9999

	hashed, err := bcrypt.Hash("test-123")
	assert.Equal(t, "crypto/bcrypt: cost 9999 is outside allowed inclusive range 4..31", err.Error())
	assert.Empty(t, hashed)
}

func TestBCrypt_Validate(t *testing.T) {
	bcrypt := crypto.NewBCrypt()

	hashed := "$2a$10$ey6hBBzIt1r1HQy6.hUihOCJ/6Ee9kLpFBD3P9of8is0RUwEL4uk6"
	err := bcrypt.Validate(hashed, "test-123")
	assert.NoError(t, err)
}

func TestBCrypt_Validate_Failed(t *testing.T) {
	bcrypt := crypto.NewBCrypt()

	hashed := "$2a$10$ey6hBBzIt1r1HQy6.hUihOCJ/6Ee9kLpFBD3P9of8is0RUwEL4uk6"
	err := bcrypt.Validate(hashed, "different")
	assert.Equal(t, "crypto/bcrypt: hashedPassword is not the hash of the given password", err.Error())
}

// reference hash generated with Python bcrypt
func TestBCrypt_ReferenceVector(t *testing.T) {
	bcrypt := crypto.NewBCrypt()

	assert.NoError(t, bcrypt.Validate("$2b$10$cfbrCNkE/jOpUw8oDO6rWORakBkVoI1XW9TX1bQ2wbLmmeBmua03O", "test-123"))
}

func TestBCrypt_RoundTrip(t *testing.T) {
	bcrypt := crypto.NewBCrypt()

	hashed, err := bcrypt.Hash("x")
	assert.NoError(t, err)
	assert.NoError(t, bcrypt.Validate(hashed, "x"))
}

func TestBCrypt_Hash_TooLong(t *testing.T) {
	_, err := crypto.NewBCrypt().Hash(string(make([]byte, 73)))
	assert.Error(t, err)
}
