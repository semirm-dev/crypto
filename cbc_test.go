package crypto_test

import (
	"testing"

	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
)

const cbcKey = "3t6w9z$C&F)J@NcR"

func TestCBC_RoundTrip(t *testing.T) {
	cbc := crypto.NewCBC(cbcKey)

	raw, hexed, err := cbc.Encrypt([]byte("test-123"))
	assert.NoError(t, err)

	decrypted, err := cbc.Decrypt(raw)
	assert.NoError(t, err)
	assert.Equal(t, "test-123", decrypted)

	decrypted, err = cbc.DecryptHex(hexed)
	assert.NoError(t, err)
	assert.Equal(t, "test-123", decrypted)
}

func TestCBC_RandomIV(t *testing.T) {
	cbc := crypto.NewCBC(cbcKey)

	a, _, _ := cbc.Encrypt([]byte("test-123"))
	b, _, _ := cbc.Encrypt([]byte("test-123"))
	assert.NotEqual(t, a, b)
}

func TestCBC_Tampered(t *testing.T) {
	cbc := crypto.NewCBC(cbcKey)

	raw, _, _ := cbc.Encrypt([]byte("test-123"))
	b := []byte(raw)
	b[20] ^= 1

	_, err := cbc.Decrypt(string(b))
	assert.EqualError(t, err, "authentication failed")
}

func TestCBC_WrongKey(t *testing.T) {
	raw, _, _ := crypto.NewCBC(cbcKey).Encrypt([]byte("test-123"))

	_, err := crypto.NewCBC("AAAAAAAAAAAAAAAA").Decrypt(raw)
	assert.EqualError(t, err, "authentication failed")
}

func TestCBC_InvalidInput(t *testing.T) {
	cbc := crypto.NewCBC(cbcKey)

	_, err := cbc.Decrypt("short")
	assert.Error(t, err)

	_, err = cbc.Decrypt(string(make([]byte, 81)))
	assert.Error(t, err)

	_, err = cbc.DecryptHex("zz")
	assert.Error(t, err)
}

func TestCBC_InvalidKey(t *testing.T) {
	_, _, err := crypto.NewCBC("short").Encrypt([]byte("a"))
	assert.Error(t, err)

	_, err = crypto.NewCBC("short").Decrypt("a")
	assert.Error(t, err)
}
