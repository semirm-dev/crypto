package crypto_test

import (
	"testing"

	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
)

func TestGCM_RoundTrip(t *testing.T) {
	gcm := crypto.NewGCM(cbcKey)

	raw, hexed, b64, err := gcm.Encrypt([]byte("test-123"))
	assert.NoError(t, err)

	for _, dec := range []func() (string, error){
		func() (string, error) { return gcm.Decrypt(raw) },
		func() (string, error) { return gcm.DecryptHex(hexed) },
		func() (string, error) { return gcm.DecryptBase64(b64) },
	} {
		decrypted, err := dec()
		assert.NoError(t, err)
		assert.Equal(t, "test-123", decrypted)
	}
}

func TestGCM_RandomNonce(t *testing.T) {
	gcm := crypto.NewGCM(cbcKey)

	a, _, _, _ := gcm.Encrypt([]byte("test-123"))
	b, _, _, _ := gcm.Encrypt([]byte("test-123"))
	assert.NotEqual(t, a, b)
}

func TestGCM_AAD(t *testing.T) {
	gcm := crypto.NewGCM(cbcKey)

	raw, _, _, err := gcm.EncryptAAD([]byte("test-123"), []byte("ctx"))
	assert.NoError(t, err)

	decrypted, err := gcm.DecryptAAD(raw, []byte("ctx"))
	assert.NoError(t, err)
	assert.Equal(t, "test-123", decrypted)

	_, err = gcm.DecryptAAD(raw, []byte("other"))
	assert.Error(t, err)

	_, err = gcm.Decrypt(raw)
	assert.Error(t, err)
}

func TestGCM_Tampered(t *testing.T) {
	gcm := crypto.NewGCM(cbcKey)

	raw, _, _, _ := gcm.Encrypt([]byte("test-123"))
	b := []byte(raw)
	b[len(b)-1] ^= 1

	_, err := gcm.Decrypt(string(b))
	assert.Error(t, err)
}

func TestGCM_InvalidInput(t *testing.T) {
	gcm := crypto.NewGCM(cbcKey)

	_, err := gcm.Decrypt("short")
	assert.EqualError(t, err, "encrypted text too short")

	_, err = gcm.DecryptHex("zz")
	assert.Error(t, err)

	_, err = gcm.DecryptBase64("!")
	assert.Error(t, err)

	_, _, _, err = crypto.NewGCM("short").Encrypt([]byte("a"))
	assert.Error(t, err)

	_, err = crypto.NewGCM("short").Decrypt("a")
	assert.Error(t, err)
}
