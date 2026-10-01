package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testKey = []byte("3t6w9z$C&F)J@NcR")

func newCiphers(t *testing.T, key []byte) map[string]Cipher {
	gcm, err := NewGCM(key)
	assert.NoError(t, err)
	cbc, err := NewCBC(key)
	assert.NoError(t, err)

	return map[string]Cipher{"gcm": gcm, "cbc": cbc}
}

func TestCiphers_RoundTrip(t *testing.T) {
	for name, c := range newCiphers(t, testKey) {
		for _, pt := range [][]byte{nil, []byte("a"), []byte("test-123"), make([]byte, 16), make([]byte, 1000)} {
			ct, err := c.Encrypt(pt, []byte("ctx"))
			assert.NoError(t, err, name)

			got, err := c.Decrypt(ct, []byte("ctx"))
			assert.NoError(t, err, name)
			assert.Equal(t, len(pt), len(got), name)
			assert.True(t, string(pt) == string(got), name)
		}
	}
}

func TestCiphers_Randomized(t *testing.T) {
	for name, c := range newCiphers(t, testKey) {
		a, _ := c.Encrypt([]byte("test-123"), nil)
		b, _ := c.Encrypt([]byte("test-123"), nil)
		assert.NotEqual(t, a, b, name)
	}
}

func TestCiphers_Rejects(t *testing.T) {
	other := newCiphers(t, []byte("AAAAAAAAAAAAAAAA"))

	for name, c := range newCiphers(t, testKey) {
		ct, _ := c.Encrypt([]byte("test-123"), []byte("ctx"))

		_, err := c.Decrypt(ct, []byte("other"))
		assert.ErrorIs(t, err, ErrDecrypt, name+" wrong aad")

		_, err = c.Decrypt(ct, nil)
		assert.ErrorIs(t, err, ErrDecrypt, name+" missing aad")

		_, err = other[name].Decrypt(ct, []byte("ctx"))
		assert.ErrorIs(t, err, ErrDecrypt, name+" wrong key")

		for i := range ct { // every single byte is authenticated
			tampered := append([]byte{}, ct...)
			tampered[i] ^= 1
			_, err = c.Decrypt(tampered, []byte("ctx"))
			assert.ErrorIs(t, err, ErrDecrypt, name)
		}

		for _, bad := range [][]byte{nil, {1}, ct[:len(ct)-1], ct[:16], append(append([]byte{}, ct...), 0)} {
			_, err = c.Decrypt(bad, []byte("ctx"))
			assert.ErrorIs(t, err, ErrDecrypt, name)
		}

		// Decrypt must not modify its input
		orig := append([]byte{}, ct...)
		c.Decrypt(ct, []byte("ctx"))
		assert.Equal(t, orig, ct, name)
	}
}

func TestCiphers_KeySizes(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		for _, c := range newCiphers(t, make([]byte, n)) {
			ct, _ := c.Encrypt([]byte("x"), nil)
			_, err := c.Decrypt(ct, nil)
			assert.NoError(t, err)
		}
	}

	for _, n := range []int{0, 15, 17, 33} {
		_, err := NewGCM(make([]byte, n))
		assert.Error(t, err)
		_, err = NewCBC(make([]byte, n))
		assert.Error(t, err)
	}
}

// reference value from Python cryptography AESGCM, nonce 00..0b, aad "ctx"
func TestGCM_ReferenceVector(t *testing.T) {
	gcm, _ := NewGCM(testKey)
	ct, _ := hex.DecodeString("000102030405060708090a0be18ba3bf8aeba0305005b0b7e5375acee682d8e7edf2ce64")

	pt, err := gcm.Decrypt(ct, []byte("ctx"))
	assert.NoError(t, err)
	assert.Equal(t, "test-123", string(pt))
}

// reference value built with Python cryptography: AES-CBC PKCS7 + HMAC-SHA256, iv 00..0f, aad "ctx",
// keys derived as HMAC-SHA256(key, "cbc-enc"/"cbc-mac")
func TestCBC_ReferenceVector(t *testing.T) {
	cbc, _ := NewCBC(testKey)
	ct, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0fa39f5d0766753067896b3b2ff5005dbcc121766b962be8f7402c0f45ebaafe1f1b585b701570c148d1fdd6e4c4370ffe")

	pt, err := cbc.Decrypt(ct, []byte("ctx"))
	assert.NoError(t, err)
	assert.Equal(t, "test-123", string(pt))
}

func TestStringHelpers(t *testing.T) {
	for name, c := range newCiphers(t, testKey) {
		s, err := EncryptString(c, "héllo", []byte("ctx"))
		assert.NoError(t, err, name)
		assert.NotContains(t, s, "=")

		got, err := DecryptString(c, s, []byte("ctx"))
		assert.NoError(t, err, name)
		assert.Equal(t, "héllo", got)

		_, err = DecryptString(c, "!!", nil)
		assert.ErrorIs(t, err, ErrDecrypt)
		_, err = DecryptString(c, s, nil)
		assert.ErrorIs(t, err, ErrDecrypt)
	}
}

func FuzzCiphersDecrypt(f *testing.F) {
	gcm, _ := NewGCM(testKey)
	cbc, _ := NewCBC(testKey)
	for _, c := range []Cipher{gcm, cbc} {
		ct, _ := c.Encrypt([]byte("test-123"), nil)
		f.Add(ct)
	}
	f.Fuzz(func(t *testing.T, ct []byte) {
		for _, c := range []Cipher{gcm, cbc} {
			if _, err := c.Decrypt(ct, nil); err != nil {
				assert.ErrorIs(t, err, ErrDecrypt)
			}
		}
	})
}
