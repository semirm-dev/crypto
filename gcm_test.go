package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testKey = []byte("3t6w9z$C&F)J@NcR")

func newTestGCM(t *testing.T, key []byte) *GCM {
	g, err := NewGCM(key)
	assert.NoError(t, err)

	return g
}

func TestGCM_RoundTrip(t *testing.T) {
	g := newTestGCM(t, testKey)

	for _, pt := range [][]byte{nil, []byte("a"), []byte("test-123"), make([]byte, 16), make([]byte, 1000)} {
		ct, err := g.Encrypt(pt, []byte("ctx"))
		assert.NoError(t, err)

		got, err := g.Decrypt(ct, []byte("ctx"))
		assert.NoError(t, err)
		assert.Equal(t, string(pt), string(got))
	}
}

func TestGCM_Randomized(t *testing.T) {
	g := newTestGCM(t, testKey)

	a, _ := g.Encrypt([]byte("test-123"), nil)
	b, _ := g.Encrypt([]byte("test-123"), nil)
	assert.NotEqual(t, a, b)
}

func TestGCM_Rejects(t *testing.T) {
	g := newTestGCM(t, testKey)
	ct, _ := g.Encrypt([]byte("test-123"), []byte("ctx"))

	_, err := g.Decrypt(ct, []byte("other"))
	assert.ErrorIs(t, err, ErrDecrypt, "wrong aad")

	_, err = g.Decrypt(ct, nil)
	assert.ErrorIs(t, err, ErrDecrypt, "missing aad")

	_, err = newTestGCM(t, []byte("AAAAAAAAAAAAAAAA")).Decrypt(ct, []byte("ctx"))
	assert.ErrorIs(t, err, ErrDecrypt, "wrong key")

	for i := range ct { // every single byte is authenticated
		tampered := append([]byte{}, ct...)
		tampered[i] ^= 1
		_, err = g.Decrypt(tampered, []byte("ctx"))
		assert.ErrorIs(t, err, ErrDecrypt)
	}

	for _, bad := range [][]byte{nil, {1}, ct[:len(ct)-1], ct[:16], append(append([]byte{}, ct...), 0)} {
		_, err = g.Decrypt(bad, []byte("ctx"))
		assert.ErrorIs(t, err, ErrDecrypt)
	}

	// Decrypt must not modify its input
	orig := append([]byte{}, ct...)
	g.Decrypt(ct, []byte("ctx"))
	assert.Equal(t, orig, ct)
}

func TestGCM_KeySizes(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		g := newTestGCM(t, make([]byte, n))

		ct, _ := g.Encrypt([]byte("x"), nil)
		_, err := g.Decrypt(ct, nil)
		assert.NoError(t, err)
	}

	for _, n := range []int{0, 15, 17, 33} {
		_, err := NewGCM(make([]byte, n))
		assert.Error(t, err)
	}
}

// reference value from Python cryptography AESGCM, nonce 00..0b, aad "ctx"
func TestGCM_ReferenceVector(t *testing.T) {
	g := newTestGCM(t, testKey)
	ct, _ := hex.DecodeString("000102030405060708090a0be18ba3bf8aeba0305005b0b7e5375acee682d8e7edf2ce64")

	pt, err := g.Decrypt(ct, []byte("ctx"))
	assert.NoError(t, err)
	assert.Equal(t, "test-123", string(pt))
}

func TestGCM_Strings(t *testing.T) {
	g := newTestGCM(t, testKey)

	s, err := g.EncryptString("héllo", []byte("ctx"))
	assert.NoError(t, err)
	assert.NotContains(t, s, "=")

	got, err := g.DecryptString(s, []byte("ctx"))
	assert.NoError(t, err)
	assert.Equal(t, "héllo", got)

	_, err = g.DecryptString("!!", nil)
	assert.ErrorIs(t, err, ErrDecrypt)
	_, err = g.DecryptString(s, nil)
	assert.ErrorIs(t, err, ErrDecrypt)
}

func FuzzGCMDecrypt(f *testing.F) {
	g, _ := NewGCM(testKey)
	ct, _ := g.Encrypt([]byte("test-123"), nil)
	f.Add(ct)
	f.Fuzz(func(t *testing.T, ct []byte) {
		if _, err := g.Decrypt(ct, nil); err != nil {
			assert.ErrorIs(t, err, ErrDecrypt)
		}
	})
}
