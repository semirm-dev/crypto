package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSalt(t *testing.T) {
	a, err := GenerateSalt(16)
	assert.NoError(t, err)
	assert.Len(t, a, 16)

	b, _ := GenerateSalt(16)
	assert.NotEqual(t, a, b)

	_, err = GenerateSalt(-1)
	assert.Error(t, err)
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef")

	k1, err := DeriveKey("pass", salt)
	assert.NoError(t, err)
	assert.Len(t, k1, 32)

	k2, _ := DeriveKey("pass", salt)
	assert.Equal(t, k1, k2)

	k3, _ := DeriveKey("other", salt)
	assert.NotEqual(t, k1, k3)

	_, err = DeriveKey("pass", []byte("short"))
	assert.Error(t, err)

	_, err = NewGCM(k1)
	assert.NoError(t, err)
}
