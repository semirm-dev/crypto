package crypto_test

import (
	"errors"
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func mockedSaltGen(len int) ([]byte, error) {
	return []byte("salt"), nil
}

func mockedSaltGenErr(len int) ([]byte, error) {
	return nil, errors.New("salt gen failed")
}

func TestGenerateSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt(10)

	assert.NoError(t, err)
	assert.NotEmpty(t, salt)
	assert.Len(t, salt, 10)
}

func TestGenerateSalt_Negative(t *testing.T) {
	_, err := crypto.GenerateSalt(-1)
	assert.Error(t, err)
}
