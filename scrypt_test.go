package crypto_test

import (
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewSCrypt(t *testing.T) {
	scrypt := crypto.NewSCrypt()

	assert.Equal(t, 32768, scrypt.N)
	assert.Equal(t, 8, scrypt.R)
	assert.Equal(t, 1, scrypt.P)
	assert.Equal(t, 32, scrypt.SaltLen)
	assert.Equal(t, 32, scrypt.KeyLen)
}

func TestSCrypt_Hash(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed, err := scrypt.Hash("test-123")
	assert.NoError(t, err)

	expected := "32768$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	assert.Equal(t, expected, hashed)
}

func TestSCrypt_Hash_SaltGenFail(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGenErr

	_, err := scrypt.Hash("test-123")
	assert.Equal(t, "salt gen failed", err.Error())
}

func TestSCrypt_Hash_KeyGenerateFail(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen
	scrypt.N = 0

	_, err := scrypt.Hash("test-123")
	assert.Equal(t, "scrypt: N must be a power of 2 greater than 1", err.Error())
}

func TestSCrypt_Validate(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.NoError(t, err)
}

func TestSCrypt_Validate_InvalidHash(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "different")
	assert.Equal(t, "invalid hash", err.Error())
}

func TestSCrypt_Validate_KeyGenerateFail(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "0$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "scrypt: N must be a power of 2 greater than 1", err.Error())
}

func TestSCrypt_Validate_InvalidHashLength(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$d5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "invalid hash length", err.Error())
}

func TestSCrypt_Validate_InvalidN(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "_$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.Atoi: parsing \"_\": invalid syntax", err.Error())
}

func TestSCrypt_Validate_InvalidR(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$_$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.Atoi: parsing \"_\": invalid syntax", err.Error())
}

func TestSCrypt_Validate_InvalidP(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$8$_$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.Atoi: parsing \"_\": invalid syntax", err.Error())
}

func TestSCrypt_Validate_InvalidSalt(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$8$1$_$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "encoding/hex: invalid byte: U+005F '_'", err.Error())
}

func TestSCrypt_Validate_InvalidDK(t *testing.T) {
	scrypt := crypto.NewSCrypt()
	scrypt.SaltGen = mockedSaltGen

	hashed := "32768$8$1$73616c74$_"
	err := scrypt.Validate(hashed, "test-123")
	assert.Equal(t, "encoding/hex: invalid byte: U+005F '_'", err.Error())
}

func TestSCrypt_Validate_UnsafeParams(t *testing.T) {
	scrypt := crypto.NewSCrypt()

	for _, hashed := range []string{
		"1048576$8$1$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1000$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1$73616c74$",
	} {
		assert.Error(t, scrypt.Validate(hashed, "x"), hashed)
	}
}
