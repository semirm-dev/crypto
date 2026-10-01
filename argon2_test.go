package crypto_test

import (
	"github.com/gobackpack/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewArgon2(t *testing.T) {
	argon2 := crypto.NewArgon2()

	assert.Equal(t, uint32(64*1024), argon2.Memory)
	assert.Equal(t, uint32(3), argon2.Time)
	assert.Equal(t, uint8(2), argon2.Threads)
	assert.Equal(t, 32, argon2.SaltLen)
	assert.Equal(t, uint32(32), argon2.KeyLen)
}

func TestArgon2_Hash(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed, err := argon2.Hash("test-123")
	assert.NoError(t, err)

	assert.Regexp(t, `^\$argon2id\$v=19\$m=65536,t=3,p=2\$`, hashed)
	assert.NoError(t, argon2.Validate(hashed, "test-123"))
}

func TestArgon2_Hash_SaltGenFail(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGenErr

	_, err := argon2.Hash("test-123")
	assert.Equal(t, "salt gen failed", err.Error())
}

func TestArgon2_Validate(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$3$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.NoError(t, err)
}

func TestArgon2_Validate_InvalidHash(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$3$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102a"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "invalid hash", err.Error())
}

func TestArgon2_Validate_InvalidLength(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "invalid hash length", err.Error())
}

func TestArgon2_Validate_InvalidVersion(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "_$65536$3$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.Atoi: parsing \"_\": invalid syntax", err.Error())
}

func TestArgon2_Validate_IncompatibleVersion(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "0000$65536$3$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "incompatible argon2 version", err.Error())
}

func TestArgon2_Validate_InvalidMemory(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$_$3$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.ParseUint: parsing \"_\": invalid syntax", err.Error())
}

func TestArgon2_Validate_InvalidTime(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$_$2$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.ParseUint: parsing \"_\": invalid syntax", err.Error())
}

func TestArgon2_Validate_InvalidThread(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$3$_$73616c74$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "strconv.ParseUint: parsing \"_\": invalid syntax", err.Error())
}

func TestArgon2_Validate_InvalidSalt(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$3$2$_$d8801786d6416fb063115b1b997ef50a56cd862a5e59062e2c6aadd301be102e"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "encoding/hex: invalid byte: U+005F '_'", err.Error())
}

func TestArgon2_Validate_InvalidDK(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = mockedSaltGen

	hashed := "19$65536$3$2$73616c74$_"
	err := argon2.Validate(hashed, "test-123")
	assert.Equal(t, "encoding/hex: invalid byte: U+005F '_'", err.Error())
}

func TestArgon2_Validate_UnsafeParams(t *testing.T) {
	argon2 := crypto.NewArgon2()

	for _, hashed := range []string{
		"19$65536$3$0$73616c74$d8801786d6416fb063115b1b997ef50a",
		"19$65536$0$2$73616c74$d8801786d6416fb063115b1b997ef50a",
		"19$65536$3$256$73616c74$d8801786d6416fb063115b1b997ef50a",
		"19$4194304$3$2$73616c74$d8801786d6416fb063115b1b997ef50a",
		"19$65536$3$2$73616c74$",
	} {
		assert.NotPanics(t, func() { assert.Error(t, argon2.Validate(hashed, "x")) }, hashed)
	}
}

func TestArgon2_Hash_InvalidParams(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.Threads = 0

	_, err := argon2.Hash("x")
	assert.Error(t, err)
}

func TestArgon2_Hash_Stateless(t *testing.T) {
	argon2 := crypto.NewArgon2()

	a, _ := argon2.Hash("x")
	b, _ := argon2.Hash("x")
	assert.NotEqual(t, a, b)
}

// reference value computed with OpenSSL 3.5 (openssl kdf ARGON2ID)
const argon2OpenSSL = "$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$fPT0u9P4JBezKhy07/DIjAJxHEFQAzSXWRzMd9zRXYA"

func TestArgon2_Validate_PHC_OpenSSLVector(t *testing.T) {
	argon2 := crypto.NewArgon2()

	assert.NoError(t, argon2.Validate(argon2OpenSSL, "test-123"))
	assert.Equal(t, crypto.ErrMismatch, argon2.Validate(argon2OpenSSL, "test-124"))
}

func TestArgon2_Validate_PHC_Invalid(t *testing.T) {
	argon2 := crypto.NewArgon2()

	for _, hashed := range []string{
		"$argon2i$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=18$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=x$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=2junk$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$!!",
		"$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg",
		"$argon2id$v=19$m=4194304,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		assert.Error(t, argon2.Validate(hashed, "x"), hashed)
	}
}

func TestArgon2_Hash_SaltTooShort(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltLen = 0

	_, err := argon2.Hash("x")
	assert.Error(t, err)
}

func TestArgon2_Hash_NilSaltGen(t *testing.T) {
	argon2 := crypto.NewArgon2()
	argon2.SaltGen = nil

	hashed, err := argon2.Hash("x")
	assert.NoError(t, err)
	assert.NoError(t, argon2.Validate(hashed, "x"))
}
