package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// RFC 7914 section 12 vector 3: pleaseletmein / SodiumChloride, N=16384 r=8 p=1 dkLen=64
const (
	scryptRFCPHC    = "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw"
	scryptRFCLegacy = "16384$8$1$536f6469756d43686c6f72696465$7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
)

func TestSCrypt_Defaults(t *testing.T) {
	assert.Equal(t, SCrypt{N: 32768, R: 8, P: 1, SaltLen: 32, KeyLen: 32}, *NewSCrypt())
}

func TestSCrypt_Hash_MatchesRFC7914(t *testing.T) {
	s := &SCrypt{N: 16384, R: 8, P: 1, SaltLen: 14, KeyLen: 64, saltGen: func(int) ([]byte, error) { return []byte("SodiumChloride"), nil }}

	hashed, err := s.Hash("pleaseletmein")
	assert.NoError(t, err)
	assert.Equal(t, scryptRFCPHC, hashed)
}

func TestSCrypt_Validate(t *testing.T) {
	s := NewSCrypt()

	for _, hashed := range []string{scryptRFCPHC, scryptRFCLegacy} {
		assert.NoError(t, s.Validate(hashed, "pleaseletmein"))
		assert.ErrorIs(t, s.Validate(hashed, "x"), ErrMismatch)
	}

	// computed with Python hashlib.scrypt
	assert.NoError(t, s.Validate("32768$8$1$73616c74$2560437b98f140fbf72bff2290d772c2593c1ea4dd2206b6b0dfbdc025bcced5", "test-123"))
}

func TestSCrypt_RoundTrip(t *testing.T) {
	s := NewSCrypt()

	hashed, err := s.Hash("x")
	assert.NoError(t, err)
	assert.NoError(t, s.Validate(hashed, "x"))
	assert.ErrorIs(t, s.Validate(hashed, "y"), ErrMismatch)
	assert.False(t, s.NeedsRehash(hashed))

	s.N = 16384
	assert.True(t, s.NeedsRehash(hashed))
	assert.True(t, s.NeedsRehash(scryptRFCLegacy))
}

func TestSCrypt_Hash_Errors(t *testing.T) {
	tests := map[string]func(*SCrypt){
		"n zero":    func(s *SCrypt) { s.N = 0 },
		"n not pow": func(s *SCrypt) { s.N = 3000 },
		"r":         func(s *SCrypt) { s.R = 0 },
		"p":         func(s *SCrypt) { s.P = 17 },
		"memory":    func(s *SCrypt) { s.N = 1 << 20 },
		"keylen":    func(s *SCrypt) { s.KeyLen = 4 },
		"saltlen":   func(s *SCrypt) { s.SaltLen = 0 },
		"saltgen":   func(s *SCrypt) { s.saltGen = func(int) ([]byte, error) { return nil, assert.AnError } },
	}
	for name, mutate := range tests {
		s := NewSCrypt()
		mutate(s)

		_, err := s.Hash("x")
		assert.Error(t, err, name)
	}
}

func TestSCrypt_Validate_InvalidHash(t *testing.T) {
	const salt, dk = "U29kaXVtQ2hsb3JpZGU", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []string{
		"",
		"32768$",
		"_$8$1$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$_$1$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$_$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1$_$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1$73616c74$_",
		"1048576$8$1$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1000$73616c74$d8801786d6416fb063115b1b997ef50a",
		"32768$8$1$73616c74$",
		"3000$8$1$73616c74$d8801786d6416fb063115b1b997ef50a",
		"$scrypt2$ln=14,r=8,p=1$" + salt + "$" + dk,
		"$scrypt$ln=14,r=8$" + salt + "$" + dk,
		"$scrypt$ln=14,r=8,p=1x$" + salt + "$" + dk,
		"$scrypt$ln=0,r=8,p=1$" + salt + "$" + dk,
		"$scrypt$ln=63,r=8,p=1$" + salt + "$" + dk,
		"$scrypt$ln=20,r=8,p=1$" + salt + "$" + dk,
		"$scrypt$ln=14,r=8,p=1$!!$" + dk,
		"$scrypt$ln=14,r=8,p=1$" + salt + "$!!",
		"$scrypt$ln=14,r=8,p=1$" + salt,
	}
	for _, hashed := range tests {
		s := NewSCrypt()

		assert.NotPanics(t, func() { assert.ErrorIs(t, s.Validate(hashed, "x"), ErrInvalidHash, hashed) }, hashed)
		assert.True(t, s.NeedsRehash(hashed), hashed)
	}
}

func FuzzDecodeSCryptHash(f *testing.F) {
	f.Add(scryptRFCPHC)
	f.Add(scryptRFCLegacy)
	f.Fuzz(func(t *testing.T, s string) {
		p, salt, dk, err := decodeSCryptHash(s)
		if err != nil {
			assert.ErrorIs(t, err, ErrInvalidHash)
			return
		}
		assert.NoError(t, p.validateParams())
		assert.Len(t, dk, p.KeyLen)
		assert.Len(t, salt, p.SaltLen)
	})
}
