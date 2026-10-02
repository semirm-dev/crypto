package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func fixedSalt(int) ([]byte, error) { return []byte("0123456789abcdef"), nil }

// reference computed with OpenSSL 3.5: openssl kdf ARGON2ID, pass test-123, salt 0123456789abcdef, t=3, m=65536, lanes=2
const argon2OpenSSL = "$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$fPT0u9P4JBezKhy07/DIjAJxHEFQAzSXWRzMd9zRXYA"

func TestArgon2_Defaults(t *testing.T) {
	a := NewArgon2()
	assert.Equal(t, Argon2{Memory: 65536, Time: 3, Threads: 2, SaltLen: 32, KeyLen: 32}, *a)
}

func TestArgon2_Hash_MatchesOpenSSL(t *testing.T) {
	a := NewArgon2()
	a.SaltLen, a.saltGen = 16, fixedSalt

	hashed, err := a.Hash("test-123")
	assert.NoError(t, err)
	assert.Equal(t, argon2OpenSSL, hashed)
}

func TestArgon2_Validate(t *testing.T) {
	a := NewArgon2()

	assert.NoError(t, a.Validate(argon2OpenSSL, "test-123"))
	assert.ErrorIs(t, a.Validate(argon2OpenSSL, "test-124"), ErrMismatch)

}

func TestArgon2_RoundTrip(t *testing.T) {
	a := NewArgon2()

	h1, err := a.Hash("x")
	assert.NoError(t, err)
	h2, _ := a.Hash("x")
	assert.NotEqual(t, h1, h2)
	assert.NoError(t, a.Validate(h1, "x"))
	assert.False(t, a.NeedsRehash(h1))
}

func TestArgon2_Hash_Errors(t *testing.T) {
	tests := map[string]func(*Argon2){
		"threads": func(a *Argon2) { a.Threads = 0 },
		"time":    func(a *Argon2) { a.Time = 0 },
		"memory":  func(a *Argon2) { a.Memory = 1 << 30 },
		"keylen":  func(a *Argon2) { a.KeyLen = 4 },
		"saltlen": func(a *Argon2) { a.SaltLen = 0 },
		"saltgen": func(a *Argon2) { a.saltGen = func(int) ([]byte, error) { return nil, assert.AnError } },
	}
	for name, mutate := range tests {
		a := NewArgon2()
		mutate(a)

		_, err := a.Hash("x")
		assert.Error(t, err, name)
	}
}

func TestArgon2_Validate_InvalidHash(t *testing.T) {
	const salt, dk = "MDEyMzQ1Njc4OWFiY2RlZg", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []string{
		"",
		"$argon2i$v=19$m=65536,t=3,p=2$" + salt + "$" + dk,
		"$argon2id$v=18$m=65536,t=3,p=2$" + salt + "$" + dk,
		"$argon2id$v=x$m=65536,t=3,p=2$" + salt + "$" + dk,
		"$argon2id$v=19$m=65536,t=3$" + salt + "$" + dk,
		"$argon2id$v=19$m=65536,t=3,p=2junk$" + salt + "$" + dk,
		"$argon2id$v=19$m=065536,t=3,p=2$" + salt + "$" + dk,
		"$argon2id$v=19$m=65536,t=3,p=2$!!$" + dk,
		"$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$!!",
		"$argon2id$v=19$m=65536,t=3,p=2$" + salt,
		"$argon2id$v=19$m=4194304,t=3,p=2$" + salt + "$" + dk,
		"$argon2id$v=19$m=65536,t=3,p=2$" + salt + "$AA",
	}
	for _, hashed := range tests {
		a := NewArgon2()

		assert.NotPanics(t, func() { assert.ErrorIs(t, a.Validate(hashed, "x"), ErrInvalidHash, hashed) }, hashed)
		assert.True(t, a.NeedsRehash(hashed), hashed)
	}
}

func TestArgon2_NeedsRehash(t *testing.T) {
	a := NewArgon2()
	a.SaltLen = 16
	assert.False(t, a.NeedsRehash(argon2OpenSSL))

	a.Time = 4
	assert.True(t, a.NeedsRehash(argon2OpenSSL))
	assert.True(t, NewArgon2().NeedsRehash(argon2OpenSSL)) // salt length 16 != default 32
}

func FuzzDecodeArgonHash(f *testing.F) {
	f.Add(argon2OpenSSL)
	f.Fuzz(func(t *testing.T, s string) {
		p, salt, dk, err := decodeArgonHash(s)
		if err != nil {
			assert.ErrorIs(t, err, ErrInvalidHash)
			return
		}
		assert.NoError(t, p.validateParams())
		assert.Len(t, dk, int(p.KeyLen))
		assert.Len(t, salt, p.SaltLen)
	})
}
