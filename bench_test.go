package crypto

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkHash(b *testing.B) {
	for name, h := range map[string]Hasher{"argon2": NewArgon2(), "scrypt": NewSCrypt(), "bcrypt": NewBCrypt()} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				h.Hash("test-123")
			}
		})
	}
}

func BenchmarkCipher(b *testing.B) {
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))

	for name, c := range map[string]Cipher{"gcm": mustCipher(NewGCM(testKey))} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				ct, _ := c.Encrypt(pt, nil)
				c.Decrypt(ct, nil)
			}
		})
	}
}

func mustCipher[T Cipher](c T, err error) T {
	if err != nil {
		panic(err)
	}

	return c
}

// shared hashers and ciphers must be safe for concurrent use (run with -race)
func TestConcurrentUse(t *testing.T) {
	hashers := []Hasher{&Argon2{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, &SCrypt{N: 1024, R: 8, P: 1, SaltLen: 16, KeyLen: 32}, &BCrypt{Cost: 4}}
	ciphers := []Cipher{mustCipher(NewGCM(testKey))}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, h := range hashers {
				hashed, err := h.Hash("x")
				assert.NoError(t, err)
				assert.NoError(t, h.Validate(hashed, "x"))
			}
			for _, c := range ciphers {
				ct, err := c.Encrypt([]byte("x"), nil)
				assert.NoError(t, err)
				_, err = c.Decrypt(ct, nil)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
}
