package crypto

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkHash(b *testing.B) {
	hash := map[string]func(string) (string, error){"argon2": NewArgon2().Hash, "scrypt": NewSCrypt().Hash}
	for name, fn := range hash {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				fn("test-123")
			}
		})
	}
}

func BenchmarkGCM(b *testing.B) {
	g, _ := NewGCM(testKey)
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))

	for b.Loop() {
		ct, _ := g.Encrypt(pt, nil)
		g.Decrypt(ct, nil)
	}
}

// shared hashers and ciphers must be safe for concurrent use (run with -race)
func TestConcurrentUse(t *testing.T) {
	type hasher interface {
		Hash(string) (string, error)
		Validate(string, string) error
	}
	hashers := []hasher{&Argon2{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, &SCrypt{N: 1024, R: 8, P: 1, SaltLen: 16, KeyLen: 32}}
	gcm, _ := NewGCM(testKey)

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
			ct, err := gcm.Encrypt([]byte("x"), nil)
			assert.NoError(t, err)
			_, err = gcm.Decrypt(ct, nil)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}
