package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Credits to: https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go

const (
	maxArgonMemory = 256 * 1024 // KiB
	maxArgonTime   = 10
	minKeyLen      = 16
	maxKeyLen      = 1024
)

// Argon2 hashing algorithm
type Argon2 struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen int
	KeyLen  uint32
	SaltGen func(len int) ([]byte, error)
}

// NewArgon2 will initialize default Argon2 params
func NewArgon2() *Argon2 {
	return &Argon2{
		Memory:  64 * 1024,
		Time:    3,
		Threads: 2,
		SaltLen: 32,
		KeyLen:  32,
		SaltGen: GenerateSalt,
	}
}

// Hash value using argon2 algorithm
func (argon *Argon2) Hash(value string) (string, error) {
	if err := argon.validateParams(); err != nil {
		return "", err
	}

	salt, err := newSalt(argon.SaltLen, argon.SaltGen)
	if err != nil {
		return "", err
	}

	dk := argon2.IDKey([]byte(value), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argon.Memory, argon.Time, argon.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// validateParams guards against argon2 panics and unbounded cost
func (argon *Argon2) validateParams() error {
	switch {
	case argon.Threads < 1:
		return errors.New("argon2: threads must be at least 1")
	case argon.Time < 1 || argon.Time > maxArgonTime:
		return fmt.Errorf("argon2: time must be between 1 and %d", maxArgonTime)
	case argon.Memory < 8*uint32(argon.Threads) || argon.Memory > maxArgonMemory:
		return fmt.Errorf("argon2: memory must be between 8*threads and %d KiB", maxArgonMemory)
	case argon.KeyLen < minKeyLen || argon.KeyLen > maxKeyLen:
		return fmt.Errorf("argon2: key length must be between %d and %d", minKeyLen, maxKeyLen)
	}

	return nil
}

// Validate plain against hashed
func (argon *Argon2) Validate(hashed, plain string) error {
	existing, salt, edk, err := decodeArgonHash(hashed)
	if err != nil {
		return err
	}

	dk := argon2.IDKey([]byte(plain), salt, existing.Time, existing.Memory, existing.Threads, existing.KeyLen)

	if subtle.ConstantTimeCompare(edk, dk) == 1 {
		return nil
	}

	return ErrMismatch
}

// decodePHCArgonHash parses $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func decodePHCArgonHash(encodedHash string) (*Argon2, []byte, []byte, error) {
	values := strings.Split(encodedHash, "$")
	if len(values) != 6 || values[1] != "argon2id" {
		return nil, nil, nil, errors.New("invalid hash")
	}

	var version int
	if _, err := fmt.Sscanf(values[2], "v=%d", &version); err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}

	dk, err := base64.RawStdEncoding.Strict().DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}

	if values[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, time, threads) {
		return nil, nil, nil, errors.New("invalid hash params")
	}

	argon := &Argon2{Memory: memory, Time: time, Threads: threads, SaltLen: len(salt), KeyLen: uint32(len(dk))}
	if err = argon.validateParams(); err != nil {
		return nil, nil, nil, err
	}

	return argon, salt, dk, nil
}

// decodeArgonHash parses PHC string or legacy hex format (version$m$t$p$salt$hash)
func decodeArgonHash(encodedHash string) (*Argon2, []byte, []byte, error) {
	if strings.HasPrefix(encodedHash, "$") {
		return decodePHCArgonHash(encodedHash)
	}

	values := strings.Split(encodedHash, "$")
	if len(values) != 6 {
		return nil, nil, nil, errors.New("invalid hash length")
	}

	version, err := strconv.Atoi(values[0])
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
	}

	memory, err := strconv.ParseUint(values[1], 10, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	time, err := strconv.ParseUint(values[2], 10, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	threads, err := strconv.ParseUint(values[3], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := hex.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}

	dk, err := hex.DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}

	argon := &Argon2{
		Memory:  uint32(memory),
		Time:    uint32(time),
		Threads: uint8(threads),
		SaltLen: len(salt),
		KeyLen:  uint32(len(dk)),
	}
	if err = argon.validateParams(); err != nil {
		return nil, nil, nil, err
	}

	return argon, salt, dk, nil
}
