package crypto

import (
	"crypto/subtle"
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

	salt, err := argon.SaltGen(argon.SaltLen)
	if err != nil {
		return "", err
	}

	dk := argon2.IDKey([]byte(value), salt, argon.Time, argon.Memory, argon.Threads, argon.KeyLen)

	return fmt.Sprintf("%d$%d$%d$%d$%x$%x", argon2.Version, argon.Memory, argon.Time, argon.Threads, salt, dk), nil
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

	return errors.New("invalid hash")
}

// decodeArgonHash returns parsed params, salt and derived key
func decodeArgonHash(encodedHash string) (*Argon2, []byte, []byte, error) {
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
