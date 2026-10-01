package crypto

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Credits to: https://github.com/elithrar/simple-scrypt/blob/master/scrypt.go

const maxScryptMemory = 256 << 20 // bytes

// SCrypt hashing algorithm
type SCrypt struct {
	N       int // 32768, should be the highest power of 2 derived within 100 milliseconds
	R       int // 8
	P       int // 1
	SaltLen int // 32
	KeyLen  int // 32
	SaltGen func(len int) ([]byte, error)
}

// NewSCrypt will initialize default SCrypt params
func NewSCrypt() *SCrypt {
	return &SCrypt{
		N:       32768,
		R:       8,
		P:       1,
		SaltLen: 32,
		KeyLen:  32,
		SaltGen: GenerateSalt,
	}
}

// Hash sCrypt.Plain
func (sCrypt *SCrypt) Hash(value string) (string, error) {
	if err := sCrypt.validateParams(); err != nil {
		return "", err
	}

	salt, err := newSalt(sCrypt.SaltLen, sCrypt.SaltGen)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(value), salt, sCrypt.N, sCrypt.R, sCrypt.P, sCrypt.KeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%d$%d$%d$%x$%x", sCrypt.N, sCrypt.R, sCrypt.P, salt, dk), nil
}

// validateParams guards against unbounded cost
func (sCrypt *SCrypt) validateParams() error {
	switch {
	case sCrypt.N < 2 || sCrypt.N&(sCrypt.N-1) != 0:
		return errors.New("scrypt: N must be a power of 2 greater than 1")
	case sCrypt.R < 1 || sCrypt.R > 32 || sCrypt.P < 1 || sCrypt.P > 16:
		return errors.New("scrypt: R must be 1-32 and P must be 1-16")
	case sCrypt.N > maxScryptMemory/128/sCrypt.R:
		return fmt.Errorf("scrypt: memory 128*N*R exceeds %d bytes", maxScryptMemory)
	case sCrypt.KeyLen < minKeyLen || sCrypt.KeyLen > maxKeyLen:
		return fmt.Errorf("scrypt: key length must be between %d and %d", minKeyLen, maxKeyLen)
	}

	return nil
}

// Validate sCrypt.Plain against sCrypt.Hashed
func (sCrypt *SCrypt) Validate(hashed, plain string) error {
	existing, salt, edk, err := decodeSCryptHash(hashed)
	if err != nil {
		return err
	}

	dk, err := scrypt.Key([]byte(plain), salt, existing.N, existing.R, existing.P, existing.KeyLen)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(edk, dk) == 1 {
		return nil
	}

	return ErrMismatch
}

// decodeSCryptHash returns parsed params, salt and derived key
func decodeSCryptHash(hash string) (*SCrypt, []byte, []byte, error) {
	values := strings.Split(hash, "$")

	// N, R, P, Salt, scrypt derived key
	if len(values) != 5 {
		return nil, nil, nil, errors.New("invalid hash length")
	}

	sCrypt := &SCrypt{}
	var err error

	if sCrypt.N, err = strconv.Atoi(values[0]); err != nil {
		return nil, nil, nil, err
	}
	if sCrypt.R, err = strconv.Atoi(values[1]); err != nil {
		return nil, nil, nil, err
	}
	if sCrypt.P, err = strconv.Atoi(values[2]); err != nil {
		return nil, nil, nil, err
	}

	salt, err := hex.DecodeString(values[3])
	if err != nil {
		return nil, nil, nil, err
	}
	sCrypt.SaltLen = len(salt)

	dk, err := hex.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}
	sCrypt.KeyLen = len(dk)

	if err = sCrypt.validateParams(); err != nil {
		return nil, nil, nil, err
	}

	return sCrypt, salt, dk, nil
}
