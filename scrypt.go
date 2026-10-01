package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	maxScryptMemory = 256 << 20 // bytes
	maxScryptLogN   = 30
)

// SCrypt hashes passwords with scrypt. Hashes look like
// $scrypt$ln=15,r=8,p=1$<salt>$<hash>. The legacy hex format (N$r$p$salt$hash)
// is still accepted by Validate.
type SCrypt struct {
	N       int // power of 2, ideally the highest that hashes within ~100ms
	R       int
	P       int
	SaltLen int
	KeyLen  int

	saltGen func(int) ([]byte, error)
}

// NewSCrypt returns an SCrypt with N=32768, r=8, p=1.
func NewSCrypt() *SCrypt {
	return &SCrypt{N: 32768, R: 8, P: 1, SaltLen: 32, KeyLen: 32}
}

// Hash returns the encoded scrypt hash of value.
func (s *SCrypt) Hash(value string) (string, error) {
	if err := s.validateParams(); err != nil {
		return "", err
	}

	salt, err := newSalt(s.SaltLen, s.saltGen)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(value), salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s", bits.TrailingZeros(uint(s.N)), s.R, s.P,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// Validate plain against hashed.
func (s *SCrypt) Validate(hashed, plain string) error {
	p, salt, dk, err := decodeSCryptHash(hashed)
	if err != nil {
		return err
	}

	got, err := scrypt.Key([]byte(plain), salt, p.N, p.R, p.P, p.KeyLen)
	if err != nil {
		return invalidHash("%v", err)
	}
	defer clear(got)

	if subtle.ConstantTimeCompare(dk, got) != 1 {
		return ErrMismatch
	}

	return nil
}

// NeedsRehash reports whether hashed is legacy, unparsable or uses other parameters than s.
func (s *SCrypt) NeedsRehash(hashed string) bool {
	p, _, _, err := decodeSCryptHash(hashed)

	return err != nil || !strings.HasPrefix(hashed, "$") ||
		p.N != s.N || p.R != s.R || p.P != s.P || p.SaltLen != s.SaltLen || p.KeyLen != s.KeyLen
}

// validateParams guards against invalid parameters and unbounded cost.
func (s *SCrypt) validateParams() error {
	switch {
	case s.N < 2 || s.N&(s.N-1) != 0:
		return errors.New("crypto: scrypt N must be a power of 2 greater than 1")
	case s.R < 1 || s.R > 32 || s.P < 1 || s.P > 16:
		return errors.New("crypto: scrypt r must be 1-32 and p must be 1-16")
	case s.N > maxScryptMemory/128/s.R:
		return fmt.Errorf("crypto: scrypt memory 128*N*r exceeds %d bytes", maxScryptMemory)
	case s.KeyLen < minKeyLen || s.KeyLen > maxKeyLen:
		return fmt.Errorf("crypto: scrypt key length must be between %d and %d", minKeyLen, maxKeyLen)
	}

	return nil
}

// decodeSCryptHash parses a PHC-style or legacy hex hash into validated params, salt and key.
func decodeSCryptHash(encoded string) (*SCrypt, []byte, []byte, error) {
	var (
		p        *SCrypt
		salt, dk []byte
		err      error
	)

	if strings.HasPrefix(encoded, "$") {
		p, salt, dk, err = decodePHCSCrypt(encoded)
	} else {
		p, salt, dk, err = decodeLegacySCrypt(encoded)
	}
	if err != nil {
		return nil, nil, nil, invalidHash("%v", err)
	}

	p.SaltLen, p.KeyLen = len(salt), len(dk)
	if err = p.validateParams(); err != nil {
		return nil, nil, nil, invalidHash("%v", err)
	}

	return p, salt, dk, nil
}

// decodePHCSCrypt parses $scrypt$ln=15,r=8,p=1$<salt>$<hash>.
func decodePHCSCrypt(encoded string) (*SCrypt, []byte, []byte, error) {
	values := strings.Split(encoded, "$")
	if len(values) != 5 || values[1] != "scrypt" {
		return nil, nil, nil, errors.New("not a scrypt hash")
	}

	var ln, r, p int
	if _, err := fmt.Sscanf(values[2], "ln=%d,r=%d,p=%d", &ln, &r, &p); err != nil ||
		values[2] != fmt.Sprintf("ln=%d,r=%d,p=%d", ln, r, p) || ln < 1 || ln > maxScryptLogN {
		return nil, nil, nil, errors.New("malformed parameters")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(values[3])
	if err != nil {
		return nil, nil, nil, err
	}

	dk, err := base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}

	return &SCrypt{N: 1 << ln, R: r, P: p}, salt, dk, nil
}

// decodeLegacySCrypt parses N$r$p$salt$hash with hex salt and key.
func decodeLegacySCrypt(encoded string) (*SCrypt, []byte, []byte, error) {
	values := strings.Split(encoded, "$")
	if len(values) != 5 {
		return nil, nil, nil, errors.New("invalid hash length")
	}

	s := &SCrypt{}
	var err error

	if s.N, err = strconv.Atoi(values[0]); err != nil {
		return nil, nil, nil, err
	}
	if s.R, err = strconv.Atoi(values[1]); err != nil {
		return nil, nil, nil, err
	}
	if s.P, err = strconv.Atoi(values[2]); err != nil {
		return nil, nil, nil, err
	}

	salt, err := hex.DecodeString(values[3])
	if err != nil {
		return nil, nil, nil, err
	}

	dk, err := hex.DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}

	return s, salt, dk, nil
}
