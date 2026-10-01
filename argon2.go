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

const (
	maxArgonMemory = 256 * 1024 // KiB
	maxArgonTime   = 10
	minKeyLen      = 16
	maxKeyLen      = 1024
)

// Argon2 hashes passwords with Argon2id. Hashes are PHC strings:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>. The legacy hex format
// (version$m$t$p$salt$hash) is still accepted by Validate.
// Hashing uses Memory KiB per call, so limit concurrency in servers.
type Argon2 struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen int
	KeyLen  uint32

	saltGen func(int) ([]byte, error)
}

// NewArgon2 returns an Argon2 with 64 MiB, 3 iterations, 2 lanes (RFC 9106 second recommendation, fewer lanes).
func NewArgon2() *Argon2 {
	return &Argon2{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 32, KeyLen: 32}
}

// Hash returns the PHC encoded Argon2id hash of value.
func (a *Argon2) Hash(value string) (string, error) {
	if err := a.validateParams(); err != nil {
		return "", err
	}

	salt, err := newSalt(a.SaltLen, a.saltGen)
	if err != nil {
		return "", err
	}

	dk := argon2.IDKey([]byte(value), salt, a.Time, a.Memory, a.Threads, a.KeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, a.Memory, a.Time, a.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// Validate plain against hashed.
func (a *Argon2) Validate(hashed, plain string) error {
	p, salt, dk, err := decodeArgonHash(hashed)
	if err != nil {
		return err
	}

	got := argon2.IDKey([]byte(plain), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	defer clear(got)

	if subtle.ConstantTimeCompare(dk, got) != 1 {
		return ErrMismatch
	}

	return nil
}

// NeedsRehash reports whether hashed is legacy, unparsable or uses other parameters than a.
func (a *Argon2) NeedsRehash(hashed string) bool {
	p, _, _, err := decodeArgonHash(hashed)

	return err != nil || !strings.HasPrefix(hashed, "$") ||
		p.Memory != a.Memory || p.Time != a.Time || p.Threads != a.Threads || p.SaltLen != a.SaltLen || p.KeyLen != a.KeyLen
}

// validateParams guards against argon2 panics and unbounded cost.
func (a *Argon2) validateParams() error {
	switch {
	case a.Threads < 1:
		return errors.New("crypto: argon2 threads must be at least 1")
	case a.Time < 1 || a.Time > maxArgonTime:
		return fmt.Errorf("crypto: argon2 time must be between 1 and %d", maxArgonTime)
	case a.Memory < 8*uint32(a.Threads) || a.Memory > maxArgonMemory:
		return fmt.Errorf("crypto: argon2 memory must be between 8*threads and %d KiB", maxArgonMemory)
	case a.KeyLen < minKeyLen || a.KeyLen > maxKeyLen:
		return fmt.Errorf("crypto: argon2 key length must be between %d and %d", minKeyLen, maxKeyLen)
	}

	return nil
}

// decodeArgonHash parses a PHC string or legacy hex hash into validated params, salt and key.
func decodeArgonHash(encoded string) (*Argon2, []byte, []byte, error) {
	var (
		p         *Argon2
		salt, dk  []byte
		err       error
		decodeErr = func(format string, args ...any) (*Argon2, []byte, []byte, error) {
			return nil, nil, nil, invalidHash(format, args...)
		}
	)

	if strings.HasPrefix(encoded, "$") {
		p, salt, dk, err = decodePHCArgon(encoded)
	} else {
		p, salt, dk, err = decodeLegacyArgon(encoded)
	}
	if err != nil {
		return decodeErr("%v", err)
	}

	p.SaltLen, p.KeyLen = len(salt), uint32(len(dk))
	if err = p.validateParams(); err != nil {
		return decodeErr("%v", err)
	}

	return p, salt, dk, nil
}

// decodePHCArgon parses $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func decodePHCArgon(encoded string) (*Argon2, []byte, []byte, error) {
	values := strings.Split(encoded, "$")
	if len(values) != 6 || values[1] != "argon2id" {
		return nil, nil, nil, errors.New("not an argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(values[2], "v=%d", &version); err != nil || values[2] != "v="+strconv.Itoa(version) {
		return nil, nil, nil, errors.New("malformed version")
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(values[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil ||
		values[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, time, threads) {
		return nil, nil, nil, errors.New("malformed parameters")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(values[4])
	if err != nil {
		return nil, nil, nil, err
	}

	dk, err := base64.RawStdEncoding.Strict().DecodeString(values[5])
	if err != nil {
		return nil, nil, nil, err
	}

	return &Argon2{Memory: memory, Time: time, Threads: threads}, salt, dk, nil
}

// decodeLegacyArgon parses version$m$t$p$salt$hash with hex salt and key.
func decodeLegacyArgon(encoded string) (*Argon2, []byte, []byte, error) {
	values := strings.Split(encoded, "$")
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

	return &Argon2{Memory: uint32(memory), Time: uint32(time), Threads: uint8(threads)}, salt, dk, nil
}
