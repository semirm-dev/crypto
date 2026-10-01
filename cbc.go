package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

// CBC encryption. Output is IV || ciphertext || HMAC-SHA256 (encrypt-then-MAC).
// Prefer GCM for new code.
type CBC struct {
	Secret string // AES key: 16, 24 or 32 bytes
}

func NewCBC(secret string) *CBC {
	return &CBC{Secret: secret}
}

// Encrypt content using AES encryption CBC mode with random IV, returns raw and hex encoded output
func (cbcEnc *CBC) Encrypt(content []byte) (string, string, error) {
	block, err := aes.NewCipher([]byte(cbcEnc.Secret))
	if err != nil {
		return "", "", err
	}

	byteIn := pkcsPad(content, aes.BlockSize)
	out := make([]byte, aes.BlockSize+len(byteIn), aes.BlockSize+len(byteIn)+sha256.Size)

	iv := out[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aes.BlockSize:], byteIn)
	out = cbcEnc.mac(out).Sum(out)

	return string(out), hex.EncodeToString(out), nil
}

// Decrypt raw output of Encrypt
func (cbcEnc *CBC) Decrypt(encrypted string) (string, error) {
	block, err := aes.NewCipher([]byte(cbcEnc.Secret))
	if err != nil {
		return "", err
	}

	byteIn := []byte(encrypted)
	if len(byteIn) < 2*aes.BlockSize+sha256.Size || (len(byteIn)-sha256.Size)%aes.BlockSize != 0 {
		return "", errors.New("invalid encrypted text length")
	}

	body, tag := byteIn[:len(byteIn)-sha256.Size], byteIn[len(byteIn)-sha256.Size:]
	if !hmac.Equal(cbcEnc.mac(body).Sum(nil), tag) {
		return "", errors.New("authentication failed")
	}

	iv, ct := body[:aes.BlockSize], body[aes.BlockSize:]
	decrypted := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, ct)

	decrypted, err = pkcsUnPad(decrypted, aes.BlockSize)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// DecryptHex decrypts hex encoded output of Encrypt
func (cbcEnc *CBC) DecryptHex(encrypted string) (string, error) {
	raw, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	return cbcEnc.Decrypt(string(raw))
}

// mac returns HMAC primed with data, keyed by a key derived from Secret
func (cbcEnc *CBC) mac(data []byte) hash.Hash {
	kdf := hmac.New(sha256.New, []byte(cbcEnc.Secret))
	kdf.Write([]byte("cbc-mac-key"))

	m := hmac.New(sha256.New, kdf.Sum(nil))
	m.Write(data)

	return m
}

// pkcsPad for non-full length blocks.
// pkcs5 or pkcs7 will be used based on block size
func pkcsPad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(append([]byte{}, ciphertext...), padtext...)
}

// pkcsUnPad will remove PKCS5 padding.
// pkcs5 or pkcs7 will be used based on block size
func pkcsUnPad(input []byte, blockSize int) ([]byte, error) {
	inputLen := len(input)
	if inputLen == 0 {
		return nil, errors.New("cryptgo/padding: invalid padding size")
	}

	pad := input[inputLen-1]
	padLen := int(pad)
	if padLen == 0 || padLen > inputLen || padLen > blockSize {
		return nil, errors.New("cryptgo/padding: invalid padding size")
	}

	for _, v := range input[inputLen-padLen : inputLen-1] {
		if v != pad {
			return nil, errors.New("cryptgo/padding: invalid padding")
		}
	}

	return input[:inputLen-padLen], nil
}
