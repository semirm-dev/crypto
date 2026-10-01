![alt Go](https://img.shields.io/github/go-mod/go-version/gobackpack/crypto)

Thin wrappers around password hashing (Argon2id, scrypt, bcrypt) and AES encryption (GCM, CBC).

#### Usage
```go
hashed, err := crypto.NewArgon2().Hash("password")
err = crypto.NewArgon2().Validate(hashed, "password") // nil on match

gcm := crypto.NewGCM("0123456789abcdef") // 16, 24 or 32 byte key
raw, hexed, b64, err := gcm.Encrypt([]byte("secret"))
plain, err := gcm.DecryptBase64(b64)
```

#### Notes
- Argon2 hashes are standard PHC strings (`$argon2id$v=19$m=65536,t=3,p=2$salt$hash`), verified against OpenSSL. The legacy `version$m$t$p$salt$hash` hex format is still accepted by `Validate`. scrypt output is `N$r$p$salt$key` (hex); scrypt is verified against RFC 7914 and bcrypt against Python `bcrypt`.
- `Validate` returns `ErrMismatch` on a wrong password. Salts must be at least 8 bytes.
- `GCM` uses random 96-bit nonces: rotate the key before ~2^32 messages.
- `Hash` does not mutate the receiver, instances are safe to share between goroutines.
- `Validate` rejects hashes whose cost parameters are out of bounds (Argon2 memory <= 256 MiB, time <= 10; scrypt 128*N*R <= 256 MiB) to prevent DoS from untrusted hashes. Argon2 hashing is memory heavy (64 MiB by default), limit concurrent hashes in servers.
- Secrets are raw AES keys, not passphrases. Derive them with a KDF first if needed.
- Prefer `GCM`. `CBC` uses a random IV and HMAC-SHA256 (encrypt-then-MAC); its output format is not compatible with earlier versions.

#### Run tests
```shell
make test-cover
```
