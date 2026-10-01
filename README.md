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
- `Hash` does not mutate the receiver, instances are safe to share between goroutines.
- `Validate` rejects hashes whose cost parameters are out of bounds (Argon2 memory <= 256 MiB, time <= 10; scrypt 128*N*R <= 256 MiB) to prevent DoS from untrusted hashes. Argon2 hashing is memory heavy (64 MiB by default), limit concurrent hashes in servers.
- Secrets are raw AES keys, not passphrases. Derive them with a KDF first if needed.
- Prefer `GCM`. `CBC` uses a random IV and HMAC-SHA256 (encrypt-then-MAC); its output format is not compatible with earlier versions.

#### Run tests
```shell
make test-cover
```
