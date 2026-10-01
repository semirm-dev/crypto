![Go](https://img.shields.io/github/go-mod/go-version/semirm-dev/crypto)

Password hashing (Argon2id, scrypt, bcrypt) and authenticated encryption (AES-GCM, AES-CBC+HMAC) with safe defaults.

```go
// password hashing: every hasher implements crypto.Hasher
var h crypto.Hasher = crypto.NewArgon2()
hashed, err := h.Hash("password")
err = h.Validate(hashed, "password") // nil, crypto.ErrMismatch, or wraps crypto.ErrInvalidHash
if h.NeedsRehash(hashed) { /* parameters changed: re-hash after a successful Validate */ }

// encryption: every cipher implements crypto.Cipher (key: 16, 24 or 32 bytes)
key, _ := crypto.GenerateSalt(32)
gcm, err := crypto.NewGCM(key)
ct, err := gcm.Encrypt([]byte("secret"), []byte("user-42")) // aad binds the ciphertext to a context
pt, err := gcm.Decrypt(ct, []byte("user-42"))
s, err := crypto.EncryptString(gcm, "secret", nil) // URL-safe base64, see DecryptString

// passphrase instead of a random key
key, err = crypto.DeriveKey("passphrase", salt) // store salt (>= 8 bytes) next to the ciphertext
```

#### Formats
| Algorithm | Output | Verified against |
|---|---|---|
| Argon2id | `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>` (PHC) | OpenSSL 3.5 |
| scrypt | `$scrypt$ln=15,r=8,p=1$<salt>$<hash>` | RFC 7914, Python `hashlib` |
| bcrypt | `$2b$12$...` | Python `bcrypt` |
| GCM | `nonce \|\| ciphertext \|\| tag` | Python `cryptography` |
| CBC | `iv \|\| ciphertext \|\| HMAC-SHA256` (encrypt-then-MAC, separate derived keys, aad authenticated) | Python `cryptography` |

`Validate` still accepts the legacy hex formats of Argon2 (`version$m$t$p$salt$hash`) and scrypt (`N$r$p$salt$hash`); `NeedsRehash` reports them as outdated.

#### Safety properties
- `Validate` bounds every parameter of an untrusted hash (Argon2 memory <= 256 MiB and time <= 10, scrypt 128*N*r <= 256 MiB, key length 16-1024) before doing any work, so crafted hashes cannot panic or exhaust memory. The decoders are fuzzed.
- Salts must be at least 8 bytes. bcrypt rejects passwords over 72 bytes instead of truncating.
- All decryption failures return the same `ErrDecrypt`, and the MAC is verified before any padding is looked at.
- Hashers keep no state between calls; ciphers are immutable after construction. Both are safe for concurrent use.
- Argon2 uses 64 MiB per hash by default: limit concurrent hashes in servers, and rate-limit login endpoints.
- GCM uses random 96-bit nonces: rotate the key before ~2^32 messages per key.
- `CBC` is deprecated and only for compatibility; use `GCM`.

#### Development
```shell
make test        # vet + race tests
make test-cover
make bench
make fuzz
```
