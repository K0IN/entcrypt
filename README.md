# entcrypt

[![CI](https://github.com/k0in/entcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/k0in/entcrypt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/k0in/entcrypt.svg)](https://pkg.go.dev/github.com/k0in/entcrypt)
[![Go Version](https://img.shields.io/github/go-mod/go-version/k0in/entcrypt)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`entcrypt` provides automatic field-level encryption for [ent](https://entgo.io/) schemas. Fields
are encrypted before writes (via hooks) and decrypted after reads (via
interceptors) using AES-256-GCM. Clients always see plaintext values.

## Features

- **Automatic encryption/decryption** — encrypt on write, decrypt on read
- **Annotation-based** — mark fields with `entcrypt.EncryptedField{}`
- **AES-256-GCM** — authenticated encryption with random nonces
- **Pluggable key providers** — static keys, env vars, or your own
- **No schema changes** — encrypted data stays in the same string column
- **entc extension** — auto-discovers encrypted fields during codegen

## Supported field types

| Type | Description |
|------|-------------|
| `string` | Only `string` fields can be encrypted. The ciphertext is stored in the same column, so the field type must be compatible. Make sure your columns are long enough to accommodate the encrypted data. |

## Installation

```bash
go get github.com/k0in/entcrypt
```

## Quick start

### 1. Mark fields for encryption

Annotate any `string` field with `entcrypt.EncryptedField{}`:

```go
// ent/schema/user.go
package schema

import (
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "github.com/k0in/entcrypt"
)

type User struct{ ent.Schema }

func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("name"),
        field.String("email").Annotations(entcrypt.EncryptedField{}),
        field.String("ssn").Annotations(entcrypt.EncryptedField{}),
    }
}
```

### 2. Add the entcrypt extension to `entc`

```go
// cmd/entc/main.go
package main

import (
    "entgo.io/ent/entc"
    "entgo.io/ent/entc/gen"
    "github.com/k0in/entcrypt"
)

func main() {
    entc.Generate("./ent/schema", &gen.Config{}, 
        entc.Extensions(entcrypt.Extension{}),
    )
}
```

Now run `go run cmd/entc/main.go`. The extension scans all schemas, discovers
`EncryptedField` annotations, and emits an `entcrypt_gen.go` file that
registers the mapping automatically.

### 3. Use hooks and interceptors at runtime

```diff
 func main() {
     ctx := context.Background()

     // Create an encrypter from a hex-encoded AES-256 key.
+    key, _ := hex.DecodeString(os.Getenv("ENTCRYPT_KEY"))
+    enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})
+    if err != nil {
+        log.Fatal(err)
+    }

     // Open the ent client.
     client, err := ent.Open(dialect.SQLite, "file:ent.db?_fk=1")
     if err != nil {
         log.Fatal(err)
     }
     defer client.Close()

     // Install the encryption hook (writes) and decryption interceptor (reads).
+    client.Use(entx.EncryptHookFunc(enc))
+    client.Intercept(entx.DecryptInterceptor(enc))

     // Create — field values are encrypted in the DB.
     u, err := client.User.Create().
         SetName("Alice").
         SetEmail("alice@example.com").
         SetSsn("000-00-0000").
         Save(ctx)
     // u.Email → "alice@example.com" (plaintext on the returned value)

     // Get — values are decrypted automatically.
     u, err = client.User.Get(ctx, u.ID)
     // u.Email → "alice@example.com"

     // Query — all results are decrypted.
     all, err := client.User.Query().All(ctx)
     // all[0].Email → "alice@example.com"
 }
```

### 4. Set your encryption key

```bash
export ENTCRYPT_KEY=$(openssl rand -hex 32)
```

## Key Providers

```go
// StaticKeyProvider- Set the key directly in code (loaded from env, flag, or config)
key, _ := hex.DecodeString(os.Getenv("ENTCRYPT_KEY"))
enc, _ := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})

// EnvKeyProvider - Reads a hex-encoded key from an environment variable automatically
enc, _ := entcrypt.New(&entcrypt.EnvKeyProvider{EnvVar: "ENTCRYPT_KEY"})

// Custom provider - implement the KeyProvider interface for your own key source (Vault, AWS KMS, etc.)

type VaultProvider struct { ... }

func (p *VaultProvider) EncryptionKey() ([]byte, error) {
    return p.fetchKey()
}
```

## Without the entc extension

You don't have to use the `entcrypt.Extension{}` with a custom `cmd/entc/main.go`.
If you prefer standard `go generate ./ent`, just register the encrypted fields
manually:

```go
// ent/entcrypt_gen.go
package ent

import "github.com/k0in/entcrypt"

func init() {
    entcrypt.Register("User", "email", "ssn")
}
```

Keep this list in sync with your schema annotations. That's the only extra step.

See [`examples/noentc/`](./examples/noentc/) for a complete working example.

## Memory protection

Built with the `goexperiment.runtimesecret` tag, entcrypt uses [`runtime/secret`](https://pkg.go.dev/runtime/secret) to protect decrypted plaintext from GC scanning:

```bash
go build -tags goexperiment.runtimesecret ./...
```

Without the tag, entcrypt falls back to standard decryption.

## Examples

Two examples are provided in the [`examples/`](./examples/) directory:

| Directory | Approach | Codegen command |
|-----------|----------|----------------|
| [`simple`](./examples/simple/) | `entcrypt.Extension{}` with `entc.Generate()` (auto-register) | `go run ./cmd/entc/` |
| [`noentc`](./examples/noentc/) | Standard `go generate` (manual register) | `go generate ./ent` |

Both produce the same runtime behaviour — the difference is only in how encrypted fields are registered.

## How it works

| Layer | Component | What it does |
|-------|-----------|--------------|
| Codegen | `entcrypt.Extension{}` in `entc.Generate()` | Scans schemas, auto-discovers `EncryptedField` annotations, emits a registry file |
| Schema | `entcrypt.EncryptedField{}` annotation | Marks a string field as encrypted |
| Hook | `entx.EncryptHookFunc(enc)` | Encrypts field values before DB writes |
| Interceptor | `entx.DecryptInterceptor(enc)` | Decrypts field values after DB reads |

1. **Codegen time**: The `entcrypt.Extension` hook fires during `entc.Generate()`,
   inspects every `Field.Annotations` for `EncryptedField`, and writes an
   `entcrypt_gen.go` file with an `init()` that registers the mapping. No
   manual config needed.
2. **Write path**: The `EncryptHookFunc` hook intercepts `Create` and `Update`
   mutations, looks up the entity type in the registry, encrypts the matching
   string fields, then passes the ciphertext to the database.
3. **Read path**: The `DecryptInterceptor` interceptor runs after every query
   (`Get`, `Query`, `QueryX`), decrypts encrypted fields, and returns the
   plaintext to the caller.
4. **Return values**: The hook also decrypts the value returned by `Save`,
   `Update`, and `UpdateOne` so callers always see plaintext.

### Storage format

Every encrypted value is stored as a plain-text header followed by the
base64-encoded ciphertext. This makes the format self-describing and easy
to identify when inspecting the database directly:

```
v1:AES-256-GCM:<base64>
```

| Part | Example | Description |
|------|---------|-------------|
| Version | `v1` | Format version for future migration |
| Algorithm | `AES-256-GCM` | Cipher suite used |
| Body | `<base64>` | Nonce + AES-GCM authenticated ciphertext, base64-encoded |

```sql
-- Inspecting encrypted data in the database:
sqlite3 ent.db "SELECT email, ssn FROM users;"
-- email → "v1:AES-256-GCM:qK4RmjH...#..."
-- ssn  → "v1:AES-256-GCM:8LpX2yT...#..."
```

## API Reference

| Package | Type / Function | Description |
|---------|----------------|-------------|
| `entcrypt` | `EncryptedField{}` | Schema annotation for encrypted string fields |
| `entcrypt` | `Extension{}` | entc extension that auto-discovers encrypted fields during codegen |
| `entcrypt` | `New(provider)` | Creates an `Encrypter` from a key provider |
| `entcrypt` | `StaticKeyProvider` | Key provider with a static AES key |
| `entcrypt` | `EnvKeyProvider` | Key provider reading from an env var |
| `entx` | `EncryptHookFunc(enc)` | Returns an ent.Hook that encrypts on write |
| `entx` | `DecryptInterceptor(enc)` | Returns an ent.Interceptor that decrypts on read |