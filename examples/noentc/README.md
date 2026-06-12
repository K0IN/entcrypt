# examples/noentc — Using entcrypt without the entc extension

This example shows the **alternative** approach: using standard `go generate`
without the `entcrypt.Extension{}`. You manually register encrypted fields
instead of relying on the codegen extension.

## How it works

1. **Schema** (`ent/schema/user.go`) — fields are annotated with `entcrypt.EncryptedField{}`
   (same as the `simple` example).
2. **Codegen** (`ent/generate.go`) — instead of a custom `cmd/entc/main.go`, the
   standard ent codegen CLI is invoked via `//go:generate`.
3. **Registry** (`ent/entcrypt_gen.go`) — **manually maintained**. You call
   `entcrypt.Register("User", "email", "ssn")` yourself, keeping it in sync
   with your schema. This replaces what the extension does automatically.
4. **Runtime** (`main.go`) — identical to the `simple` example: hooks and
   interceptors handle encryption/decryption transparently.

## Why use this approach?

- You don't want a custom `cmd/entc/main.go` in your project.
- You prefer plain `go generate ./ent`.
- You already have a codegen workflow and just need to add the registry call.

## Key files to look at

| File | What it does |
|------|-------------|
| `ent/schema/user.go` | Schema defining which fields are encrypted |
| `ent/generate.go` | `go:generate` directive using standard ent codegen (no entcrypt extension) |
| `ent/entcrypt_gen.go` | **Manually written** — registers encrypted fields via `entcrypt.Register()` |
| `tools.go` | Pins the `entgo.io/ent/cmd/entc` module so `go mod tidy` keeps it available for codegen |
| `main.go` | Application wiring hooks, interceptors, and queries |

## Run it

```bash
go generate ./ent          # standard ent codegen (no entcrypt extension)
go run .                   # run the example
```

The example uses a fixed 32-byte AES-256 key for repeatable local runs. In an
application, load a 64-character hex key from configuration or generate one
with `openssl rand -hex 32`.

## What to expect

```
created: id=1 name=Alice email=alice@example.com ssn=000-00-0000
queried: id=1 name=Alice email=alice@example.com ssn=000-00-0000
all: id=1 name=Alice email=alice@example.com ssn=000-00-0000
plaintext email predicate matched encrypted row: false
raw (encrypted): email="v1:AES-256-GCM:..." ssn="v1:AES-256-GCM:..."
```

The plaintext predicate result is expected. Encrypted fields are decrypted after
reads, but normal ent predicates compare against the randomized ciphertext in
the database.

Same runtime behaviour as the `simple` example. The only difference is how the
encrypted field registry gets populated (manual vs automatic).

## Keeping the registry in sync

When you add, remove, or rename encrypted fields in your schema, update
`ent/entcrypt_gen.go` accordingly:

```go
func init() {
    entcrypt.Register("User", "email", "ssn", "newEncryptedField")
}
```

If `Register` is called more than once for the same entity, entcrypt merges the
field lists and ignores duplicate field names.
