# examples/reencrypt — Key rotation and legacy data migration

This example demonstrates `entcrypt.ReEncrypt`, a safe helper for re-encrypting
data under a new key without exposing plaintext to the caller.

## Scenarios covered

### 1. Planned key rotation
Data encrypted with an old key is re-encrypted under a new key. The plaintext
exists only transiently inside `ReEncrypt` — the caller never sees it. After
migration, the old key can no longer decrypt the new ciphertext (AES-GCM
authentication fails).

### 2. Legacy plaintext migration
Existing unencrypted column values (no `v1:AES-256-GCM:` header) are migrated
to properly encrypted storage using `WithPlaintextFallback()` on the old
Encrypter.

## Why not just encrypt/decrypt directly?

If you called `oldEnc.Decrypt(ct)` then `newEnc.Encrypt(pt)` yourself, the
plaintext would be visible in your application's variables, could be logged,
leak into GC traces, etc. `ReEncrypt` keeps the plaintext contained, reducing
the chance of accidental exposure during migration scripts.

## Run it

```bash
go run .
```

## What to expect

```
old ciphertext: v1:AES-256-GCM:qK4RmjH...#...
re-encrypted:   v1:AES-256-GCM:8LpX2yT...#...
✓ old key rejected (expected)
✓ new key decrypts: "ssn-000-00-0000"
migrated legacy: v1:AES-256-GCM:...
✓ migrated value has entcrypt header
✓ new key decrypts migrated value: "plaintext-email@example.com"

✓ All re-encryption scenarios passed!
```
