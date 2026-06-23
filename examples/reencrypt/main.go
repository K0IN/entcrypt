package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/k0in/entcrypt"
)

func main() {
	// ── Scenario 1: Key rotation ──────────────────────────────────────────
	//
	// You have data encrypted with an old key and need to migrate it to a
	// new key without ever exposing the plaintext to application code.

	oldKey := randomHexKey()
	newKey := randomHexKey()

	oldEnc := mustNew(oldKey)
	newEnc := mustNew(newKey)

	// Simulate existing ciphertext in the database.
	original := "ssn-000-00-0000"
	oldCiphertext, err := oldEnc.Encrypt(original)
	if err != nil {
		log.Fatalf("old encrypt: %v", err)
	}
	fmt.Printf("old ciphertext: %s\n", oldCiphertext)

	// Re-encrypt under the new key.  The plaintext never leaves ReEncrypt.
	reEncrypted, err := entcrypt.ReEncrypt(oldEnc, newEnc, oldCiphertext)
	if err != nil {
		log.Fatalf("re-encrypt: %v", err)
	}
	fmt.Printf("re-encrypted:   %s\n", reEncrypted)

	// Old key can no longer decrypt the new ciphertext (authentication fail).
	if _, err := oldEnc.Decrypt(reEncrypted); err == nil {
		log.Fatal("old key should NOT decrypt re-encrypted value")
	}
	fmt.Println("✓ old key rejected (expected)")

	// New key decrypts successfully.
	plaintext, err := newEnc.Decrypt(reEncrypted)
	if err != nil {
		log.Fatalf("new key decrypt: %v", err)
	}
	if plaintext != original {
		log.Fatalf("got %q, want %q", plaintext, original)
	}
	fmt.Printf("✓ new key decrypts: %q\n\n", plaintext)

	// ── Scenario 2: Legacy plaintext migration ────────────────────────────
	//
	// You have an existing column with unencrypted values and want to
	// migrate them to encrypted storage.  Use WithPlaintextFallback on the
	// old (read-only) Encrypter so it passes plaintext through, then write
	// back through a properly-encrypting Encrypter.

	oldFallback := mustNewWithFallback(oldKey)
	newEnc2 := mustNew(newKey)

	// Simulate a legacy plaintext value in the database.
	legacyValue := "plaintext-email@example.com"

	// ReEncrypt passes the plaintext through oldFallback.Decrypt (which
	// returns it unchanged via WithPlaintextFallback) and encrypts it
	// with newEnc2.
	migrated, err := entcrypt.ReEncrypt(oldFallback, newEnc2, legacyValue)
	if err != nil {
		log.Fatalf("migrate legacy: %v", err)
	}
	fmt.Printf("migrated legacy: %s\n", migrated)

	// The migrated value has the entcrypt header now.
	if len(migrated) < len("v1:AES-256-GCM:") || migrated[:15] != "v1:AES-256-GCM:" {
		log.Fatal("migrated value should have the entcrypt header")
	}
	fmt.Println("✓ migrated value has entcrypt header")

	// New key decrypts it.
	pt2, err := newEnc2.Decrypt(migrated)
	if err != nil {
		log.Fatalf("new key decrypt after migration: %v", err)
	}
	if pt2 != legacyValue {
		log.Fatalf("got %q, want %q", pt2, legacyValue)
	}
	fmt.Printf("✓ new key decrypts migrated value: %q\n", pt2)

	fmt.Println("\n✓ All re-encryption scenarios passed!")
}

func randomHexKey() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("rand.Read: %v", err)
	}
	// Return hex-encoded form so it looks like what a user would load from
	// an env var or config file.
	hexKey := make([]byte, 64)
	hex.Encode(hexKey, b)
	return hexKey
}

func mustNew(hexKey []byte) *entcrypt.Encrypter {
	key, err := hex.DecodeString(string(hexKey))
	if err != nil {
		log.Fatalf("hex decode: %v", err)
	}
	enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})
	if err != nil {
		log.Fatalf("entcrypt.New: %v", err)
	}
	return enc
}

func mustNewWithFallback(hexKey []byte) *entcrypt.Encrypter {
	key, err := hex.DecodeString(string(hexKey))
	if err != nil {
		log.Fatalf("hex decode: %v", err)
	}
	enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key}, entcrypt.WithPlaintextFallback())
	if err != nil {
		log.Fatalf("entcrypt.New: %v", err)
	}
	return enc
}
