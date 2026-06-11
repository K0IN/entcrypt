package entcrypt

import (
	"crypto/rand"
	"testing"
)

func TestNew(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encrypter")
	}
}

func TestNew_InvalidKeySize(t *testing.T) {
	_, err := New(&StaticKeyProvider{Key: []byte("too-short")})
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
	}{
		{"short", "hello"},
		{"medium", "alice@example.com"},
		{"ssn", "000-00-0000"},
		{"unicode", "héllo ωorld"},
		{"long", string(make([]byte, 1000))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if ciphertext == tt.input {
				t.Fatal("ciphertext should differ from plaintext")
			}
			if len(ciphertext) < len(headerV1) || ciphertext[:len(headerV1)] != headerV1 {
				t.Fatalf("ciphertext missing version header: got %q, want prefix %q", ciphertext, headerV1)
			}

			plaintext, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if plaintext != tt.input {
				t.Fatalf("got %q, want %q", plaintext, tt.input)
			}
		})
	}
}

func TestDecrypt_PlaintextFallback(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	// Values without the encryption header should be returned as-is.
	tests := []struct {
		name string
		in   string
	}{
		{"no-header", "no-header-here"},
		{"random-text", "not-valid-base64!!!"},
		{"short", "too-short"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enc.Decrypt(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.in {
				t.Fatalf("got %q, want %q", got, tt.in)
			}
		})
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	enc1, _ := New(&StaticKeyProvider{Key: key1})
	enc2, _ := New(&StaticKeyProvider{Key: key2})

	ct, err := enc1.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc2.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestStaticKeyProvider_Validation(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		ok   bool
	}{
		{"aes-128", make([]byte, 16), true},
		{"aes-192", make([]byte, 24), true},
		{"aes-256", make([]byte, 32), true},
		{"too-small", []byte{1, 2, 3}, false},
		{"too-large", make([]byte, 33), false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&StaticKeyProvider{Key: tt.key})
			if (err == nil) != tt.ok {
				t.Fatalf("got err=%v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestEnvKeyProvider(t *testing.T) {
	t.Setenv("TEST_ENTCRYPT_KEY", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	enc, err := New(&EnvKeyProvider{EnvVar: "TEST_ENTCRYPT_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Encrypt("test")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "test" {
		t.Fatalf("got %q, want %q", pt, "test")
	}
}

func TestEnvKeyProvider_Missing(t *testing.T) {
	t.Setenv("TEST_MISSING_KEY", "")
	_, err := New(&EnvKeyProvider{EnvVar: "TEST_MISSING_KEY"})
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestEnvKeyProvider_InvalidHex(t *testing.T) {
	t.Setenv("TEST_BAD_HEX_KEY", "not-hex!!!")
	_, err := New(&EnvKeyProvider{EnvVar: "TEST_BAD_HEX_KEY"})
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestEnvKeyProvider_WrongKeySize(t *testing.T) {
	// 10 bytes after hex decode - not 16, 24, or 32
	t.Setenv("TEST_BAD_SIZE_KEY", "010203040506070809")
	_, err := New(&EnvKeyProvider{EnvVar: "TEST_BAD_SIZE_KEY"})
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestEnvKeyProvider_DefaultEnvVar(t *testing.T) {
	t.Setenv("ENTCRYPT_KEY", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	enc, err := New(&EnvKeyProvider{})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Encrypt("default")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "default" {
		t.Fatalf("got %q, want %q", pt, "default")
	}
}

func TestEnvKeyProvider_NotSet(t *testing.T) {
	// Use an env var that definitely doesn't exist
	_, err := New(&EnvKeyProvider{EnvVar: "ENTCRYPT_NONEXISTENT_VAR_12345"})
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}

func TestAES192(t *testing.T) {
	key := make([]byte, 24)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "hello" {
		t.Fatalf("got %q, want %q", pt, "hello")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.Decrypt(headerV1 + "!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecrypt_TooShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	// Valid header but ciphertext too short (less than nonce size)
	_, err = enc.Decrypt(headerV1 + "AA")
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Encrypt("")
	if err != nil {
		t.Fatal(err)
	}

	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "" {
		t.Fatalf("got %q, want empty string", pt)
	}
}

func TestEncryptDecrypt_DeterministicHeader(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	ct1, err := enc.Encrypt("same")
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := enc.Encrypt("same")
	if err != nil {
		t.Fatal(err)
	}

	// Same plaintext should produce different ciphertext (different nonces)
	if ct1 == ct2 {
		t.Fatal("expected different ciphertexts for same plaintext")
	}

	// Both should decrypt to the same value
	pt1, err := enc.Decrypt(ct1)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := enc.Decrypt(ct2)
	if err != nil {
		t.Fatal(err)
	}
	if pt1 != pt2 {
		t.Fatalf("decrypted values differ: %q vs %q", pt1, pt2)
	}
}

func TestDecrypt_CorruptedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid ciphertext then corrupt the data
	ct, err := enc.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the last byte of the base64 data
	ct = ct[:len(ct)-1] + "X"

	_, err = enc.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}