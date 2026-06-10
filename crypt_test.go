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

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	enc, err := New(&StaticKeyProvider{Key: key})
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid ciphertext")
	}

	_, err = enc.Decrypt("too-short")
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
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