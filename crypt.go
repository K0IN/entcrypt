package entcrypt

import (
	"encoding/hex"
	"fmt"
	"os"
)

type KeyProvider interface {
	EncryptionKey() ([]byte, error)
}

type StaticKeyProvider struct {
	Key []byte
}

func (s *StaticKeyProvider) EncryptionKey() ([]byte, error) {
	if len(s.Key) != 32 {
		return nil, fmt.Errorf("entcrypt: key size %d is invalid; need 32 bytes", len(s.Key))
	}
	return s.Key, nil
}

type EnvKeyProvider struct {
	EnvVar string
}

func (e *EnvKeyProvider) EncryptionKey() ([]byte, error) {
	v := e.EnvVar
	if v == "" {
		v = "ENTCRYPT_KEY"
	}
	s, ok := os.LookupEnv(v)
	if !ok || s == "" {
		return nil, fmt.Errorf("entcrypt: environment variable %s is not set", v)
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("entcrypt: %s is not valid hex: %w", v, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("entcrypt: %s decodes to %d bytes; need 32", v, len(key))
	}
	return key, nil
}

type Encrypter struct {
	key                    []byte
	allowPlaintextFallback bool
}

type Option func(*Encrypter)

func WithPlaintextFallback() Option {
	return func(e *Encrypter) {
		e.allowPlaintextFallback = true
	}
}

func New(prov KeyProvider, opts ...Option) (*Encrypter, error) {
	if prov == nil {
		return nil, fmt.Errorf("entcrypt: key provider is nil")
	}
	key, err := prov.EncryptionKey()
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("entcrypt: key size %d is invalid; need 32 bytes", len(key))
	}
	enc := &Encrypter{key: cloneBytes(key)}
	for _, opt := range opts {
		if opt != nil {
			opt(enc)
		}
	}
	return enc, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// ReEncrypt decrypts ciphertext with old and re-encrypts it with new.
// The plaintext exists only transiently in local variables and is never
// exposed to the caller, making this safe for key-rotation migration scripts.
//
// This is particularly useful with WithPlaintextFallback on the old
// Encrypter: legacy plaintext values (without the v1:AES-256-GCM: header)
// pass through old.Decrypt and become properly encrypted by new.Encrypt.
func ReEncrypt(old, new *Encrypter, ciphertext string) (string, error) {
	pt, err := old.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("entcrypt: re-encrypt (decrypt): %w", err)
	}
	ct, err := new.Encrypt(pt)
	if err != nil {
		return "", fmt.Errorf("entcrypt: re-encrypt (encrypt): %w", err)
	}
	return ct, nil
}
