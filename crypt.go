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
	key []byte
}

func New(prov KeyProvider) (*Encrypter, error) {
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
	return &Encrypter{key: cloneBytes(key)}, nil
}

func cloneBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
