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
	if len(s.Key) != 16 && len(s.Key) != 24 && len(s.Key) != 32 {
		return nil, fmt.Errorf("entcrypt: key size %d is invalid; need 16, 24, or 32 bytes", len(s.Key))
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
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("entcrypt: %s decodes to %d bytes; need 16, 24, or 32", v, len(key))
	}
	return key, nil
}

type Encrypter struct {
	key []byte
}

func New(prov KeyProvider) (*Encrypter, error) {
	key, err := prov.EncryptionKey()
	if err != nil {
		return nil, err
	}
	return &Encrypter{key: key}, nil
}