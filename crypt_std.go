//go:build !goexperiment.runtimesecret

package entcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// headerV1 is the plain-text prefix prepended to every encrypted value,
// identifying the format version and algorithm used.
const headerV1 = "v1:AES-256-GCM:"

func (e *Encrypter) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return headerV1 + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func (e *Encrypter) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, headerV1) {
		return "", fmt.Errorf("entcrypt: unknown or missing encryption header")
	}
	body := ciphertext[len(headerV1):]

	data, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("entcrypt: ciphertext too short")
	}
	nonce, raw := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, raw, nil)
	if err != nil {
		return "", fmt.Errorf("entcrypt: %w", err)
	}
	return string(plaintext), nil
}
