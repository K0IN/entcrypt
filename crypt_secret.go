//go:build goexperiment.runtimesecret

package entcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"runtime/secret"
	"strings"
)

const headerV1 = "v1:AES-256-GCM:"

func (e *Encrypter) Encrypt(plaintext string) (result string, err error) {
	secret.Do(func() {
		block, cerr := aes.NewCipher(e.key)
		if cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		gcm, cerr := cipher.NewGCM(block)
		if cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, cerr := io.ReadFull(rand.Reader, nonce); cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
		result = headerV1 + base64.RawStdEncoding.EncodeToString(ct)
	})
	return
}

func (e *Encrypter) Decrypt(ciphertext string) (result string, err error) {
	if !strings.HasPrefix(ciphertext, headerV1) {
		// No encryption header — treat as plaintext (migration tolerance).
		result = ciphertext
		return
	}
	secret.Do(func() {
		body := ciphertext[len(headerV1):]

		data, cerr := base64.RawStdEncoding.DecodeString(body)
		if cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		block, cerr := aes.NewCipher(e.key)
		if cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		gcm, cerr := cipher.NewGCM(block)
		if cerr != nil {
			err = fmt.Errorf("entcrypt: %w", cerr)
			return
		}
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			err = fmt.Errorf("entcrypt: ciphertext too short")
			return
		}
		nonce, raw := data[:nonceSize], data[nonceSize:]
		pt, e := gcm.Open(nil, nonce, raw, nil)
		if e != nil {
			err = fmt.Errorf("entcrypt: %w", e)
			return
		}
		result = string(pt)
	})
	return
}
