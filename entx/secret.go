//go:build goexperiment.runtimesecret

package entx

import "runtime/secret"

// decryptSecret wraps a single decrypt call in runtime/secret so that
// the plaintext only exists on a secret-marked stack frame. This prevents
// the Go runtime from scanning or copying the plaintext during GC.
func decryptSecret(d interface{ Decrypt(string) (string, error) }, ciphertext string) (plaintext string, err error) {
	secret.Do(func() {
		plaintext, err = d.Decrypt(ciphertext)
	})
	return
}
