//go:build !goexperiment.runtimesecret

package entx

// decryptSecret is a no-op fallback when runtime/secret is not available.
// It simply calls the decrypter directly.
func decryptSecret(d interface{ Decrypt(string) (string, error) }, ciphertext string) (plaintext string, err error) {
	return d.Decrypt(ciphertext)
}
