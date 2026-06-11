package entcrypt

import (
	"testing"
)

func TestRegisterAndLookup(t *testing.T) {
	// Reset state for this test.
	Reset()

	Register("User", "email", "ssn")
	Register("Post", "secret_content")

	fields := EncryptedFields("User")
	if len(fields) != 2 || fields[0] != "email" || fields[1] != "ssn" {
		t.Fatalf("got %v, want [email ssn]", fields)
	}

	fields = EncryptedFields("Post")
	if len(fields) != 1 || fields[0] != "secret_content" {
		t.Fatalf("got %v, want [secret_content]", fields)
	}
}

func TestEncryptedFields_Unknown(t *testing.T) {
	Reset()

	fields := EncryptedFields("Unknown")
	if fields != nil {
		t.Fatalf("got %v, want nil", fields)
	}
}

func TestAll(t *testing.T) {
	Reset()

	Register("User", "email")
	Register("Post", "body")

	all := All()
	if len(all) != 2 {
		t.Fatalf("got %d entities, want 2", len(all))
	}
}

func TestRegister_MultipleCalls(t *testing.T) {
	mu.Lock()
	entities = nil
	mu.Unlock()

	Register("User", "email")
	Register("User", "ssn")

	fields := EncryptedFields("User")
	// Each Register call appends a new Entity entry.
	// The lookup returns the first match.
	if len(fields) != 1 || fields[0] != "email" {
		t.Fatalf("got %v, want [email]", fields)
	}
}

func TestConcurrentAccess(t *testing.T) {
	mu.Lock()
	entities = nil
	mu.Unlock()

	t.Run("parallel", func(t *testing.T) {
		t.Parallel()
		Register("Concurrent", "field")
		_ = EncryptedFields("Concurrent")
	})
}