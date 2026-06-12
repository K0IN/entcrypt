package entcrypt

import (
	"testing"
)

func resetRegistryForTest() {
	mu.Lock()
	entities = nil
	mu.Unlock()
}

func TestRegisterAndLookup(t *testing.T) {
	resetRegistryForTest()

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
	resetRegistryForTest()

	fields := EncryptedFields("Unknown")
	if fields != nil {
		t.Fatalf("got %v, want nil", fields)
	}
}

func TestAll(t *testing.T) {
	resetRegistryForTest()

	Register("User", "email")
	Register("Post", "body")

	all := All()
	if len(all) != 2 {
		t.Fatalf("got %d entities, want 2", len(all))
	}
}

func TestRegister_MultipleCalls(t *testing.T) {
	resetRegistryForTest()

	Register("User", "email")
	Register("User", "ssn")

	fields := EncryptedFields("User")
	if len(fields) != 2 || fields[0] != "email" || fields[1] != "ssn" {
		t.Fatalf("got %v, want [email ssn]", fields)
	}

	all := All()
	if len(all) != 1 {
		t.Fatalf("got %d entities, want 1", len(all))
	}
}

func TestRegister_DeduplicatesFields(t *testing.T) {
	resetRegistryForTest()

	Register("User", "email", "ssn")
	Register("User", "email", "phone")

	fields := EncryptedFields("User")
	if len(fields) != 3 || fields[0] != "email" || fields[1] != "ssn" || fields[2] != "phone" {
		t.Fatalf("got %v, want [email ssn phone]", fields)
	}
}

func TestEncryptedFields_ReturnsCopy(t *testing.T) {
	resetRegistryForTest()

	Register("User", "email")

	fields := EncryptedFields("User")
	fields[0] = "mutated"

	fields = EncryptedFields("User")
	if len(fields) != 1 || fields[0] != "email" {
		t.Fatalf("got %v, want [email]", fields)
	}
}

func TestRegister_CopiesInputFields(t *testing.T) {
	resetRegistryForTest()

	fields := []string{"email", "ssn"}
	Register("User", fields...)
	fields[0] = "mutated"

	got := EncryptedFields("User")
	if len(got) != 2 || got[0] != "email" || got[1] != "ssn" {
		t.Fatalf("got %v, want [email ssn]", got)
	}
}

func TestAll_ReturnsCopy(t *testing.T) {
	resetRegistryForTest()

	Register("User", "email")

	all := All()
	all[0].Fields[0] = "mutated"

	fields := EncryptedFields("User")
	if len(fields) != 1 || fields[0] != "email" {
		t.Fatalf("got %v, want [email]", fields)
	}
}

func TestConcurrentAccess(t *testing.T) {
	resetRegistryForTest()

	t.Run("parallel", func(t *testing.T) {
		t.Parallel()
		Register("Concurrent", "field")
		_ = EncryptedFields("Concurrent")
	})
}
