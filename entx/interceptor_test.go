package entx

import (
	"context"
	"fmt"
	"testing"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

// UserQuery simulates a generated ent query type.
type UserQuery struct{}

type testDecrypter struct{}

func (testDecrypter) Decrypt(s string) (string, error) { return s[4:], nil }

func TestDecryptInterceptor(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email", "ssn")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return &struct{ Email, Ssn string }{Email: "enc:test@example.com", Ssn: "enc:000-00-0000"}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	u := v.(*struct{ Email, Ssn string })
	if u.Email != "test@example.com" {
		t.Fatalf("got %q, want %q", u.Email, "test@example.com")
	}
	if u.Ssn != "000-00-0000" {
		t.Fatalf("got %q, want %q", u.Ssn, "000-00-0000")
	}
}

func TestDecryptInterceptor_NilResult(t *testing.T) {
	entcrypt.Reset()
	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return nil, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatal("expected nil")
	}
}

func TestDecryptInterceptor_NoEncryptedFields(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("Other", "some_field")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return &struct{ Name string }{Name: "Bob"}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if v.(*struct{ Name string }).Name != "Bob" {
		t.Fatal("value should pass through unchanged")
	}
}

func TestQueryType(t *testing.T) {
	entcrypt.Reset()
	got := queryType(&UserQuery{})
	if got != "User" {
		t.Fatalf("got %q, want %q", got, "User")
	}
}

func TestDecryptInterceptor_QueryError(t *testing.T) {
	entcrypt.Reset()
	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return nil, fmt.Errorf("query failed")
	})

	_, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptInterceptor_SliceOfPointers(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return []*struct{ Email string }{
			{Email: "enc:alice@example.com"},
			{Email: "enc:bob@example.com"},
		}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	users := v.([]*struct{ Email string })
	if users[0].Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", users[0].Email, "alice@example.com")
	}
	if users[1].Email != "bob@example.com" {
		t.Fatalf("got %q, want %q", users[1].Email, "bob@example.com")
	}
}

func TestDecryptInterceptor_SliceOfStructs(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return []struct{ Email string }{
			{Email: "enc:alice@example.com"},
			{Email: "enc:bob@example.com"},
		}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	users := v.([]struct{ Email string })
	if users[0].Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", users[0].Email, "alice@example.com")
	}
}

func TestDecryptInterceptor_PointerToStruct(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return &struct{ Email string }{Email: "enc:alice@example.com"}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	u := v.(*struct{ Email string })
	if u.Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", u.Email, "alice@example.com")
	}
}

func TestDecryptInterceptor_StructValue(t *testing.T) {
	// Note: struct values (not pointers) cannot be modified by the interceptor
	// because reflection cannot set fields of non-addressable values.
	// This test verifies that struct values pass through unchanged.
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return struct{ Email string }{Email: "enc:alice@example.com"}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	u := v.(struct{ Email string })
	// Struct values cannot be modified, so the field remains encrypted
	if u.Email != "enc:alice@example.com" {
		t.Fatalf("got %q, want %q (struct values pass through unchanged)", u.Email, "enc:alice@example.com")
	}
}

func TestDecryptInterceptor_DecryptError(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(failingDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return &struct{ Email string }{Email: "enc:alice@example.com"}, nil
	})

	_, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptInterceptor_EmptyFields(t *testing.T) {
	entcrypt.Reset()
	entcrypt.Register("User", "email")

	interceptor := DecryptInterceptor(testDecrypter{})
	next := ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		return &struct{ Email string }{Email: ""}, nil
	})

	v, err := interceptor.Intercept(next).Query(context.Background(), &UserQuery{})
	if err != nil {
		t.Fatal(err)
	}

	u := v.(*struct{ Email string })
	if u.Email != "" {
		t.Fatalf("got %q, want empty", u.Email)
	}
}

func TestQueryType_Value(t *testing.T) {
	entcrypt.Reset()
	// Test with non-pointer query type
	type PostQuery struct{}
	got := queryType(PostQuery{})
	if got != "Post" {
		t.Fatalf("got %q, want %q", got, "Post")
	}
}

func TestQueryType_PostQuery(t *testing.T) {
	entcrypt.Reset()
	type PostQuery struct{}
	got := queryType(&PostQuery{})
	if got != "Post" {
		t.Fatalf("got %q, want %q", got, "Post")
	}
}
