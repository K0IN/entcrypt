package entx

import (
	"context"
	"testing"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

// UserQuery simulates a generated ent query type.
type UserQuery struct{}

type testDecrypter struct{}

func (testDecrypter) Decrypt(s string) (string, error) { return s[4:], nil }

func TestDecryptInterceptor(t *testing.T) {
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
	got := queryType(&UserQuery{})
	if got != "User" {
		t.Fatalf("got %q, want %q", got, "User")
	}
}