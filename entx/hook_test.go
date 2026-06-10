package entx

import (
	"context"
	"testing"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

type testEncrypter struct{}

func (testEncrypter) Encrypt(s string) (string, error) { return "enc:" + s, nil }
func (testEncrypter) Decrypt(s string) (string, error) { return s[4:], nil }

type testMutation struct {
	typ    string
	fields map[string]interface{}
}

func (m *testMutation) Type() string              { return m.typ }
func (m *testMutation) Op() ent.Op                 { return ent.OpCreate }
func (m *testMutation) Field(name string) (ent.Value, bool) {
	v, ok := m.fields[name]
	return v, ok
}
func (m *testMutation) SetField(name string, v ent.Value) error {
	m.fields[name] = v
	return nil
}
func (m *testMutation) Fields() []string {
	var names []string
	for k := range m.fields {
		names = append(names, k)
	}
	return names
}

func (m *testMutation) AddedFields() []string           { return nil }
func (m *testMutation) AddedField(string) (ent.Value, bool) { return nil, false }
func (m *testMutation) AddField(string, ent.Value) error    { return nil }
func (m *testMutation) ClearedFields() []string             { return nil }
func (m *testMutation) FieldCleared(string) bool            { return false }
func (m *testMutation) ClearField(string) error             { return nil }
func (m *testMutation) ResetField(string) error             { return nil }
func (m *testMutation) AddedEdges() []string                { return nil }
func (m *testMutation) AddedIDs(string) []ent.Value         { return nil }
func (m *testMutation) RemovedEdges() []string              { return nil }
func (m *testMutation) RemovedIDs(string) []ent.Value       { return nil }
func (m *testMutation) ClearedEdges() []string              { return nil }
func (m *testMutation) EdgeCleared(string) bool             { return false }
func (m *testMutation) ClearEdge(string) error              { return nil }
func (m *testMutation) ResetEdge(string) error              { return nil }
func (m *testMutation) OldField(context.Context, string) (ent.Value, error) { return nil, nil }

func TestEncryptHookFunc(t *testing.T) {
	// Register encrypted fields.
	entcrypt.Register("User", "email", "ssn")

	hook := EncryptHookFunc(testEncrypter{})
	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		u := &struct{ Email, Ssn string }{}
		if v, ok := m.Field("email"); ok {
			u.Email = v.(string)
		}
		if v, ok := m.Field("ssn"); ok {
			u.Ssn = v.(string)
		}
		return u, nil
	})

	m := &testMutation{
		typ: "User",
		fields: map[string]interface{}{
			"name":  "Alice",
			"email": "alice@example.com",
			"ssn":   "000-00-0000",
		},
	}

	result, err := hook(next).Mutate(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}

	u := result.(*struct{ Email, Ssn string })
	if u.Email != "alice@example.com" {
		t.Fatalf("email not decrypted: got %q", u.Email)
	}
	if u.Ssn != "000-00-0000" {
		t.Fatalf("ssn not decrypted: got %q", u.Ssn)
	}
}

func TestEncryptHookFunc_NoEncryptedFields(t *testing.T) {
	hook := EncryptHookFunc(testEncrypter{})
	m := &testMutation{typ: "Other", fields: map[string]interface{}{"name": "Bob"}}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Name string }{Name: "Bob"}, nil
	})

	v, err := hook(next).Mutate(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if v.(*struct{ Name string }).Name != "Bob" {
		t.Fatal("value should pass through unchanged")
	}
}