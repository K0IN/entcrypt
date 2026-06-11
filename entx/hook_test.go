package entx

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

type testEncrypter struct{}

func (testEncrypter) Encrypt(s string) (string, error) { return "enc:" + s, nil }
func (testEncrypter) Decrypt(s string) (string, error) { return s[4:], nil }

type failingDecrypter struct{}

func (failingDecrypter) Decrypt(s string) (string, error) {
	return "", fmt.Errorf("decrypt failed")
}

type failingEncrypter struct{}

func (failingEncrypter) Encrypt(s string) (string, error) {
	return "", fmt.Errorf("encrypt failed")
}
func (failingEncrypter) Decrypt(s string) (string, error) {
	return s, nil
}

type testMutation struct {
	typ    string
	fields map[string]interface{}
}

func (m *testMutation) Type() string { return m.typ }
func (m *testMutation) Op() ent.Op   { return ent.OpCreate }
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

func (m *testMutation) AddedFields() []string                               { return nil }
func (m *testMutation) AddedField(string) (ent.Value, bool)                 { return nil, false }
func (m *testMutation) AddField(string, ent.Value) error                    { return nil }
func (m *testMutation) ClearedFields() []string                             { return nil }
func (m *testMutation) FieldCleared(string) bool                            { return false }
func (m *testMutation) ClearField(string) error                             { return nil }
func (m *testMutation) ResetField(string) error                             { return nil }
func (m *testMutation) AddedEdges() []string                                { return nil }
func (m *testMutation) AddedIDs(string) []ent.Value                         { return nil }
func (m *testMutation) RemovedEdges() []string                              { return nil }
func (m *testMutation) RemovedIDs(string) []ent.Value                       { return nil }
func (m *testMutation) ClearedEdges() []string                              { return nil }
func (m *testMutation) EdgeCleared(string) bool                             { return false }
func (m *testMutation) ClearEdge(string) error                              { return nil }
func (m *testMutation) ResetEdge(string) error                              { return nil }
func (m *testMutation) OldField(context.Context, string) (ent.Value, error) { return nil, nil }

type failingSetFieldMutation struct {
	typ    string
	fields map[string]interface{}
}

func (m *failingSetFieldMutation) Type() string { return m.typ }
func (m *failingSetFieldMutation) Op() ent.Op   { return ent.OpCreate }
func (m *failingSetFieldMutation) Field(name string) (ent.Value, bool) {
	v, ok := m.fields[name]
	return v, ok
}
func (m *failingSetFieldMutation) SetField(name string, v ent.Value) error {
	return fmt.Errorf("setfield not allowed")
}
func (m *failingSetFieldMutation) Fields() []string {
	var names []string
	for k := range m.fields {
		names = append(names, k)
	}
	return names
}
func (m *failingSetFieldMutation) AddedFields() []string               { return nil }
func (m *failingSetFieldMutation) AddedField(string) (ent.Value, bool) { return nil, false }
func (m *failingSetFieldMutation) AddField(string, ent.Value) error    { return nil }
func (m *failingSetFieldMutation) ClearedFields() []string             { return nil }
func (m *failingSetFieldMutation) FieldCleared(string) bool            { return false }
func (m *failingSetFieldMutation) ClearField(string) error             { return nil }
func (m *failingSetFieldMutation) ResetField(string) error             { return nil }
func (m *failingSetFieldMutation) AddedEdges() []string                { return nil }
func (m *failingSetFieldMutation) AddedIDs(string) []ent.Value         { return nil }
func (m *failingSetFieldMutation) RemovedEdges() []string              { return nil }
func (m *failingSetFieldMutation) RemovedIDs(string) []ent.Value       { return nil }
func (m *failingSetFieldMutation) ClearedEdges() []string              { return nil }
func (m *failingSetFieldMutation) EdgeCleared(string) bool             { return false }
func (m *failingSetFieldMutation) ClearEdge(string) error              { return nil }
func (m *failingSetFieldMutation) ResetEdge(string) error              { return nil }
func (m *failingSetFieldMutation) OldField(context.Context, string) (ent.Value, error) {
	return nil, nil
}

func TestEncryptHookFunc(t *testing.T) {
	// Register encrypted fields.
	entcrypt.Register("UserEncryptHook", "email", "ssn")

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
		typ: "UserEncryptHook",
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
	m := &testMutation{typ: "NoEncryptedHook", fields: map[string]interface{}{"name": "Bob"}}

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
func TestDecrypt_SliceOfPointers(t *testing.T) {
	type User struct {
		Email string
		Ssn   string
	}

	users := []*User{
		{Email: "enc:alice@example.com", Ssn: "enc:000-00-0000"},
		{Email: "enc:bob@example.com", Ssn: "enc:111-11-1111"},
	}

	err := decrypt(&users, []string{"email", "ssn"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if users[0].Email != "alice@example.com" {
		t.Fatalf("got %q", users[0].Email)
	}
	if users[1].Ssn != "111-11-1111" {
		t.Fatalf("got %q", users[1].Ssn)
	}
}

func TestDecrypt_SliceOfValues(t *testing.T) {
	type User struct {
		Email string
	}

	users := []User{
		{Email: "enc:alice@example.com"},
	}

	err := decrypt(users, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if users[0].Email != "alice@example.com" {
		t.Fatalf("got %q", users[0].Email)
	}
}

func TestDecrypt_PointerToStruct(t *testing.T) {
	type User struct {
		Email string
	}

	u := &User{Email: "enc:alice@example.com"}
	err := decrypt(u, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if u.Email != "alice@example.com" {
		t.Fatalf("got %q", u.Email)
	}
}

func TestDecrypt_StructValue(t *testing.T) {
	type User struct {
		Email string
	}

	u := User{Email: "enc:alice@example.com"}
	err := decrypt(u, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecrypt_EmptyFields(t *testing.T) {
	type User struct {
		Email string
	}

	u := &User{Email: "enc:alice@example.com"}
	err := decrypt(u, []string{}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptStruct_MissingField(t *testing.T) {
	type User struct {
		Name string
	}

	u := &User{Name: "Alice"}
	err := decryptStruct(reflect.ValueOf(u).Elem(), []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptStruct_NonStringField(t *testing.T) {
	type User struct {
		Email int
	}

	u := &User{Email: 123}
	err := decryptStruct(reflect.ValueOf(u).Elem(), []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptStruct_InvalidValue(t *testing.T) {
	var v reflect.Value
	err := decryptStruct(v, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptStruct_JsonTag(t *testing.T) {
	type User struct {
		EmailAddress string `json:"email"`
	}

	u := &User{EmailAddress: "enc:alice@example.com"}
	err := decrypt(u, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if u.EmailAddress != "alice@example.com" {
		t.Fatalf("got %q", u.EmailAddress)
	}
}

func TestDecryptStruct_JsonTagOmitEmpty(t *testing.T) {
	type User struct {
		EmailAddress string `json:"email,omitempty"`
	}

	u := &User{EmailAddress: "enc:alice@example.com"}
	err := decrypt(u, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if u.EmailAddress != "alice@example.com" {
		t.Fatalf("got %q", u.EmailAddress)
	}
}

func TestDecryptStruct_SnakeCaseField(t *testing.T) {
	type User struct {
		HomeAddress string
	}

	u := &User{HomeAddress: "enc:123 Main St"}
	err := decrypt(u, []string{"home_address"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}

	if u.HomeAddress != "123 Main St" {
		t.Fatalf("got %q", u.HomeAddress)
	}
}

func TestDecryptStruct_DecryptError(t *testing.T) {
	type User struct {
		Email string
	}

	u := &User{Email: "enc:bad"}
	err := decrypt(u, []string{"email"}, failingDecrypter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecrypt_NilPointer(t *testing.T) {
	var u *struct{ Email string }
	err := decrypt(u, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecrypt_EmptySlice(t *testing.T) {
	users := []struct{ Email string }{}
	err := decrypt(&users, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSnakeToPascal(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"email", "Email"},
		{"home_address", "HomeAddress"},
		{"ssn", "Ssn"},
		{"user_id", "UserId"},
		{"_leading", "Leading"},
		{"trailing_", "Trailing"},
		{"a_b_c", "ABC"},
		{"single", "Single"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := snakeToPascal(tt.input)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncryptHookFunc_EncryptError(t *testing.T) {
	entcrypt.Register("UserEncryptError", "email")

	hook := EncryptHookFunc(failingEncrypter{})
	m := &testMutation{
		typ:    "UserEncryptError",
		fields: map[string]interface{}{"email": "alice@example.com"},
	}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Email string }{}, nil
	})

	_, err := hook(next).Mutate(context.Background(), m)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEncryptHookFunc_NonStringField(t *testing.T) {
	entcrypt.Register("UserNonString", "age")

	hook := EncryptHookFunc(testEncrypter{})
	m := &testMutation{
		typ:    "UserNonString",
		fields: map[string]interface{}{"age": 25},
	}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Age int }{Age: 25}, nil
	})

	result, err := hook(next).Mutate(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if result.(*struct{ Age int }).Age != 25 {
		t.Fatal("value should pass through unchanged")
	}
}

func TestEncryptHookFunc_EmptyStringField(t *testing.T) {
	entcrypt.Register("UserEmptyString", "email")

	hook := EncryptHookFunc(testEncrypter{})
	m := &testMutation{
		typ:    "UserEmptyString",
		fields: map[string]interface{}{"email": ""},
	}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Email string }{}, nil
	})

	result, err := hook(next).Mutate(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if result.(*struct{ Email string }).Email != "" {
		t.Fatal("empty string should pass through unchanged")
	}
}

func TestEncryptHookFunc_SetFieldError(t *testing.T) {
	entcrypt.Register("UserSetField", "email")

	hook := EncryptHookFunc(testEncrypter{})
	m := &failingSetFieldMutation{
		typ:    "UserSetField",
		fields: map[string]interface{}{"email": "alice@example.com"},
	}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Email string }{}, nil
	})

	_, err := hook(next).Mutate(context.Background(), m)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEncryptHookFunc_FieldNotPresent(t *testing.T) {
	// Test when m.Field(f) returns false (field not present in mutation)
	entcrypt.Register("UserFieldNotPresent", "email")

	hook := EncryptHookFunc(testEncrypter{})
	// Mutation has no "email" field - Field() will return (!ok)
	m := &testMutation{
		typ:    "UserFieldNotPresent",
		fields: map[string]interface{}{"name": "Alice"},
	}

	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return &struct{ Name string }{Name: "Alice"}, nil
	})

	result, err := hook(next).Mutate(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if result.(*struct{ Name string }).Name != "Alice" {
		t.Fatal("value should pass through unchanged")
	}
}

func TestDecrypt_StructValue_Pointer(t *testing.T) {
	// Test decrypt with a pointer to struct (not slice)
	type User struct {
		Email string
	}
	user := User{Email: "enc:alice@example.com"}
	err := decrypt(&user, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", user.Email, "alice@example.com")
	}
}

func TestEncryptHookFunc_NextMutateError(t *testing.T) {
	entcrypt.Register("UserNextMutateError", "email")

	hook := EncryptHookFunc(testEncrypter{})
	m := &testMutation{
		typ:    "UserNextMutateError",
		fields: map[string]interface{}{"email": "alice@example.com"},
	}

	// Simulate next.Mutate returning an error
	next := ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		return nil, fmt.Errorf("mutate failed")
	})

	_, err := hook(next).Mutate(context.Background(), m)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecrypt_StructWithUnexportedField(t *testing.T) {
	// Test decrypt with a struct that has unexported fields (can't be set)
	type User struct {
		Email  string
		secret string // unexported field
	}
	user := User{Email: "enc:alice@example.com", secret: "hidden"}
	err := decrypt(&user, []string{"email", "secret"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", user.Email, "alice@example.com")
	}
}

func TestDecrypt_NonStructPointer(t *testing.T) {
	// Test decrypt with a pointer to a non-slice, non-struct type (like *string)
	s := "enc:hello"
	err := decrypt(&s, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
	// The value should be unchanged because it's not a slice or struct
	if s != "enc:hello" {
		t.Fatalf("got %q, want %q", s, "enc:hello")
	}
}

func TestDecrypt_SliceWithNilPointers(t *testing.T) {
	// Test decrypt with a slice of pointers where some are nil
	type User struct {
		Email string
	}
	users := []*User{
		{Email: "enc:alice@example.com"},
		nil,
		{Email: "enc:bob@example.com"},
	}
	err := decrypt(&users, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
	if users[0].Email != "alice@example.com" {
		t.Fatalf("got %q, want %q", users[0].Email, "alice@example.com")
	}
	if users[1] != nil {
		t.Fatal("expected nil pointer")
	}
	if users[2].Email != "bob@example.com" {
		t.Fatalf("got %q, want %q", users[2].Email, "bob@example.com")
	}
}

func TestDecryptStruct_NonStruct(t *testing.T) {
	// Test decryptStruct with a non-struct value
	s := "not a struct"
	rv := reflect.ValueOf(s)
	err := decryptStruct(rv, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecrypt_SliceDecryptError(t *testing.T) {
	// Test decrypt with a slice where decryptStruct returns an error
	// This covers the "return err" path in the slice loop
	type User struct {
		Email string
	}
	users := []*User{
		{Email: "enc:alice@example.com"},
		{Email: "enc:bob@example.com"},
	}
	// Use the existing failingDecrypter which always fails
	err := decrypt(&users, []string{"email"}, failingDecrypter{})
	if err == nil {
		t.Fatal("expected error from decrypt")
	}
}

func TestDecryptStruct_EmptyField(t *testing.T) {
	// Test decryptStruct with a struct that has an empty string field
	// This covers the "if c == \"\" { continue }" path
	type User struct {
		Email string
	}
	user := User{Email: ""}
	rv := reflect.ValueOf(user)
	err := decryptStruct(rv, []string{"email"}, testDecrypter{})
	if err != nil {
		t.Fatal(err)
	}
	// The empty field should remain empty
	if user.Email != "" {
		t.Fatalf("got %q, want empty", user.Email)
	}
}
