package entcrypt

import (
	"testing"

	"entgo.io/ent/schema"
)

func TestEncryptedField_Name(t *testing.T) {
	if got := (EncryptedField{}).Name(); got != "EncryptedField" {
		t.Fatalf("got %q, want %q", got, "EncryptedField")
	}
}

func TestEncryptedField_Merge(t *testing.T) {
	a := EncryptedField{}
	b := EncryptedField{}
	got := a.Merge(b)
	if _, ok := got.(EncryptedField); !ok {
		t.Fatal("merge should return EncryptedField")
	}
}

func TestEncryptedField_ImplementsAnnotation(t *testing.T) {
	var a schema.Annotation = EncryptedField{}
	_ = a
}

func TestEncryptedField_ImplementsMerger(t *testing.T) {
	var m schema.Merger = EncryptedField{}
	_ = m
}
