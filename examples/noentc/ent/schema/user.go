package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/k0in/entcrypt"
)

type User struct{ ent.Schema }

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("name"),
		field.String("email").
			Annotations(entcrypt.EncryptedField{}),
		field.String("ssn").
			Annotations(entcrypt.EncryptedField{}),
	}
}

func (User) Edges() []ent.Edge {
	return nil
}