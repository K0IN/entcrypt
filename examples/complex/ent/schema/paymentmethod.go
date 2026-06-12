package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/k0in/entcrypt"
)

type PaymentMethod struct{ ent.Schema }

func (PaymentMethod) Fields() []ent.Field {
	return []ent.Field{
		field.String("brand"),
		field.String("last_four"),
		field.String("cardholder_name").
			Annotations(entcrypt.EncryptedField{}),
		field.String("billing_zip").
			Annotations(entcrypt.EncryptedField{}),
	}
}

func (PaymentMethod) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("payment_methods").
			Unique().
			Required(),
	}
}
