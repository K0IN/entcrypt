package entcrypt

import "entgo.io/ent/schema"

type EncryptedField struct{}

func (EncryptedField) Name() string { return "EncryptedField" }

func (e EncryptedField) Merge(other schema.Annotation) schema.Annotation { return e }

var _ schema.Annotation = EncryptedField{}
var _ schema.Merger = EncryptedField{}
