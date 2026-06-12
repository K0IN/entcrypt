package entx

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

func EncryptHookFunc(enc interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			fields := entcrypt.EncryptedFields(m.Type())
			if len(fields) == 0 {
				return next.Mutate(ctx, m)
			}

			encrypted := make(map[string]string, len(fields))
			for _, f := range fields {
				v, ok := m.Field(f)
				if !ok {
					continue
				}
				s, ok := v.(string)
				if !ok || s == "" {
					continue
				}
				e, err := enc.Encrypt(s)
				if err != nil {
					return nil, fmt.Errorf("entx: encrypt %s.%s: %w", m.Type(), f, err)
				}
				encrypted[f] = e
			}
			if len(encrypted) == 0 {
				return next.Mutate(ctx, m)
			}
			for f, e := range encrypted {
				if err := m.SetField(f, e); err != nil {
					return nil, fmt.Errorf("entx: set encrypted %s.%s: %w", m.Type(), f, err)
				}
			}

			v, err := next.Mutate(ctx, m)
			if err != nil {
				return v, err
			}
			if err := decrypt(v, fields, enc); err != nil {
				return nil, err
			}
			return v, nil
		})
	}
}

func decrypt(v interface{}, fields []string, d interface{ Decrypt(string) (string, error) }) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr { // nolint:govet
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Slice:
		for i := 0; i < rv.Len(); i++ {
			e := rv.Index(i)
			if e.Kind() == reflect.Ptr { // nolint:govet
				e = e.Elem()
			}
			if err := decryptStruct(e, fields, d); err != nil {
				return err
			}
		}
	case reflect.Struct:
		return decryptStruct(rv, fields, d)
	}
	return nil
}

func decryptStruct(rv reflect.Value, fields []string, d interface{ Decrypt(string) (string, error) }) error {
	if !rv.IsValid() || rv.Kind() != reflect.Struct {
		return nil
	}
	t := rv.Type()
	for _, f := range fields {
		sf, ok := t.FieldByNameFunc(func(name string) bool {
			field, ok2 := t.FieldByName(name)
			if !ok2 {
				return false
			}
			tagName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			return tagName == f || name == snakeToPascal(f)
		})
		if !ok {
			continue
		}
		fv := rv.FieldByIndex(sf.Index)
		if !fv.IsValid() || fv.Kind() != reflect.String || !fv.CanSet() {
			continue
		}
		c := fv.String()
		if c == "" {
			continue
		}
		p, err := decryptSecret(d, c)
		if err != nil {
			return fmt.Errorf("entx: decrypt %s: %w", f, err)
		}
		fv.SetString(p)
	}
	return nil
}

func snakeToPascal(s string) string {
	var b strings.Builder
	up := true
	for _, c := range s {
		if c == '_' {
			up = true
			continue
		}
		if up {
			b.WriteRune(unicode.ToUpper(c))
			up = false
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
