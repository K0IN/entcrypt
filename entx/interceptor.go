package entx

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"entgo.io/ent"
	"github.com/k0in/entcrypt"
)

func DecryptInterceptor(enc interface{ Decrypt(string) (string, error) }) ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			v, err := next.Query(ctx, q)
			if err != nil || v == nil {
				return v, err
			}
			fields := entcrypt.EncryptedFields(queryType(q))
			if len(fields) == 0 {
				return v, nil
			}
			if err := decrypt(v, fields, enc); err != nil {
				return nil, fmt.Errorf("entx: query interceptor: %w", err)
			}
			return v, nil
		})
	})
}

func queryType(q ent.Query) string {
	const ptrKind = reflect.Ptr
	t := reflect.TypeOf(q)
	if t.Kind() == ptrKind {
		t = t.Elem()
	}
	return strings.TrimSuffix(t.Name(), "Query")
}