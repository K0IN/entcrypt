package entcrypt

import "sync"

var (
	mu       sync.RWMutex
	entities []Entity
)

type Entity struct {
	Type   string
	Fields []string
}

func Register(entity string, fields ...string) {
	mu.Lock()
	defer mu.Unlock()

	for i, e := range entities {
		if e.Type == entity {
			entities[i].Fields = appendUnique(e.Fields, fields...)
			return
		}
	}
	entities = append(entities, Entity{Type: entity, Fields: cloneFields(fields)})
}

func EncryptedFields(entity string) []string {
	mu.RLock()
	defer mu.RUnlock()
	for _, e := range entities {
		if e.Type == entity {
			return cloneFields(e.Fields)
		}
	}
	return nil
}

func All() []Entity {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Entity, len(entities))
	for i, e := range entities {
		out[i] = Entity{Type: e.Type, Fields: cloneFields(e.Fields)}
	}
	return out
}

func appendUnique(existing []string, fields ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(fields))
	for _, f := range existing {
		seen[f] = struct{}{}
	}
	for _, f := range fields {
		if _, ok := seen[f]; ok {
			continue
		}
		existing = append(existing, f)
		seen[f] = struct{}{}
	}
	return existing
}

func cloneFields(fields []string) []string {
	out := make([]string, len(fields))
	copy(out, fields)
	return out
}
