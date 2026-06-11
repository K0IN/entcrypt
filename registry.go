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
	entities = append(entities, Entity{Type: entity, Fields: fields})
	mu.Unlock()
}

func EncryptedFields(entity string) []string {
	mu.RLock()
	defer mu.RUnlock()
	for _, e := range entities {
		if e.Type == entity {
			return e.Fields
		}
	}
	return nil
}

func All() []Entity {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Entity, len(entities))
	copy(out, entities)
	return out
}
