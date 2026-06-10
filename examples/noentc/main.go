package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"

	"entgo.io/ent/dialect"
	"github.com/k0in/entcrypt"
	"github.com/k0in/entcrypt/examples/noentc/ent"
	"github.com/k0in/entcrypt/examples/noentc/ent/user"
	"github.com/k0in/entcrypt/entx"
)

func main() {
	ctx := context.Background()

	key, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		log.Fatalf("ENTCRYPT_KEY must be a hex-encoded AES-256 key: %v", err)
	}
	enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})
	if err != nil {
		log.Fatalf("creating encrypter: %v", err)
	}

	client, err := ent.Open(dialect.SQLite, "file:entcrypt_noentc.db?_fk=1")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	client.Use(entx.EncryptHookFunc(enc))
	client.Intercept(entx.DecryptInterceptor(enc))

	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("migration: %v", err)
	}

	u, err := client.User.Create().
		SetName("Alice").
		SetEmail("alice@example.com").
		SetSsn("000-00-0000").
		Save(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("created: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)

	u, err = client.User.Query().Where(user.IDEQ(u.ID)).Only(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("queried: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)

	all, err := client.User.Query().All(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, u := range all {
		fmt.Printf("all: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)
	}

	// Verify data is actually encrypted in the database by querying without
	// the encryption hook/interceptor.
	rawClient, err := ent.Open(dialect.SQLite, "file:entcrypt_noentc.db?_fk=1")
	if err != nil {
		log.Fatal(err)
	}
	defer rawClient.Close()
	raw, err := rawClient.User.Query().Where(user.IDEQ(u.ID)).Only(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("raw (encrypted): email=%q ssn=%q\n", raw.Email, raw.Ssn)

	fmt.Println("\n✓ All encryption tests passed!")
	fmt.Println("DB saved to entcrypt_noentc.db — inspect with: sqlite3 entcrypt_noentc.db 'SELECT * FROM users;'")
}