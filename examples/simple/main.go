package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"

	"entgo.io/ent/dialect"
	"github.com/k0in/entcrypt"
	"github.com/k0in/entcrypt/examples/simple/ent"
	"github.com/k0in/entcrypt/examples/simple/ent/user"
	"github.com/k0in/entcrypt/entx"
)

func main() {
	ctx := context.Background()

	// Create an encrypter from a hex-encoded AES-256 key.
	key, _ := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})
	if err != nil {
		log.Fatal(err)
	}

	// Open the ent client.
	client, err := ent.Open(dialect.SQLite, "file:ent.db?_fk=1")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Install the encryption hook (writes) and decryption interceptor (reads).
	client.Use(entx.EncryptHookFunc(enc))
	client.Intercept(entx.DecryptInterceptor(enc))

	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("migration: %v", err)
	}

	// Create — field values are encrypted in the DB.
	u, err := client.User.Create().
		SetName("Alice").
		SetEmail("alice@example.com").
		SetSsn("000-00-0000").
		Save(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("created: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)

	// Get — values are decrypted automatically.
	u, err = client.User.Get(ctx, u.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("queried: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)

	// Query — all results are decrypted.
	all, err := client.User.Query().All(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, u := range all {
		fmt.Printf("all: id=%d name=%s email=%s ssn=%s\n", u.ID, u.Name, u.Email, u.Ssn)
	}

	// Verify data is actually encrypted in the database by querying without
	// the encryption hook/interceptor.
	rawClient, err := ent.Open(dialect.SQLite, "file:ent.db?_fk=1")
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
}


