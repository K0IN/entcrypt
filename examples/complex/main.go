package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"entgo.io/ent/dialect"
	"github.com/k0in/entcrypt"
	"github.com/k0in/entcrypt/entx"
	"github.com/k0in/entcrypt/examples/complex/ent"
	"github.com/k0in/entcrypt/examples/complex/ent/paymentmethod"
	"github.com/k0in/entcrypt/examples/complex/ent/user"
)

func main() {
	ctx := context.Background()
	dbURL := "file:entcrypt_complex?mode=memory&cache=shared&_fk=1"

	key, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		log.Fatalf("decode key: %v", err)
	}
	enc, err := entcrypt.New(&entcrypt.StaticKeyProvider{Key: key})
	if err != nil {
		log.Fatalf("creating encrypter: %v", err)
	}

	client, err := ent.Open(dialect.SQLite, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	client.Use(entx.EncryptHookFunc(enc))
	client.Intercept(entx.DecryptInterceptor(enc))

	if err := client.Schema.Create(ctx); err != nil {
		log.Fatalf("migration: %v", err)
	}

	alice, err := client.User.Create().
		SetName("Alice").
		SetEmail("alice@example.com").
		SetPhone("+1-202-555-0101").
		Save(ctx)
	if err != nil {
		log.Fatal(err)
	}

	card, err := client.PaymentMethod.Create().
		SetOwner(alice).
		SetBrand("Visa").
		SetLastFour("4242").
		SetCardholderName("Alice Example").
		SetBillingZip("94105").
		Save(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("created user: id=%d name=%s email=%s phone=%s\n", alice.ID, alice.Name, alice.Email, alice.Phone)
	fmt.Printf("created payment: id=%d brand=%s last_four=%s cardholder=%s billing_zip=%s\n",
		card.ID, card.Brand, card.LastFour, card.CardholderName, card.BillingZip)

	loaded, err := client.User.Query().
		Where(user.IDEQ(alice.ID)).
		WithPaymentMethods().
		Only(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("loaded user: id=%d email=%s phone=%s payment_count=%d\n",
		loaded.ID, loaded.Email, loaded.Phone, len(loaded.Edges.PaymentMethods))
	for _, pm := range loaded.Edges.PaymentMethods {
		fmt.Printf("loaded payment: id=%d cardholder=%s billing_zip=%s\n", pm.ID, pm.CardholderName, pm.BillingZip)
	}

	plaintextEmailMatch, err := client.User.Query().
		Where(user.EmailEQ("alice@example.com")).
		Exist(ctx)
	if err != nil {
		log.Fatal(err)
	}
	plaintextZipMatch, err := client.PaymentMethod.Query().
		Where(paymentmethod.BillingZipEQ("94105")).
		Exist(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext encrypted-field predicates matched encrypted rows: email=%t billing_zip=%t\n",
		plaintextEmailMatch, plaintextZipMatch)
	if plaintextEmailMatch || plaintextZipMatch {
		log.Fatal("plaintext predicates should not match randomized encrypted values")
	}

	rawClient, err := ent.Open(dialect.SQLite, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer rawClient.Close()

	rawUser, err := rawClient.User.Get(ctx, alice.ID)
	if err != nil {
		log.Fatal(err)
	}
	rawPayment, err := rawClient.PaymentMethod.Get(ctx, card.ID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("raw user: email=%q phone=%q\n", rawUser.Email, rawUser.Phone)
	fmt.Printf("raw payment: cardholder=%q billing_zip=%q\n", rawPayment.CardholderName, rawPayment.BillingZip)

	if !strings.HasPrefix(rawUser.Email, "v1:AES-256-GCM:") ||
		!strings.HasPrefix(rawPayment.BillingZip, "v1:AES-256-GCM:") {
		log.Fatal("expected encrypted database values to use the entcrypt storage header")
	}

	fmt.Println("\ncomplex example passed")
}
