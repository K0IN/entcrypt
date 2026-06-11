package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	"github.com/k0in/entcrypt"
)

func main() {
	opts := []entc.Option{
		entc.Extensions(entcrypt.Extension{}),
	}
	err := entc.Generate("./ent/schema", &gen.Config{}, opts...)
	if err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}
}
