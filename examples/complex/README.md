# examples/complex

This example is a slightly larger Ent project for exercising `entcrypt` with:

- a standalone example module
- the `entcrypt.Extension{}` codegen path
- two schemas: `User` and `PaymentMethod`
- encrypted fields on both schemas
- an edge from users to payment methods
- runtime proof that app reads are decrypted while raw database reads are encrypted

## Commands I ran

1. Create the project folders.

   ```bash
   mkdir -p examples/complex/ent/schema examples/complex/cmd/entc
   ```

   Why: Ent projects keep schemas under `ent/schema`, and this example uses a
   custom `cmd/entc` binary so the `entcrypt.Extension{}` runs during codegen.

2. Initialize a separate example module.

   ```bash
   cd examples/complex
   go mod init github.com/k0in/entcrypt/examples/complex
   ```

   Why: the other examples are separate modules, so this keeps the complex
   example consistent and runnable on its own.

3. Point the example at the local checkout.

   ```bash
   go mod edit -replace github.com/k0in/entcrypt=../..
   ```

   Why: this makes the example use the local `entcrypt` source instead of a
   released version.

4. Normalize the Go version and add the dependencies needed before codegen.

   ```bash
   go mod edit -go=1.26
   go get entgo.io/ent@v0.14.6 github.com/mattn/go-sqlite3@v1.14.28 github.com/k0in/entcrypt@v0.0.0-00010101000000-000000000000
   ```

   Why: `go mod init` recorded the patch version from the local toolchain, while
   the repo examples use `go 1.26`. The explicit `go get` makes the custom
   codegen command runnable before generated Ent packages exist.

5. Add source files.

   Files edited:

   - `tools.go` pins `entgo.io/ent/cmd/entc` for `go mod tidy`.
   - `ent/generate.go` adds `//go:generate go run ../cmd/entc`.
   - `cmd/entc/main.go` runs Ent codegen with `entcrypt.Extension{}`.
   - `ent/schema/user.go` defines `User` with encrypted `email` and `phone`.
   - `ent/schema/paymentmethod.go` defines `PaymentMethod` with encrypted
     `cardholder_name` and `billing_zip`, plus an owner edge.
   - `main.go` opens sqlite, installs the encrypt hook/decrypt interceptor,
     creates related records, queries them back, and checks raw ciphertext.

6. Generate Ent code.

   ```bash
   go generate ./ent
   ```

   Why: this creates the Ent client and `ent/entcrypt_gen.go`. The generated
   registry should include both encrypted entities:

   ```go
   entcrypt.Register("PaymentMethod", "billing_zip", "cardholder_name")
   entcrypt.Register("User", "email", "phone")
   ```

7. Resolve module dependencies.

   ```bash
   go mod tidy
   ```

   Why: now that generated Ent packages exist, `go mod tidy` can resolve the
   example's generated imports and clean up `go.mod` and `go.sum`.

8. Format the hand-written Go files.

   ```bash
   gofmt -w main.go tools.go cmd/entc/main.go ent/generate.go ent/schema/user.go ent/schema/paymentmethod.go
   ```

   Why: keep the example in normal Go style.

9. Run the example.

   ```bash
   go run .
   ```

   Why: this proves the example works end to end.

## Run it yourself

```bash
cd examples/complex
go generate ./ent
go run .
```

Expected output includes plaintext application reads, failed plaintext
predicates for encrypted fields, raw `v1:AES-256-GCM:` database values, and:

```text
complex example passed
```
