// Command op-client-secret provisions client secrets for static clients.
//
// With no arguments it mints a new high-entropy client_secret and prints
// the plaintext to hand to the client together with the stored hash to
// seed the OP with (op.ConfidentialClient.SecretHash, for use with
// op.WithHighEntropyClientSecrets):
//
//	go run github.com/libraz/go-oidc-provider/cmd/op-client-secret
//
// With -argon2id it reads one plaintext line from standard input and
// prints its Argon2id hash, the form op.ConfidentialClient.SecretHash
// (or PreviousSecretHash) stores:
//
//	printf '%s\n' "$SECRET" | go run github.com/libraz/go-oidc-provider/cmd/op-client-secret -argon2id
//
// The plaintext printed by the default mode is the only copy.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/libraz/go-oidc-provider/op"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "op-client-secret:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("op-client-secret", flag.ContinueOnError)
	fs.SetOutput(stderr)
	argon2id := fs.Bool("argon2id", false, "hash the plaintext read from stdin with Argon2id instead of minting a new secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	if *argon2id {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read stdin: %w", err)
		}
		plaintext := strings.TrimRight(line, "\r\n")
		if plaintext == "" {
			return errors.New("empty secret on stdin")
		}
		hash, err := op.HashClientSecret(plaintext)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "hash: %s\n", hash)
		return err
	}

	secret, hash, err := op.NewClientSecret()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "secret: %s\nhash: %s\n", secret, hash)
	return err
}
