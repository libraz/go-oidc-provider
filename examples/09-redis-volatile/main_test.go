//go:build example

package main

import (
	"errors"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"

	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
)

func TestRedactedMySQLDSNDoesNotDiscloseCredentials(t *testing.T) {
	t.Parallel()
	const dsn = "sensitive-user:percent%40secret@tcp(mysql.internal:3306)/oidc?parseTime=true&tls=preferred"
	got, err := redactedMySQLDSN(dsn)
	if err != nil {
		t.Fatalf("redactedMySQLDSN: %v", err)
	}
	if want := "tcp(mysql.internal:3306)/oidc"; got != want {
		t.Fatalf("redactedMySQLDSN()=%q, want %q", got, want)
	}
	for _, secret := range []string{"sensitive-user", "percent%40secret", "parseTime", "preferred"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redactedMySQLDSN()=%q disclosed %q", got, secret)
		}
	}
}

func TestRedactedMySQLDSNInvalidInputFailsClosed(t *testing.T) {
	t.Parallel()
	const dsn = "sensitive-user:percent%40secret@tcp(mysql.internal:3306"
	got, err := redactedMySQLDSN(dsn)
	if err == nil {
		t.Fatal("want invalid-DSN error")
	}
	if got != "" {
		t.Fatalf("redactedMySQLDSN()=%q, want empty label", got)
	}
	for _, secret := range []string{dsn, "sensitive-user", "percent%40secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q disclosed %q", err, secret)
		}
	}
}

func TestRunInvalidMySQLDSNDoesNotDiscloseCredentials(t *testing.T) {
	const dsn = "sensitive-user:percent%40secret@tcp(mysql.internal:3306"
	t.Setenv("MYSQL_DSN", dsn)
	err := run()
	if err == nil {
		t.Fatal("want invalid-DSN startup error")
	}
	for _, secret := range []string{dsn, "sensitive-user", "percent%40secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("startup error %q disclosed %q", err, secret)
		}
	}
}

func TestMySQLConnectionErrorDoesNotForwardDriverText(t *testing.T) {
	t.Parallel()
	const endpoint = "tcp(mysql.internal:3306)/oidc"
	cases := []error{
		errors.New("dial failed for sensitive-user with percent%40secret"),
		&mysqldriver.MySQLError{
			Number:  1045,
			Message: "Access denied for user 'sensitive-user' using password 'percent%40secret'",
		},
	}
	for _, cause := range cases {
		err := mysqlConnectionError("ping", endpoint, cause)
		got := err.Error()
		for _, secret := range []string{"sensitive-user", "percent%40secret"} {
			if strings.Contains(got, secret) {
				t.Fatalf("mysqlConnectionError()=%q disclosed %q", got, secret)
			}
		}
		if !strings.Contains(got, endpoint) {
			t.Fatalf("mysqlConnectionError()=%q omitted safe endpoint", got)
		}
		if !errors.Is(err, cause) {
			t.Fatalf("mysqlConnectionError()=%v no longer unwraps to its cause", err)
		}
	}
}

func TestRedisLogLabelDoesNotDiscloseCredentials(t *testing.T) {
	t.Parallel()
	const dsn = "rediss://sensitive-user:percent%40secret@redis.internal:6380/4?protocol=3"
	got := oidcredis.RedactedDSN(dsn)
	if want := "rediss://redis.internal:6380/4"; got != want {
		t.Fatalf("RedactedDSN()=%q, want %q", got, want)
	}
	for _, secret := range []string{"sensitive-user", "percent%40secret", "protocol=3"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactedDSN()=%q disclosed %q", got, secret)
		}
	}
}
