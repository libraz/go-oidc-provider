//go:build example

package main

import (
	"strings"
	"testing"
)

func TestRedactedEndpointDropsUserinfo(t *testing.T) {
	t.Parallel()
	const endpoint = "https://sensitive-user:percent%40secret@dynamo.internal:8000/path?token=abc"
	got, err := redactedEndpoint(endpoint)
	if err != nil {
		t.Fatalf("redactedEndpoint: %v", err)
	}
	if want := "https://dynamo.internal:8000"; got != want {
		t.Fatalf("redactedEndpoint()=%q, want %q", got, want)
	}
	for _, secret := range []string{"sensitive-user", "percent%40secret", "token=abc", "/path"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redactedEndpoint()=%q disclosed %q", got, secret)
		}
	}
}

func TestRedactedEndpointInvalidInputFailsClosed(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{
		"",
		"dynamo.internal:8000",
		"://sensitive-user:percent%40secret@dynamo.internal",
	} {
		got, err := redactedEndpoint(endpoint)
		if err == nil {
			t.Fatalf("redactedEndpoint(%q) = %q, want error", endpoint, got)
		}
		if got != "" {
			t.Fatalf("redactedEndpoint(%q)=%q, want empty label", endpoint, got)
		}
		if endpoint != "" && strings.Contains(err.Error(), endpoint) {
			t.Fatalf("error %q echoed the input", err)
		}
	}
}

func TestShouldCreateTablesDefaultsToOverrideMode(t *testing.T) {
	// The cases below rewrite this variable in turn, so the test reads
	// process-global state and cannot run in parallel with anything
	// else that does. Clearing it up front also registers the restore
	// hook for whatever the caller's environment already held.
	t.Setenv("DYNAMODB_CREATE_TABLES", "")

	cases := []struct {
		env      string
		override bool
		want     bool
	}{
		// Unset: provision against an emulator, never against the
		// account the ambient AWS configuration resolves to.
		{env: "", override: true, want: true},
		{env: "", override: false, want: false},
		// Explicit settings win in both directions.
		{env: "1", override: false, want: true},
		{env: "0", override: true, want: false},
		// Anything else is not a switch-off; falling back to the
		// default keeps a typo from silently skipping provisioning.
		{env: "yes", override: true, want: true},
	}
	for _, tc := range cases {
		t.Setenv("DYNAMODB_CREATE_TABLES", tc.env)
		if got := shouldCreateTables(tc.override); got != tc.want {
			t.Errorf("shouldCreateTables(%t) with env %q = %t, want %t",
				tc.override, tc.env, got, tc.want)
		}
	}
}
