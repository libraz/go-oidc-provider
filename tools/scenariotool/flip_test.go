package main

import (
	"strings"
	"testing"
)

func TestFlipStatusInYAML(t *testing.T) {
	const base = `feature: discovery
prefix: DIS
title: Discovery endpoints
specs:
  - OIDC Discovery 1.0
rows:
  - id: DIS-001
    severity: P0
    spec: OIDC Discovery §4
    behaviour: |
      GET /.well-known/openid-configuration
      returns 200 application/json.
    status: active
  - id: DIS-002
    severity: P0
    spec: OIDC Discovery §4
    behaviour: |
      Successful response MUST NOT bind any client/session/token entity.
  - id: DIS-003
    severity: P0
    spec: OIDC Discovery §4
    behaviour: |
      Embedder-injected extra discovery properties merge into response.
    status: pending
`

	t.Run("replace existing status", func(t *testing.T) {
		got, err := flipStatusInYAML([]byte(base), "DIS-003", "active", "")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		want := strings.Replace(base,
			"  - id: DIS-003\n    severity: P0\n    spec: OIDC Discovery §4\n    behaviour: |\n      Embedder-injected extra discovery properties merge into response.\n    status: pending",
			"  - id: DIS-003\n    severity: P0\n    spec: OIDC Discovery §4\n    behaviour: |\n      Embedder-injected extra discovery properties merge into response.\n    status: active",
			1)
		if string(got) != want {
			t.Errorf("status replace produced unexpected diff:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	})

	t.Run("insert missing status", func(t *testing.T) {
		got, err := flipStatusInYAML([]byte(base), "DIS-002", "active", "")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		if !strings.Contains(string(got), "MUST NOT bind any client/session/token entity.\n    status: active\n") {
			t.Errorf("expected status: active to be appended after behaviour block, got:\n%s", got)
		}
		// Other rows must be untouched.
		if !strings.Contains(string(got), "    status: active\n  - id: DIS-002") {
			t.Errorf("DIS-001 status: active should still be intact")
		}
	})

	t.Run("flip to out-of-scope adds plain reason", func(t *testing.T) {
		got, err := flipStatusInYAML([]byte(base), "DIS-003", "out-of-scope", "embedder concern see ADR 0042")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		if !strings.Contains(string(got), "    status: out-of-scope\n    out_of_scope_reason: embedder concern see ADR 0042\n") {
			t.Errorf("expected adjacent status + plain reason line, got:\n%s", got)
		}
	})

	t.Run("flip to out-of-scope quotes risky reason", func(t *testing.T) {
		got, err := flipStatusInYAML([]byte(base), "DIS-003", "out-of-scope", "covered by spec: see ADR 0042")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		if !strings.Contains(string(got), `out_of_scope_reason: "covered by spec: see ADR 0042"`) {
			t.Errorf("expected double-quoted reason (contains colon), got:\n%s", got)
		}
	})

	t.Run("flipping away from out-of-scope drops reason", func(t *testing.T) {
		oosFile := strings.Replace(base,
			"      Embedder-injected extra discovery properties merge into response.\n    status: pending\n",
			"      Embedder-injected extra discovery properties merge into response.\n    status: out-of-scope\n    out_of_scope_reason: legacy\n",
			1)
		got, err := flipStatusInYAML([]byte(oosFile), "DIS-003", "pending", "")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		if strings.Contains(string(got), "out_of_scope_reason") {
			t.Errorf("orphaned reason should be dropped; got:\n%s", got)
		}
		if !strings.Contains(string(got), "    status: pending\n") {
			t.Errorf("status should be pending; got:\n%s", got)
		}
	})

	t.Run("unknown ID returns error", func(t *testing.T) {
		if _, err := flipStatusInYAML([]byte(base), "DIS-999", "active", ""); err == nil {
			t.Fatalf("expected error for unknown ID")
		}
	})

	t.Run("preserves trailing newline", func(t *testing.T) {
		out, err := flipStatusInYAML([]byte(base), "DIS-002", "active", "")
		if err != nil {
			t.Fatalf("flipStatusInYAML: %v", err)
		}
		if !strings.HasSuffix(string(out), "\n") {
			t.Errorf("trailing newline must be preserved")
		}
	})
}

func TestYAMLInlineString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain-text", "plain-text"},
		{"  spaces  ", "spaces"},
		{"with: colon", `"with: colon"`},
		{`"already quoted"`, `"\"already quoted\""`},
		{"hash # in middle", `"hash # in middle"`},
		{"newline\nhere", `"newline\nhere"`},
		{"-leading dash", `"-leading dash"`},
		{"", `""`},
	}
	for _, tc := range cases {
		got := yamlInlineString(tc.in)
		if got != tc.want {
			t.Errorf("yamlInlineString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveTestRoot(t *testing.T) {
	cases := []struct {
		cwd, root, want string
	}{
		{"", "test/scenarios", "test/scenarios"},
		{"/repo", "test/scenarios", "/repo/test/scenarios"},
		{"/repo", "/abs/path", "/abs/path"},
		{"/repo", "", ""},
	}
	for _, tc := range cases {
		got := resolveTestRoot(tc.cwd, tc.root)
		if got != tc.want {
			t.Errorf("resolveTestRoot(%q, %q) = %q, want %q", tc.cwd, tc.root, got, tc.want)
		}
	}
}
