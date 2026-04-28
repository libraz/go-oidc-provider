package password_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	testUsername = "alice@example.com"
	testSubject  = "sub-alice"
	testPassword = "correct horse battery staple"
)

func newPasswordStore(t *testing.T) *inmem.Store {
	t.Helper()
	st := inmem.New()
	hash := hashWith(t, testPassword, 64*1024, 3, 1, []byte("0123456789abcdef"))
	st.PutUserWithPassword(context.Background(), &store.User{Subject: testSubject}, testUsername, hash)
	return st
}

func TestNewAuthenticator_RejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := password.NewAuthenticator(nil); !errors.Is(err, password.ErrStoreRequired) {
		t.Fatalf("NewAuthenticator(nil): expected ErrStoreRequired, got %v", err)
	}
}

func TestAuthenticator_FactorMetadata(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	a, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if got := a.Type(); got != authn.FactorPassword {
		t.Errorf("Type() = %q, want %q", got, authn.FactorPassword)
	}
	if got := a.AAL(); got != authn.AAL1 {
		t.Errorf("AAL() = %v, want AAL1", got)
	}
	if got := a.AMR(); got != "pwd" {
		t.Errorf("AMR() = %q, want pwd", got)
	}
	if got := a.Prompts(); !slices.Equal(got, []string{password.PromptType}) {
		t.Errorf("Prompts() = %v, want [%q]", got, password.PromptType)
	}
}

func TestAuthenticator_BeginEmitsPrompt(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	a, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	step, err := a.Begin(context.Background(), authn.BeginInput{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatal("Begin: Prompt is nil")
	}
	if step.Prompt.Type != password.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, password.PromptType)
	}
	if len(step.Prompt.Inputs) != 2 {
		t.Fatalf("Prompt.Inputs: got %d fields, want 2", len(step.Prompt.Inputs))
	}
	if step.Prompt.Inputs[0].Name != password.UsernameFieldName {
		t.Errorf("Inputs[0].Name = %q, want %q", step.Prompt.Inputs[0].Name, password.UsernameFieldName)
	}
	if step.Prompt.Inputs[1].Name != password.PasswordFieldName {
		t.Errorf("Inputs[1].Name = %q, want %q", step.Prompt.Inputs[1].Name, password.PasswordFieldName)
	}
	if step.Prompt.Inputs[1].Kind != interaction.FieldPassword {
		t.Errorf("password field Kind = %v, want FieldPassword", step.Prompt.Inputs[1].Kind)
	}
}

func TestAuthenticator_Continue_HappyPath(t *testing.T) {
	t.Parallel()
	st := newPasswordStore(t)
	a, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	authTime := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	step, err := a.Continue(context.Background(), authn.ContinueInput{
		AuthTime: authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{
			password.UsernameFieldName: testUsername,
			password.PasswordFieldName: testPassword,
		}},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil {
		t.Fatal("Continue: Result is nil")
	}
	if step.Result.Subject != testSubject {
		t.Errorf("Result.Subject = %q, want %q", step.Result.Subject, testSubject)
	}
	if !step.Result.AuthTime.Equal(authTime) {
		t.Errorf("Result.AuthTime = %v, want %v", step.Result.AuthTime, authTime)
	}
}

func TestAuthenticator_Continue_FailureBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		values  map[string]string
		wantErr error
	}{
		{
			name:    "wrong-password",
			values:  map[string]string{password.UsernameFieldName: testUsername, password.PasswordFieldName: "wrong"},
			wantErr: password.ErrInvalidCredentials,
		},
		{
			name:    "unknown-username",
			values:  map[string]string{password.UsernameFieldName: "ghost@example.com", password.PasswordFieldName: testPassword},
			wantErr: password.ErrInvalidCredentials,
		},
		{
			name:    "missing-username",
			values:  map[string]string{password.PasswordFieldName: testPassword},
			wantErr: password.ErrFieldMissing,
		},
		{
			name:    "missing-password",
			values:  map[string]string{password.UsernameFieldName: testUsername},
			wantErr: password.ErrFieldMissing,
		},
		{
			name:    "empty-username",
			values:  map[string]string{password.UsernameFieldName: "", password.PasswordFieldName: testPassword},
			wantErr: password.ErrFieldMissing,
		},
		{
			name:    "empty-password",
			values:  map[string]string{password.UsernameFieldName: testUsername, password.PasswordFieldName: ""},
			wantErr: password.ErrFieldMissing,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newPasswordStore(t)
			a, err := password.NewAuthenticator(st.UserPasswords())
			if err != nil {
				t.Fatalf("NewAuthenticator: %v", err)
			}
			step, err := a.Continue(context.Background(), authn.ContinueInput{
				Submission: interaction.FormSubmission{Values: tc.values},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Continue: got error %v, want %v", err, tc.wantErr)
			}
			if step.Result != nil {
				t.Errorf("Continue: Result must be nil on error, got %+v", step.Result)
			}
		})
	}
}

func TestAuthenticator_Continue_NoPasswordSet(t *testing.T) {
	t.Parallel()
	// User exists but has no password column — passkey-only account.
	// The authenticator MUST collapse onto ErrInvalidCredentials so the
	// SPA's response is enumeration-safe.
	st := inmem.New()
	st.PutUserWithPassword(context.Background(), &store.User{Subject: "sub-passkey-only"}, "passkey@example.com", nil)
	a, err := password.NewAuthenticator(st.UserPasswords())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	_, err = a.Continue(context.Background(), authn.ContinueInput{
		Submission: interaction.FormSubmission{Values: map[string]string{
			password.UsernameFieldName: "passkey@example.com",
			password.PasswordFieldName: "anything",
		}},
	})
	if !errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("Continue: expected ErrInvalidCredentials for hashless user, got %v", err)
	}
}

func TestAuthenticator_Continue_PropagatesBackendFault(t *testing.T) {
	t.Parallel()
	a, err := password.NewAuthenticator(faultyStore{err: errors.New("db down")})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	_, err = a.Continue(context.Background(), authn.ContinueInput{
		Submission: interaction.FormSubmission{Values: map[string]string{
			password.UsernameFieldName: "x",
			password.PasswordFieldName: "y",
		}},
	})
	if err == nil {
		t.Fatal("Continue: expected error on backend fault")
	}
	if errors.Is(err, password.ErrInvalidCredentials) {
		t.Fatalf("Continue: backend fault must NOT collapse onto ErrInvalidCredentials, got %v", err)
	}
}

// faultyStore is a minimal [store.UserPasswordStore] that returns the
// configured error on every method. The struct lets the backend-fault
// test exercise the propagation path without touching the inmem
// reference implementation.
type faultyStore struct {
	err error
}

func (f faultyStore) FindBySubject(_ context.Context, _ string) (*store.User, error) {
	return nil, f.err
}

func (f faultyStore) FindByUsername(_ context.Context, _ string) (*store.User, error) {
	return nil, f.err
}

func (f faultyStore) ReadPasswordHash(_ context.Context, _ string) ([]byte, error) {
	return nil, f.err
}
