package testkit

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func continueAs(t *testing.T, a op.Authenticator, subject string) {
	t.Helper()
	step, err := a.Continue(context.Background(), op.ContinueInput{
		Submission: interaction.FormSubmission{Values: map[string]string{SubjectFieldName: subject}},
	})
	if err != nil || step.Result == nil || step.Result.Subject != subject {
		t.Fatalf("Continue(%q) = %+v, %v", subject, step, err)
	}
}

func TestSeedingSubjectAuthenticator_SeedsUnknownSubject(t *testing.T) {
	t.Parallel()
	users := inmem.New()
	continueAs(t, seedingSubjectAuthenticator{users: users}, "user-new")
	if _, err := users.Users().FindBySubject(context.Background(), "user-new"); err != nil {
		t.Fatalf("logged-in subject not seeded: %v", err)
	}
}

func TestSeedingSubjectAuthenticator_KeepsSeededUser(t *testing.T) {
	t.Parallel()
	users := inmem.New()
	users.PutUser(context.Background(), &store.User{Subject: "user-seeded", Claims: map[string]any{"email": "a@example.test"}})
	continueAs(t, seedingSubjectAuthenticator{users: users}, "user-seeded")
	got, err := users.Users().FindBySubject(context.Background(), "user-seeded")
	if err != nil || got.Claims["email"] != "a@example.test" {
		t.Fatalf("seeded user overwritten: %+v, %v", got, err)
	}
}

func TestSeedingSubjectAuthenticator_MissingSubjectSeedsNothing(t *testing.T) {
	t.Parallel()
	users := inmem.New()
	if _, err := (seedingSubjectAuthenticator{users: users}).Continue(context.Background(), op.ContinueInput{}); err == nil {
		t.Fatal("Continue without a subject succeeded")
	}
}
