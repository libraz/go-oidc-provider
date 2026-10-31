package contract

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- UserStore -------------------------------------------------------------

// UserStore is read-only from the library's perspective — embedders own
// the write path through their own admin plane — so everything past the
// absent-subject case needs a directory entry the harness cannot create
// on its own. [Backend.SeedUser] is that hook; the sub-tests that need
// it skip when a backend does not supply one.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var userStoreCases = []subtest{
	{"FindMissing", userStoreFindMissing},
	{"FindBySubjectRoundTrip", userStoreFindBySubject},
	{"FindByUsernameResolvesSameSubject", userPasswordFindByUsername},
	{"FindByUsernameMissing", userPasswordFindByUsernameMissing},
	{"FindByUsernameMatchesVerbatim", userPasswordFindByUsernameVerbatim},
	{"ReadPasswordHashRoundTrip", userPasswordReadHash},
	{"ReadPasswordHashMissingSubject", userPasswordReadHashMissing},
	{"UpdatePasswordHashRoundTrip", userPasswordUpdateHash},
	{"UpdatePasswordHashMissingSubject", userPasswordUpdateHashMissing},
	{"UpdatePasswordHashUnchanged", userPasswordUpdateHashUnchanged},
}

func userStoreFindMissing(t *testing.T, f Factory) {
	b := f(t)
	_, err := b.Store.Users().FindBySubject(context.Background(), "contract-absent-subject")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindBySubject missing: want ErrNotFound, got %v", err)
	}
}

// seededUserBackend arranges one directory entry and returns the
// backend alongside it, skipping when the backend cannot seed.
func seededUserBackend(t *testing.T, f Factory) (Backend, *store.User, string, []byte) {
	t.Helper()
	b := f(t)
	if b.SeedUser == nil {
		t.Skip("backend supplies no SeedUser hook")
	}
	user := &store.User{
		Subject:   "contract-user",
		Claims:    map[string]any{"name": "Contract User", "email": "user@example.com"},
		UpdatedAt: Reference,
	}
	const username = "contract-user@example.com"
	hash := []byte("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Y29udHJhY3RoYXNo")
	b.SeedUser(t, user, username, hash)
	return b, user, username, hash
}

func userStoreFindBySubject(t *testing.T, f Factory) {
	b, want, _, _ := seededUserBackend(t, f)
	got, err := b.Store.Users().FindBySubject(context.Background(), want.Subject)
	if err != nil {
		t.Fatalf("FindBySubject: %v", err)
	}
	if got.Subject != want.Subject {
		t.Fatalf("Subject = %q, want %q", got.Subject, want.Subject)
	}
	if got.Claims["name"] != want.Claims["name"] {
		t.Fatalf("Claims[name] = %v, want %v", got.Claims["name"], want.Claims["name"])
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, want.UpdatedAt)
	}
}

func requireUserPasswords(t *testing.T, s store.Store) store.UserPasswordStore {
	t.Helper()
	passwords, ok := s.Users().(store.UserPasswordStore)
	if !ok {
		t.Skipf("backend %T does not implement store.UserPasswordStore", s.Users())
	}
	return passwords
}

// userPasswordFindByUsername pins the invariant that matters most in
// this pair: both lookups must land on the same subject. A backend that
// normalises one path and not the other would enrol a login under one
// identifier and issue tokens under another.
func userPasswordFindByUsername(t *testing.T, f Factory) {
	b, want, username, _ := seededUserBackend(t, f)
	passwords := requireUserPasswords(t, b.Store)

	got, err := passwords.FindByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("FindByUsername(%q): %v", username, err)
	}
	if got.Subject != want.Subject {
		t.Fatalf("FindByUsername subject = %q, want %q", got.Subject, want.Subject)
	}
}

// userPasswordFindByUsernameVerbatim pins the matching rule
// [store.UserPasswordStore] declares: the username is compared byte for
// byte, and any folding or trimming belongs to the embedder.
//
// A backend whose column collation folds case or strips accents deviates
// twice over, and both directions are behaviour the embedder never
// asked for. A login submitted as "ALICE" resolves alice's account on
// that backend and reports "no such user" on every other, so the same
// deployment authenticates differently depending on which engine it was
// pointed at. And two accounts that differ only in case — which the
// embedder's own directory accepted — collapse onto one row, so
// provisioning the second fails with a duplicate key on that engine
// alone.
func userPasswordFindByUsernameVerbatim(t *testing.T, f Factory) {
	b := f(t)
	if b.SeedUser == nil {
		t.Skip("backend supplies no SeedUser hook")
	}
	passwords := requireUserPasswords(t, b.Store)
	ctx := context.Background()
	hash := []byte("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Y29udHJhY3RoYXNo")

	lower := &store.User{Subject: "verbatim-lower", UpdatedAt: Reference}
	b.SeedUser(t, lower, "verbatim-user@example.com", hash)

	// A username differing only in case is a different username, and
	// seeding it must not collide with the one above.
	upper := &store.User{Subject: "verbatim-upper", UpdatedAt: Reference}
	b.SeedUser(t, upper, "Verbatim-User@example.com", hash)

	for _, tc := range []struct {
		username string
		subject  string
	}{
		{"verbatim-user@example.com", lower.Subject},
		{"Verbatim-User@example.com", upper.Subject},
	} {
		got, err := passwords.FindByUsername(ctx, tc.username)
		if err != nil {
			t.Fatalf("FindByUsername(%q): %v — the two usernames collapsed onto one row", tc.username, err)
		}
		if got.Subject != tc.subject {
			t.Fatalf("FindByUsername(%q) resolved subject %q, want %q — the lookup is not comparing bytes",
				tc.username, got.Subject, tc.subject)
		}
	}

	// A case that was never seeded resolves nothing. Folding it onto a
	// stored row would authenticate a credential the directory does not
	// hold under that name.
	if _, err := passwords.FindByUsername(ctx, "VERBATIM-USER@EXAMPLE.COM"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUsername on an unseeded casing: want ErrNotFound, got %v", err)
	}
}

func userPasswordFindByUsernameMissing(t *testing.T, f Factory) {
	b, _, _, _ := seededUserBackend(t, f)
	passwords := requireUserPasswords(t, b.Store)

	// An unknown username must not resolve to a placeholder: the
	// orchestrator distinguishes "unknown user" from "wrong password"
	// internally and renders one invalid-credentials prompt either way.
	_, err := passwords.FindByUsername(context.Background(), "contract-absent@example.com")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByUsername(absent): want ErrNotFound, got %v", err)
	}
}

func userPasswordReadHash(t *testing.T, f Factory) {
	b, user, _, want := seededUserBackend(t, f)
	passwords := requireUserPasswords(t, b.Store)

	got, err := passwords.ReadPasswordHash(context.Background(), user.Subject)
	if err != nil {
		t.Fatalf("ReadPasswordHash: %v", err)
	}
	// The encoded hash round-trips verbatim: the library reads it as a
	// PHC string and any re-encoding would break verification.
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadPasswordHash = %q, want %q", got, want)
	}
}

func userPasswordReadHashMissing(t *testing.T, f Factory) {
	b, _, _, _ := seededUserBackend(t, f)
	passwords := requireUserPasswords(t, b.Store)

	_, err := passwords.ReadPasswordHash(context.Background(), "contract-absent-subject")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReadPasswordHash(absent): want ErrNotFound, got %v", err)
	}
}

// requirePasswordHashUpdater skips the current test when the user store
// does not implement [store.UserPasswordHashUpdater].
func requirePasswordHashUpdater(t *testing.T, s store.Store) store.UserPasswordHashUpdater {
	t.Helper()
	updater, ok := s.Users().(store.UserPasswordHashUpdater)
	if !ok {
		t.Skipf("backend %T does not implement store.UserPasswordHashUpdater", s.Users())
	}
	return updater
}

// rehashedPassword is the replacement hash the updater cases write.
const rehashedPassword = "$argon2id$v=19$m=65536,t=3,p=4$bmV3c2FsdA$cmVoYXNoZWQ" //nolint:gosec // fixture hash, not a credential.

// userPasswordUpdateHash pins that a rehash replaces the stored hash: the
// next ReadPasswordHash returns the new encoding verbatim, so the next
// login verifies against argon2id rather than the legacy scheme.
func userPasswordUpdateHash(t *testing.T, f Factory) {
	b, user, _, _ := seededUserBackend(t, f)
	updater := requirePasswordHashUpdater(t, b.Store)
	passwords := requireUserPasswords(t, b.Store)
	ctx := context.Background()

	if err := updater.UpdatePasswordHash(ctx, user.Subject, []byte(rehashedPassword)); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	got, err := passwords.ReadPasswordHash(ctx, user.Subject)
	if err != nil {
		t.Fatalf("ReadPasswordHash after update: %v", err)
	}
	if string(got) != rehashedPassword {
		t.Fatalf("ReadPasswordHash after update = %q, want %q", got, rehashedPassword)
	}
}

// userPasswordUpdateHashMissing pins the [store.ErrNotFound] answer for
// an unknown subject, which must not create a credential.
func userPasswordUpdateHashMissing(t *testing.T, f Factory) {
	b, _, _, _ := seededUserBackend(t, f)
	updater := requirePasswordHashUpdater(t, b.Store)
	passwords := requireUserPasswords(t, b.Store)
	ctx := context.Background()

	err := updater.UpdatePasswordHash(ctx, "contract-absent-subject", []byte(rehashedPassword))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UpdatePasswordHash(absent): want ErrNotFound, got %v", err)
	}
	if _, err := passwords.ReadPasswordHash(ctx, "contract-absent-subject"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ReadPasswordHash after a refused update: want ErrNotFound, got %v", err)
	}
}

// userPasswordUpdateHashUnchanged pins that only absence is reported as
// [store.ErrNotFound]: rewriting the hash a subject already carries is a
// successful update, even on an engine that counts changed rather than
// matched rows.
func userPasswordUpdateHashUnchanged(t *testing.T, f Factory) {
	b, user, _, hash := seededUserBackend(t, f)
	updater := requirePasswordHashUpdater(t, b.Store)

	if err := updater.UpdatePasswordHash(context.Background(), user.Subject, hash); err != nil {
		t.Fatalf("UpdatePasswordHash with the stored hash: %v", err)
	}
}
