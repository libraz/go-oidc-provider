package op_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
)

// minSalt returns a 32-byte salt the option-site validator accepts.
func minSalt() []byte {
	salt := make([]byte, subject.MinSaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

func TestWithPairwiseSubject_AcceptsMinimumSalt(t *testing.T) {
	t.Parallel()
	provider, err := op.New(append(validBaseOpts(t), op.WithPairwiseSubject(minSalt()))...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	if provider == nil {
		t.Fatal("op.New returned nil provider with no error")
	}
}

func TestWithPairwiseSubject_RejectsShortSalt(t *testing.T) {
	t.Parallel()
	short := make([]byte, subject.MinSaltLength-1)
	_, err := op.New(append(validBaseOpts(t), op.WithPairwiseSubject(short))...)
	if !errors.Is(err, op.ErrPairwiseSaltTooShort) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrPairwiseSaltTooShort)
	}
}

func TestWithPairwiseSubject_RejectsNilSalt(t *testing.T) {
	t.Parallel()
	_, err := op.New(append(validBaseOpts(t), op.WithPairwiseSubject(nil))...)
	if !errors.Is(err, op.ErrPairwiseSaltTooShort) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrPairwiseSaltTooShort)
	}
}

func TestWithPairwiseSubject_DefensivelyCopiesSalt(t *testing.T) {
	t.Parallel()
	salt := minSalt()
	provider, err := op.New(append(validBaseOpts(t), op.WithPairwiseSubject(salt))...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	original := salt[0]
	salt[0] ^= 0xff
	first, err := provider.SubjectGenerator().Generate(context.Background(), op.SubjectGeneratorInput{
		InternalUserID: "user-1",
		Client: &store.Client{
			ID:                  "c",
			SectorIdentifierURI: "https://sector.example",
		},
	})
	if err != nil {
		t.Fatalf("Generate after mutation: %v", err)
	}
	salt[0] = original
	second, err := provider.SubjectGenerator().Generate(context.Background(), op.SubjectGeneratorInput{
		InternalUserID: "user-1",
		Client: &store.Client{
			ID:                  "c",
			SectorIdentifierURI: "https://sector.example",
		},
	})
	if err != nil {
		t.Fatalf("Generate after restoration: %v", err)
	}
	if first != second {
		t.Fatalf("subject changed after caller mutated salt slice: first=%q second=%q", first, second)
	}
}

func TestWithSubjectGenerator_AcceptsCustomGenerator(t *testing.T) {
	t.Parallel()
	provider, err := op.New(append(validBaseOpts(t), op.WithSubjectGenerator(subject.UUIDv7()))...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	out, err := provider.SubjectGenerator().Generate(context.Background(), op.SubjectGeneratorInput{
		InternalUserID: "u-1",
		Client:         &store.Client{ID: "c"},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != "u-1" {
		t.Fatalf("Generate returned %q, want u-1", out)
	}
}

func TestWithSubjectGenerator_RejectsNilGenerator(t *testing.T) {
	t.Parallel()
	_, err := op.New(append(validBaseOpts(t), op.WithSubjectGenerator(nil))...)
	if !errors.Is(err, op.ErrSubjectGeneratorRequired) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrSubjectGeneratorRequired)
	}
}

func TestSubjectOptions_AreMutuallyExclusive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts []op.Option
	}{
		{
			name: "WithSubjectGenerator after WithPairwiseSubject",
			opts: []op.Option{op.WithPairwiseSubject(minSalt()), op.WithSubjectGenerator(subject.UUIDv7())},
		},
		{
			name: "WithPairwiseSubject after WithSubjectGenerator",
			opts: []op.Option{op.WithSubjectGenerator(subject.UUIDv7()), op.WithPairwiseSubject(minSalt())},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), tc.opts...)...)
			if err == nil {
				t.Fatal("op.New accepted both options simultaneously, want configuration error")
			}
			if !op.IsServerError(err) && err.Error() == "" {
				t.Fatalf("err = %v, want descriptive configuration error", err)
			}
		})
	}
}

func TestDefaultSubjectGenerator_IsUUIDv7Passthrough(t *testing.T) {
	t.Parallel()
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New returned error: %v", err)
	}
	out, err := provider.SubjectGenerator().Generate(context.Background(), op.SubjectGeneratorInput{
		InternalUserID: "default-user",
		Client:         &store.Client{ID: "c"},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != "default-user" {
		t.Fatalf("default generator returned %q, want passthrough of InternalUserID", out)
	}
}
