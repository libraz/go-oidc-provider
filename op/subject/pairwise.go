package subject

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/op/store"
)

// MinSaltLength is the minimum length the pairwise salt MUST satisfy.
// 32 bytes (256 bits) is the conventional ceiling for SHA-256 inputs
// past which the entropy gain becomes negligible while still leaving
// a large practical safety margin against precomputation. The
// op.WithPairwiseSubject option enforces the same lower bound at
// construction time so misconfiguration never reaches the runtime
// dispatch path.
const MinSaltLength = 32

// Pairwise returns the [Generator] that derives subject identifiers
// per OIDC Core 1.0 §8.1:
//
//	sub = base64url-no-pad( SHA-256( salt || ":" || sector || ":" || userID ) )
//
// The sector is resolved from the requesting client per OIDC Core
// 1.0 §5: when [store.Client.SectorIdentifierURI] is non-empty its
// host is used; otherwise the host of the single registered redirect
// URI is used; otherwise the call returns [ErrSectorUnresolved] and
// the library propagates the failure as a server-side configuration
// error.
//
// The colon separator is intentional: it prevents two distinct
// (sector, userID) pairs from producing the same SHA-256 input when
// the values themselves contain colons, since a colon in the sector
// or the userID becomes a literal byte rather than a delimiter.
//
// # Salt
//
// The supplied salt MUST be at least [MinSaltLength] bytes; shorter
// values cause Pairwise to return an always-failing generator that
// reports [ErrSaltTooShort] from every Generate call. The op package
// validator rejects short salts at the option site so the failing
// generator is unreachable in normal operation; it exists so a future
// helper that bypasses op.WithPairwiseSubject cannot silently produce
// weak subjects.
//
// The salt is captured by reference in the returned generator;
// callers MUST NOT mutate the underlying slice after the call
// returns. The op-package wrapper copies the slice defensively at the
// option boundary; tests calling Pairwise directly should pass an
// owned slice or copy first.
//
// # Determinism
//
// Pairwise satisfies the [Generator] determinism contract: identical
// (userID, sector, salt) inputs produce identical outputs across
// calls and across processes. The package's TestPairwiseDeterminism
// exercises this with a 10k-iteration property loop.
func Pairwise(salt []byte) Generator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract; the salt-too-short branch returns the always-failing variant.
	if len(salt) < MinSaltLength {
		return invalidSaltGenerator{}
	}
	return pairwiseGenerator{salt: salt}
}

// pairwiseGenerator implements [Generator] for the OIDC Core 1.0
// §8.1 pairwise strategy. The salt is owned by the value (callers
// MUST hand off ownership) so concurrent Generate calls share a
// single immutable byte slice.
type pairwiseGenerator struct {
	salt []byte
}

func (g pairwiseGenerator) Generate(_ context.Context, in GeneratorInput) (Subject, error) {
	userID, err := pickUserID(in)
	if err != nil {
		return "", err
	}
	sector, err := resolveSector(in.Client)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write(g.salt)
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(sector))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(userID))
	return Subject(base64.RawURLEncoding.EncodeToString(h.Sum(nil))), nil
}

// pickUserID returns the user identifier the pairwise hash binds
// against. The identifier is taken verbatim, so distinguishing users
// that reach the OP through different upstreams is the embedder's
// responsibility — see [GeneratorInput] for why.
func pickUserID(in GeneratorInput) (string, error) {
	if in.InternalUserID == "" {
		return "", ErrInputEmpty
	}
	return in.InternalUserID, nil
}

// resolveSector returns the sector host per OIDC Core 1.0 §5. Prefer
// client.SectorIdentifierURI; fall back to the host of the single
// registered redirect URI; reject otherwise.
func resolveSector(c *store.Client) (string, error) {
	if c == nil {
		return "", ErrSectorUnresolved
	}
	if c.SectorIdentifierURI != "" {
		host, err := hostOf(c.SectorIdentifierURI)
		if err != nil {
			return "", err
		}
		return host, nil
	}
	hosts := uniqueHosts(c.RedirectURIs)
	if len(hosts) == 1 {
		return hosts[0], nil
	}
	return "", ErrSectorUnresolved
}

// hostOf parses raw as an absolute URL and returns the lower-cased
// hostname with any port stripped, matching OIDC Core 1.0 §8.1's
// "host component" sector derivation — and byte-for-byte what the
// OP's own sector resolution produces for the same value. The
// library enforces the OIDC Core §5 "https only" rule for
// sector_identifier_uri at the metadata-validation site (the
// dynamic-registration mount) — Pairwise itself does not re-check
// the scheme because it is consumed downstream of validation.
func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ErrInvalidSectorURL
	}
	return strings.ToLower(u.Hostname()), nil
}

// uniqueHosts collapses redirectURIs to their distinct hostname
// values (port stripped, matching [hostOf]), preserving order so the
// function is deterministic for tests. Malformed URIs and entries
// without a host are skipped silently; the caller decides how to
// surface the empty result.
func uniqueHosts(uris []string) []string {
	if len(uris) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(uris))
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// invalidSaltGenerator surfaces a misconfigured salt at request time
// without panicking. It exists only as a defence-in-depth fallback;
// the op.WithPairwiseSubject validator rejects short salts at
// construction time so this path is unreachable in normal operation.
type invalidSaltGenerator struct{}

func (invalidSaltGenerator) Generate(context.Context, GeneratorInput) (Subject, error) {
	return "", ErrSaltTooShort
}

// ErrSectorUnresolved signals that the requesting client carried no
// sector_identifier_uri AND has more than one (or zero) registered
// redirect_uri host from which a sector can be derived. The op
// package wraps the sentinel into op.ErrPairwiseSectorUnresolved for
// the public catalog.
var ErrSectorUnresolved = errors.New("subject: pairwise sector cannot be resolved from client")

// ErrInvalidSectorURL signals that a SectorIdentifierURI string is
// not a parseable URL with a non-empty host. The op package wraps the
// sentinel into a server-side configuration error.
var ErrInvalidSectorURL = errors.New("subject: sector_identifier_uri is not a parseable URL")

// ErrSaltTooShort signals that [Pairwise] was constructed with a
// salt shorter than [MinSaltLength]. The op package wraps the
// sentinel into op.ErrPairwiseSaltTooShort for the public catalog.
var ErrSaltTooShort = errors.New("subject: pairwise salt is shorter than the documented minimum")
