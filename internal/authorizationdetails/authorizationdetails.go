// Package authorizationdetails parses and validates the RFC 9396
// authorization_details request parameter. It owns the structural rules
// (RFC 9396 §2.1: a JSON array of objects, each carrying a non-empty
// string "type"), conservative size limits, and the dispatch to the
// embedder-registered per-type validators. The wire error mapping
// (invalid_authorization_details vs invalid_request) is the calling
// endpoint's responsibility; this package returns typed sentinels.
package authorizationdetails

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Size limits. RFC 9396 leaves authorization_details unbounded, which is a
// denial-of-service surface: a single request could carry megabytes of
// nested JSON. The OP caps both the raw byte length and the element count
// at conservative constants. Making these configurable is deferred until
// an embedder needs it; the defaults comfortably fit realistic payment /
// open-banking payloads.
const (
	// MaxBytes is the largest raw authorization_details JSON the OP
	// decodes. Oversize input is rejected before unmarshalling so a
	// hostile request cannot force a large allocation.
	MaxBytes = 16 * 1024

	// MaxElements is the largest number of elements the array may carry.
	MaxElements = 32
)

// Sentinel errors. Endpoints map every error except [ErrTooLarge] to the
// RFC 9396 §5 wire error invalid_authorization_details; ErrTooLarge maps
// to invalid_request because the request is malformed by size, not by
// content (decision §9②).
var (
	// ErrTooLarge signals the raw value exceeded [MaxBytes].
	ErrTooLarge = errors.New("authorizationdetails: value exceeds size limit")

	// ErrNotArray signals the value did not decode to a JSON array.
	ErrNotArray = errors.New("authorizationdetails: value is not a JSON array")

	// ErrEmpty signals the array decoded but carried no elements. An
	// authorization_details parameter that is present MUST describe at
	// least one authorization.
	ErrEmpty = errors.New("authorizationdetails: array is empty")

	// ErrTooManyElements signals the array exceeded [MaxElements].
	ErrTooManyElements = errors.New("authorizationdetails: too many elements")

	// ErrElementNotObject signals an array element was not a JSON object.
	ErrElementNotObject = errors.New("authorizationdetails: element is not an object")

	// ErrTypeMissing signals an element lacked a non-empty string "type".
	ErrTypeMissing = errors.New("authorizationdetails: element is missing a string \"type\"")

	// ErrUnknownType signals an element named a "type" the OP does not
	// accept (no matching [Validator] registered).
	ErrUnknownType = errors.New("authorizationdetails: unknown authorization details type")
)

// Validator enforces the type-specific shape of one authorization details
// element. The element's "type" member equals the key it is registered
// under; client is the authenticated client. A non-nil return rejects the
// request.
type Validator func(ctx context.Context, el map[string]any, client *store.Client) error

// Check parses raw, enforces the RFC 9396 §2.1 structure and the size
// caps, then dispatches each element to the registered validator for its
// type. On success it returns the decoded elements (suitable for
// persisting on the grant). Any failure returns a typed sentinel (or a
// validator's own error wrapped with the offending type).
//
// registry maps an accepted "type" identifier to its validator; an element
// whose type is absent from registry yields [ErrUnknownType].
func Check(ctx context.Context, raw string, client *store.Client, registry map[string]Validator) ([]map[string]any, error) {
	elems, err := decodeArray(raw)
	if err != nil {
		return nil, err
	}
	for i, el := range elems {
		if err := validateElement(ctx, i, el, client, registry); err != nil {
			return nil, err
		}
	}
	return elems, nil
}

// decodeArray enforces the size caps and the array shape of raw,
// returning the decoded elements or a typed sentinel.
func decodeArray(raw string) ([]map[string]any, error) {
	if len(raw) > MaxBytes {
		return nil, ErrTooLarge
	}
	// Reject trailing garbage; UseNumber preserves number fidelity for
	// the later re-marshal on the token response.
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	var elems []map[string]any
	if err := dec.Decode(&elems); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotArray, err.Error())
	}
	if dec.More() {
		return nil, ErrNotArray
	}
	if elems == nil {
		// A literal JSON null decodes to a nil slice; treat it as a
		// shape error rather than an empty grant.
		return nil, ErrNotArray
	}
	if len(elems) == 0 {
		return nil, ErrEmpty
	}
	if len(elems) > MaxElements {
		return nil, ErrTooManyElements
	}
	return elems, nil
}

// validateElement enforces the per-element structure (RFC 9396 §2.1) and
// dispatches to the registered validator for the element's type.
func validateElement(ctx context.Context, index int, el map[string]any, client *store.Client, registry map[string]Validator) error {
	if el == nil {
		return fmt.Errorf("%w (index %d)", ErrElementNotObject, index)
	}
	typ, ok := el["type"].(string)
	if !ok || typ == "" {
		return fmt.Errorf("%w (index %d)", ErrTypeMissing, index)
	}
	validate, known := registry[typ]
	if !known {
		return fmt.Errorf("%w: %q", ErrUnknownType, typ)
	}
	if err := validate(ctx, el, client); err != nil {
		return fmt.Errorf("authorizationdetails: type %q rejected: %w", typ, err)
	}
	return nil
}
