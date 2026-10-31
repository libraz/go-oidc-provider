package jose_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenJOSECalls names go-jose entry points the OP must never call on
// inbound material: x5c chains are not a trust source, and inbound JWT
// payloads decode through encoding/json rather than go-jose's json fork.
var forbiddenJOSECalls = map[string]string{
	"Certificates":                    "x5c chains must not be parsed or trusted",
	"UnsafeClaimsWithoutVerification": "inbound claims decode through encoding/json",
	"ParseSignedAndEncrypted":         "inbound JWTs parse through internal/jose",
}

// TestNoForbiddenJOSECalls scans every non-test Go file under internal/ and
// op/ for calls into go-jose paths whose parsers carried denial-of-service
// defects, so this OP stays off them regardless of the pinned go-jose
// version. jwt.ParseSigned is flagged for the same reason as the claim
// decoders: it returns a token whose Claims use the go-jose json fork.
//
// Tracks:
//   - GHSA-v6h2-qj3f-2h6v (go-jose) — CPU exhaustion in
//     Header.Certificates() on an x5c chain with a huge RSA key.
//   - GHSA-27pc-rm86-68pq (go-jose) — json fork panicked decoding a JWT
//     claim into a struct embedding an unexported type.
func TestNoForbiddenJOSECalls(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../op"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if why, bad := forbiddenJOSECalls[sel.Sel.Name]; bad {
					t.Errorf("%s: call to %s: %s", fset.Position(call.Pos()), sel.Sel.Name, why)
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "jwt" && sel.Sel.Name == "ParseSigned" {
					t.Errorf("%s: call to jwt.ParseSigned: inbound JWTs parse through internal/jose", fset.Position(call.Pos()))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
