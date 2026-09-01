package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// Finding is one branch that turns a storage failure into an answer.
type Finding struct {
	File   string
	Line   int
	Callee string
	Detail string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Callee, f.Detail)
}

// storeMethods are the storage reads whose error the OP has repeatedly
// collapsed into a negative answer: a transport failure reported as
// "no such session", "no consent", "no ancestor", "not found".
//
// The set is a list of method names rather than a type test because the
// gate parses without type information — it has to run on a tree that
// does not build. A same-named method on something that is not a store
// is a false positive the allowlist absorbs; the alternative, a check
// that needs a green build, is a check that is not there when it is
// most useful.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var storeMethods = map[string]bool{
	"Get":         true,
	"Find":        true,
	"FindByID":    true,
	"Lookup":      true,
	"Load":        true,
	"Read":        true,
	"Fetch":       true,
	"Resolve":     true,
	"List":        true,
	"ListBy":      true,
	"Exists":      true,
	"GetClient":   true,
	"GetSession":  true,
	"GetGrant":    true,
	"FindSession": true,
	"FindGrant":   true,
}

// Analyze reports the branches in one file that answer a storage read's
// error without carrying the error anywhere.
//
// The shape it looks for is narrow on purpose:
//
//	x, err := someStore.Get(...)
//	if err != nil {
//	    return nil, false     // or: return zero values, or set a
//	}                         // "not found" flag and carry on
//
// A branch that returns the error, wraps it, tests it with errors.Is,
// hands it to a logger or an audit emitter, or assigns it outward is
// deciding about the failure and is left alone. What is reported is a
// branch that discards it, because the caller then cannot tell "there
// is no such record" from "the database did not answer" — and every
// caller that has confused those two has failed open.
func Analyze(file string, fset *token.FileSet, f *ast.File) []Finding {
	var out []Finding
	prev := neighbours(f)
	ast.Inspect(f, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		errName, ok := errNonNilTest(stmt.Cond)
		if !ok {
			return true
		}
		callee, ok := storeCallBefore(stmt, prev, errName)
		if !ok {
			return true
		}
		if carriesError(stmt.Body, errName) {
			return true
		}
		if !answersNegatively(stmt.Body) {
			return true
		}
		pos := fset.Position(stmt.Pos())
		out = append(out, Finding{
			File:   file,
			Line:   pos.Line,
			Callee: callee,
			Detail: "the branch answers without carrying the error, so a backend that did not respond is " +
				"reported as a record that does not exist; separate the two or propagate",
		})
		return true
	})
	return out
}

// errNonNilTest reports the identifier in an `err != nil` condition.
func errNonNilTest(cond ast.Expr) (string, bool) {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return "", false
	}
	lhs, ok := bin.X.(*ast.Ident)
	if !ok || !looksLikeError(lhs.Name) {
		return "", false
	}
	if rhs, ok := bin.Y.(*ast.Ident); !ok || rhs.Name != "nil" {
		return "", false
	}
	return lhs.Name, true
}

// looksLikeError reports whether an identifier names an error value.
func looksLikeError(name string) bool {
	return name == "err" || strings.HasSuffix(name, "Err") || strings.HasPrefix(name, "err")
}

// storeCallBefore reports the storage method whose call produced the
// error the if-statement tests, looking at the statement's own
// initialiser and then at the assignment immediately preceding it.
func storeCallBefore(stmt *ast.IfStmt, prev map[*ast.IfStmt]ast.Stmt, errName string) (string, bool) {
	if stmt.Init != nil {
		if callee, ok := assignCallsStore(stmt.Init, errName); ok {
			return callee, true
		}
	}
	if before := prev[stmt]; before != nil {
		return assignCallsStore(before, errName)
	}
	return "", false
}

// neighbours maps each if-statement in a file to the statement directly
// above it in the same block. The parser does not link a statement to
// its predecessor, and the call that produced the error is almost
// always that predecessor, so the map is built once per file.
//
// It is returned rather than stored: a package-level map would make the
// analyzer unsafe to run on two files at once, which is exactly the
// kind of shared mutable state this repository's own gates exist to
// catch.
func neighbours(f *ast.File) map[*ast.IfStmt]ast.Stmt {
	out := map[*ast.IfStmt]ast.Stmt{}
	ast.Inspect(f, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, s := range block.List {
			if ifs, ok := s.(*ast.IfStmt); ok && i > 0 {
				out[ifs] = block.List[i-1]
			}
		}
		return true
	})
	return out
}

// assignCallsStore reports whether an assignment binds errName from a
// call to one of the storage reads.
func assignCallsStore(s ast.Stmt, errName string) (string, bool) {
	assign, ok := s.(*ast.AssignStmt)
	if !ok {
		return "", false
	}
	bound := false
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name == errName {
			bound = true
		}
	}
	if !bound || len(assign.Rhs) != 1 {
		return "", false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !storeMethods[sel.Sel.Name] {
		return "", false
	}
	recv := ""
	if id, ok := sel.X.(*ast.Ident); ok {
		recv = id.Name + "."
	} else if inner, ok := sel.X.(*ast.SelectorExpr); ok {
		recv = inner.Sel.Name + "."
	}
	return recv + sel.Sel.Name, true
}

// carriesError reports whether a branch does anything with the error
// beyond discarding it: returns it, wraps it, classifies it, logs it,
// or assigns it outward.
func carriesError(body *ast.BlockStmt, errName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		id, ok := n.(*ast.Ident)
		if ok && id.Name == errName {
			found = true
			return false
		}
		return true
	})
	return found
}

// answersNegatively reports whether a branch produces an answer rather
// than deferring: it returns, or it assigns a literal to something and
// falls through.
//
// A branch that panics, continues a loop, or breaks is not answering
// the caller's question with a fabricated negative, so it is not what
// this gate speaks about.
func answersNegatively(body *ast.BlockStmt) bool {
	for _, s := range body.List {
		ret, ok := s.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		if len(ret.Results) == 0 {
			return true
		}
		for _, r := range ret.Results {
			if isNegativeLiteral(r) {
				return true
			}
		}
	}
	return false
}

// isNegativeLiteral reports whether an expression is one of the values a
// fabricated "no such record" answer is made of.
func isNegativeLiteral(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "nil" || v.Name == "false"
	case *ast.BasicLit:
		return v.Kind == token.INT && v.Value == "0"
	case *ast.CompositeLit:
		return len(v.Elts) == 0
	default:
		return false
	}
}
