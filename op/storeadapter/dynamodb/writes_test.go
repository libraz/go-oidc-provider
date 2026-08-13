package oidcdynamo_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conditionField is the field a guarded write sets.
const conditionField = "ConditionExpression"

// unconditionalWriters names the methods permitted to write an item
// without a condition. Each is a write that arbitrates nothing:
//
//   - Store.overwrite replaces a record whose holder is not a decision —
//     a metadata value, a directory entry, a session its own owner
//     rewrites — and is the only direct write of that kind.
//   - txOp.action renders a buffered plain put; which kind a staged
//     write gets is decided where it is staged.
//   - Store.putUserClaimingUsername stages the directory entry beside
//     the username reservation that carries the claim, and a
//     transaction is arbitrated as a unit.
//   - recoveryStore.Put replaces one subject's own slot list wholesale,
//     so no key is contended.
//
// Extending this set is the change that needs the argument, which is
// why the entries are spelled out rather than inferred.
var unconditionalWriters = map[string]bool{
	"Store.overwrite":               true,
	"txOp.action":                   true,
	"Store.putUserClaimingUsername": true,
	"recoveryStore.Put":             true,
}

// TestEveryItemWriteIsGuarded walks the adapter's sources and fails when
// a put outside [unconditionalWriters] carries no condition.
//
// The rule is a security property rather than a style preference.
// DynamoDB has no row lock, so a write that decides who holds a key by
// reading the key first admits every concurrent caller that read the
// same state: one replay marker accepted twice, one identifier claimed
// by two records. The decision has to travel with the write.
//
// The check is structural rather than a grep, so it also holds for the
// next substore: a new write shape has to state its condition or name
// itself here.
func TestEveryItemWriteIsGuarded(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	writes := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			found, unguarded := unguardedWrites(fn)
			writes += found
			if unconditionalWriters[qualifiedName(fn)] {
				continue
			}
			for _, pos := range unguarded {
				p := fset.Position(pos)
				t.Errorf("%s:%d: %s writes an item with no condition expression; "+
					"a write that decides who holds a key must state that decision as a condition",
					p.Filename, p.Line, qualifiedName(fn))
			}
		}
	}
	if writes == 0 {
		t.Fatal("found no item writes at all; the check no longer recognises the shapes it guards")
	}
}

// unguardedWrites reports how many item writes fn constructs and where
// the ones carrying no condition are.
//
// A function that assigns the condition instead of setting it in the
// literal counts as guarded throughout: that shape exists so a caller
// can branch between two conditions, and the branch is the point of it.
func unguardedWrites(fn *ast.FuncDecl) (int, []token.Pos) {
	var (
		found     int
		unguarded []token.Pos
		assigns   bool
	)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == conditionField {
					assigns = true
				}
			}
			return true
		}
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isItemWrite(lit.Type) {
			return true
		}
		found++
		if !hasField(lit, conditionField) {
			unguarded = append(unguarded, lit.Pos())
		}
		return true
	})
	if assigns {
		return found, nil
	}
	return found, unguarded
}

// qualifiedName renders a declaration as "Receiver.Method", or as the
// bare name for a plain function. The allow-list is keyed on it so an
// entry names one method rather than every function that shares a name
// as common as Put.
func qualifiedName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return fn.Name.Name
	}
	return ident.Name + "." + fn.Name.Name
}

// isItemWrite reports whether the composite-literal type is one of the
// two shapes that write a whole item: the input to a direct PutItem and
// the Put action a transaction stages.
func isItemWrite(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return (pkg.Name == "dynamodb" && sel.Sel.Name == "PutItemInput") ||
		(pkg.Name == "types" && sel.Sel.Name == "Put")
}

func hasField(lit *ast.CompositeLit, name string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == name {
			return true
		}
	}
	return false
}

// TestUnguardedWrites_DetectsAnUnconditionalPut feeds the detector the
// shapes it exists to tell apart, so a regression in the detector
// surfaces independently of what the adapter's own sources happen to
// contain.
func TestUnguardedWrites_DetectsAnUnconditionalPut(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		src       string
		mustCatch bool
	}{
		{
			name: "put with no condition",
			src: `package x
func f(s S) error {
    _, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(t), Item: i})
    return err
}`,
			mustCatch: true,
		},
		{
			name: "put carrying its condition",
			src: `package x
func f(s S) error {
    _, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
        TableName:           aws.String(t),
        Item:                i,
        ConditionExpression: aws.String("attribute_not_exists(pk)"),
    })
    return err
}`,
		},
		{
			name: "condition chosen after the literal",
			src: `package x
func f(s S) error {
    in := &dynamodb.PutItemInput{TableName: aws.String(t), Item: i}
    in.ConditionExpression = aws.String("attribute_not_exists(pk)")
    _, err := s.api.PutItem(ctx, in)
    return err
}`,
		},
		{
			name: "staged transaction put with no condition",
			src: `package x
func f(o *txOp) types.TransactWriteItem {
    return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(o.table), Item: o.item}}
}`,
			mustCatch: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synth.go", c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			caught := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				found, unguarded := unguardedWrites(fn)
				if found == 0 {
					t.Fatalf("the detector saw no item write at all\nsrc:%s", c.src)
				}
				if len(unguarded) > 0 {
					caught = true
				}
			}
			if caught != c.mustCatch {
				t.Errorf("caught=%v, want %v\nsrc:%s", caught, c.mustCatch, c.src)
			}
		})
	}
}
