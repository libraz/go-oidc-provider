package oidcdynamo_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// TestEveryProvisionedIndexIsQueried fails when [Store.TableDefinitions]
// declares a global secondary index no query path in the package reads.
//
// The rule is a cost property of the artifact rather than a style
// preference. Embedders translate the definitions into their own
// CloudFormation, CDK, or Terraform, so a declared index is provisioned
// in production: every item written to the table is copied into it and
// every write spends the index's write units. An index nothing queries
// buys that permanently and returns nothing, and on the busiest table of
// a deployment — refresh tokens, one item per rotation — it roughly
// doubles both storage and write cost.
//
// The check is structural rather than a grep, so it also holds for the
// next access pattern: an index added to a table has to be reachable
// from a query, and a query path that is deleted has to take its index
// with it.
func TestEveryProvisionedIndexIsQueried(t *testing.T) {
	t.Parallel()

	files := parsePackageSources(t)
	constants := indexNameConstants(t, files)
	queried := map[string]bool{}
	for _, file := range files {
		for ident := range queriedIndexIdents(file) {
			name, ok := constants[ident]
			if !ok {
				t.Fatalf("query names index constant %s, which no const declaration in the package defines", ident)
			}
			queried[name] = true
		}
	}
	if len(queried) == 0 {
		t.Fatal("found no index query at all; the check no longer recognises the shapes it inspects")
	}

	s, err := oidcdynamo.New(unusedAPI{})
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	declared := 0
	for _, def := range s.TableDefinitions() {
		for _, idx := range def.GlobalSecondaryIndexes {
			declared++
			name := aws.ToString(idx.IndexName)
			if !queried[name] {
				t.Errorf("table %s provisions index %s, which no query path in the adapter reads; "+
					"an index that is written on every item and never read costs storage and write units for nothing",
					def.Name, name)
			}
		}
	}
	if declared == 0 {
		t.Fatal("TableDefinitions declared no secondary index at all")
	}
}

// parsePackageSources parses every non-test source file of the adapter.
func parsePackageSources(t *testing.T) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	return files
}

// indexNameConstants maps each index-name constant to the physical index
// name it declares, so a query naming the constant can be matched against
// the definition that provisions the string.
func indexNameConstants(t *testing.T, files []*ast.File) map[string]string {
	t.Helper()

	out := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
					continue
				}
				name := value.Names[0].Name
				if !strings.HasPrefix(name, "index") {
					continue
				}
				lit, ok := value.Values[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name, err)
				}
				out[name] = unquoted
			}
		}
	}
	return out
}

// queriedIndexIdents collects the index-name identifiers a file reads
// from: the third argument of a queryIndex call, and the IndexName a
// Query input carries either in its literal or by later assignment.
//
// A function's own parameter naming an index is a pass-through — the
// shared queryIndex helper is written that way — so the identifier that
// matters is the one at its call site, which the first rule already
// collects.
func queriedIndexIdents(file *ast.File) map[string]struct{} {
	out := map[string]struct{}{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		params := parameterNames(fn)
		record := func(name string) {
			if _, isParam := params[name]; !isParam {
				out[name] = struct{}{}
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "queryIndex" && len(node.Args) > 2 {
					if ident, ok := node.Args[2].(*ast.Ident); ok {
						record(ident.Name)
					}
				}
			case *ast.KeyValueExpr:
				if ident, ok := node.Key.(*ast.Ident); ok && ident.Name == "IndexName" {
					addIndexIdent(record, node.Value)
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "IndexName" || i >= len(node.Rhs) {
						continue
					}
					addIndexIdent(record, node.Rhs[i])
				}
			}
			return true
		})
	}
	return out
}

func parameterNames(fn *ast.FuncDecl) map[string]struct{} {
	out := map[string]struct{}{}
	if fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			out[name.Name] = struct{}{}
		}
	}
	return out
}

// addIndexIdent reports the identifier behind an IndexName value, which
// the adapter always writes as aws.String(indexConstant).
func addIndexIdent(record func(string), expr ast.Expr) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return
	}
	if ident, ok := call.Args[0].(*ast.Ident); ok {
		record(ident.Name)
	}
}

// TestQueriedIndexIdents_RecognisesBothQueryShapes feeds the collector
// the two shapes an index read takes, so a regression in the collector
// surfaces independently of what the adapter's sources happen to
// contain: a collector that recognised nothing would otherwise report
// every provisioned index as dead, and one that over-matched would
// report none.
func TestQueriedIndexIdents_RecognisesBothQueryShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "helper call",
			src: `package x
func f(s *Store) {
    s.parent.queryIndex(ctx, table, indexByGrant, attrGrantID, value)
}`,
			want: []string{"indexByGrant"},
		},
		{
			name: "query input literal",
			src: `package x
func f(s *Store) {
    s.api.Query(ctx, &dynamodb.QueryInput{TableName: aws.String(t), IndexName: aws.String(indexByClientSubject)})
}`,
			want: []string{"indexByClientSubject"},
		},
		{
			name: "no index read at all",
			src: `package x
func f(s *Store) {
    s.api.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(t)})
}`,
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
			got := sortedKeys(queriedIndexIdents(file))
			if !slices.Equal(got, c.want) {
				t.Errorf("collected %v, want %v\nsrc:%s", got, c.want, c.src)
			}
		})
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// unusedAPI satisfies [oidcdynamo.API] for the construction of a Store
// whose schema is inspected without issuing a request. Every method
// fails, so a test that reaches the network fails loudly rather than
// silently depending on an emulator.
type unusedAPI struct{}

var errUnusedAPI = errors.New("oidcdynamo_test: the schema inspection issues no requests")

func (unusedAPI) GetItem(
	context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options),
) (*dynamodb.GetItemOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) PutItem(
	context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options),
) (*dynamodb.PutItemOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) UpdateItem(
	context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options),
) (*dynamodb.UpdateItemOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) DeleteItem(
	context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options),
) (*dynamodb.DeleteItemOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) Query(
	context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options),
) (*dynamodb.QueryOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) Scan(
	context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options),
) (*dynamodb.ScanOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) TransactWriteItems(
	context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) CreateTable(
	context.Context, *dynamodb.CreateTableInput, ...func(*dynamodb.Options),
) (*dynamodb.CreateTableOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) UpdateTable(
	context.Context, *dynamodb.UpdateTableInput, ...func(*dynamodb.Options),
) (*dynamodb.UpdateTableOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) DescribeTable(
	context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options),
) (*dynamodb.DescribeTableOutput, error) {
	return nil, errUnusedAPI
}

func (unusedAPI) UpdateTimeToLive(
	context.Context, *dynamodb.UpdateTimeToLiveInput, ...func(*dynamodb.Options),
) (*dynamodb.UpdateTimeToLiveOutput, error) {
	return nil, errUnusedAPI
}
