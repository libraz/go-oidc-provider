package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The kinds of vocabulary the gate walks. Each is also the first
// field of an allowlist row.
const (
	kindSymbol  = "symbol"
	kindEvent   = "event"
	kindMessage = "message"
	kindIndex   = "index"
	kindConsult = "consulted"
)

// Package locations the checks are anchored to. They are named here
// rather than spelled at each use so a package move breaks the gate's
// broken-scan guard in one place instead of silently emptying a check.
const (
	auditEventPkg  = "internal/auditevent"
	auditAliasFile = "op/audit.go"
	messagesFile   = "internal/i18n/embedded/en.json"
	dynamoPkg      = "op/storeadapter/dynamodb"
)

// reservedMarker is the phrase a public audit-event constant carries
// when the library never emits it.
//
// The marker is a fixed prefix rather than a prose match because the
// claim it stands for is load-bearing: an operator subscribing to an
// event decides, from this sentence alone, whether silence on the
// stream means "did not happen" or "not instrumented". Prose drifts
// and each block ends up phrasing the caveat slightly differently;
// pinning the opening words makes the absence of one mechanical.
const reservedMarker = "Reserved vocabulary:"

// finding is one declared-but-unreached entry, or one allowlist row the
// tree has outgrown.
type finding struct {
	kind   string
	id     string
	where  string
	detail string
}

// String renders a finding the way the gate reports it.
func (f finding) String() string {
	head := fmt.Sprintf("%s %s", f.kind, f.id)
	if f.where != "" {
		head += " (" + f.where + ")"
	}
	return head + ": " + f.detail
}

// libraryFile reports whether a repo-relative path is library code —
// the shipping OP itself, not a demo, a harness, or a build tool.
//
// Reachability is a claim about the library: an example that mentions a
// sentinel demonstrates the name, it does not show the OP ever
// producing the value. Counting demos as reach would let every item
// this gate exists to catch be answered by adding it to a sample.
func libraryFile(path string) bool {
	root := path
	if i := strings.Index(path, "/"); i >= 0 {
		root = path[:i]
	}
	switch root {
	case "examples", "cmd", "sample", "tools", "test", "conformance":
		return false
	default:
		return true
	}
}

// publicPkg reports whether a repo-relative package directory is part
// of the surface an embedder can import.
func publicPkg(pkg string) bool {
	if hasSegment(pkg, "internal") {
		return false
	}
	return pkg == "op" || strings.HasPrefix(pkg, "op/")
}

// checkSymbols reports exported constants and sentinels in the public
// packages that no library code path produces or consults.
//
// Audit-event constants are excluded and handed to [checkEvents]: they
// are a catalogue an embedder subscribes to, so "nothing in the library
// names it" is a statement about instrumentation rather than about the
// symbol, and it needs the emission-site question asked properly.
func checkSymbols(ix *index, al *allowlist) []finding {
	var out []finding
	for _, d := range ix.decls {
		if !publicPkg(d.pkg) || !isExported(d.name) || !symbolCandidate(d) {
			continue
		}
		if ix.usedIn(d.name, libraryFile) {
			continue
		}
		if d.alias != "" && ix.usedIn(d.alias, libraryFile) {
			continue
		}
		id := d.qualified()
		if al.allows(kindSymbol, id) {
			continue
		}
		out = append(out, finding{
			kind:  kindSymbol,
			id:    id,
			where: d.pos(),
			detail: "declared but no library code path produces or reads it; " +
				"return it from the path it describes, delete it, or allowlist it with the reason it is unreachable",
		})
	}
	return out
}

// checkConsulted reports exported constants the library names only
// inside their own enumeration plumbing.
//
// It is the second half of [checkSymbols]. That check asks whether a
// declaration is named anywhere, and a constant listed by its own
// String() and IsValid() answers yes — so a feature flag can be
// accepted, validated, advertised in discovery, and never branched on,
// with this gate green the whole time. The description of the gate had
// to disclaim exactly that. This check asks the narrower question the
// description implied: does anything act on the value.
//
// Sentinel errors are out of scope. An Err value's use is being
// returned and compared, neither of which the plumbing set covers, so
// running them through this check would only produce noise.
func checkConsulted(ix *index, al *allowlist) []finding {
	var out []finding
	for _, d := range ix.decls {
		if !publicPkg(d.pkg) || !isExported(d.name) || !consultCandidate(d) {
			continue
		}
		// A symbol nothing names at all is checkSymbols' finding; this
		// one speaks only about symbols that are named but inert.
		if !ix.usedIn(d.name, libraryFile) {
			continue
		}
		if ix.consultedIn(d.name, libraryFile) {
			continue
		}
		if d.alias != "" && ix.consultedIn(d.alias, libraryFile) {
			continue
		}
		id := d.qualified()
		if al.allows(kindConsult, id) {
			continue
		}
		out = append(out, finding{
			kind:  kindConsult,
			id:    id,
			where: d.pos(),
			detail: "named only by its own enumeration plumbing — String, IsValid, a lookup table — so nothing " +
				"branches on it; wire the branch it describes, delete it, or allowlist it with the reason " +
				"being enumerable is the whole contract",
		})
	}
	return out
}

// consultCandidate reports whether a declaration is one the consulted
// check speaks about: an exported constant that is not an audit event.
func consultCandidate(d decl) bool {
	return d.kind == kindConst && !isAuditEventConst(d)
}

// symbolCandidate reports whether a declaration is one the symbol check
// speaks about: an exported constant, or an exported sentinel error.
//
// Other exported variables are left alone. A package-level var is
// usually a lookup table or a default the package itself consults, and
// widening the check to cover them would trade the finding this gate
// exists for against a stream of entries whose answer is always the
// same allowlist row.
func symbolCandidate(d decl) bool {
	if isAuditEventConst(d) {
		return false
	}
	switch d.kind {
	case kindConst:
		return true
	case kindVar:
		return strings.HasPrefix(d.name, "Err")
	default:
		return false
	}
}

// isAuditEventConst reports whether a declaration is one of the public
// audit-event aliases, in either the `X AuditEvent = ...` or the
// `X = AuditEvent(...)` form the catalogue uses.
func isAuditEventConst(d decl) bool {
	if d.typeName == "AuditEvent" {
		return true
	}
	for _, ref := range d.refs {
		if ref == "AuditEvent" {
			return true
		}
	}
	return false
}

// checkEvents reports catalogued audit events whose documented
// emission status does not match the tree.
//
// Both directions fail. An event nothing emits has to say so, because
// an operator who subscribes to it and sees silence will otherwise read
// the silence as evidence. An event the library does emit must not
// carry the caveat, because a reserved marker left behind after the
// instrumentation lands tells that operator to ignore a live signal.
func checkEvents(ix *index, al *allowlist) []finding {
	var out []finding
	aliases := auditAliases(ix)
	for _, d := range ix.declsIn(auditEventPkg) {
		if d.kind != kindConst || d.typeName != "Name" || d.str == "" {
			continue
		}
		alias, ok := aliases[d.name]
		if !ok {
			out = append(out, finding{
				kind: kindEvent, id: d.str, where: d.pos(),
				detail: "catalogued but no public op constant aliases it, so an embedder cannot name the event",
			})
			continue
		}
		out = append(out, eventFinding(ix, al, d, alias)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// eventFinding compares one event's emission sites against the caveat
// its public constant carries.
func eventFinding(ix *index, al *allowlist, event, alias decl) []finding {
	emitted := ix.usedIn(event.name, emissionSite) || ix.usedIn(alias.name, emissionSite)
	reserved := strings.Contains(alias.doc, reservedMarker)
	switch {
	case emitted && reserved:
		return []finding{{
			kind: kindEvent, id: event.str, where: alias.pos(),
			detail: fmt.Sprintf("documented %q but a library code path emits it; drop the caveat", reservedMarker),
		}}
	case !emitted && !reserved:
		if al.allows(kindEvent, event.str) {
			return nil
		}
		return []finding{{
			kind: kindEvent, id: event.str, where: alias.pos(),
			detail: fmt.Sprintf("no library code path emits it and its godoc does not open with %q, "+
				"so silence on this event reads as evidence it did not happen", reservedMarker),
		}}
	default:
		return nil
	}
}

// emissionSite reports whether a file is somewhere an audit event can
// be raised from. The registry that declares the vocabulary and the
// public block that aliases it both name every event and emit none.
func emissionSite(path string) bool {
	if !libraryFile(path) {
		return false
	}
	if path == auditAliasFile {
		return false
	}
	return !strings.HasPrefix(path, auditEventPkg+"/")
}

// auditAliases maps each internal event constant to the public op
// constant that aliases it.
func auditAliases(ix *index) map[string]decl {
	out := map[string]decl{}
	for _, d := range ix.decls {
		if d.file != auditAliasFile || !isAuditEventConst(d) {
			continue
		}
		for _, ref := range d.refs {
			if strings.HasPrefix(ref, "Audit") {
				out[ref] = d
			}
		}
	}
	return out
}

// checkMessages reports seed message keys nothing renders.
//
// A key in the catalogue is a promise that some surface displays it;
// an embedder overriding it in their own bundle has no way to discover
// that theirs will never appear.
func checkMessages(root string, ix *index, al *allowlist) ([]finding, int, error) {
	//nolint:gosec // the path is derived from the scan root, not request input.
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(messagesFile)))
	if err != nil {
		return nil, 0, fmt.Errorf("read seed messages: %w", err)
	}
	var seed map[string]string
	if err := json.Unmarshal(raw, &seed); err != nil {
		return nil, 0, fmt.Errorf("parse %s: %w", messagesFile, err)
	}
	var out []finding
	for key := range seed {
		if rendered(ix, key) || al.allows(kindMessage, key) {
			continue
		}
		out = append(out, finding{
			kind: kindMessage, id: key, where: messagesFile,
			detail: "seeded but no library code names it, so no surface can render it",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, len(seed), nil
}

// rendered reports whether library code names the key as a literal.
func rendered(ix *index, key string) bool {
	for file := range ix.literals[key] {
		if libraryFile(file) && !strings.HasPrefix(file, "internal/i18n/") {
			return true
		}
	}
	return false
}

// checkIndexes reports DynamoDB secondary indexes the adapter creates
// and never queries.
//
// A GSI is provisioned capacity: an unread one is billed, is written on
// every put, and reads to a maintainer as evidence that some access
// path exists. The declaring file is the table definition, so a name
// that appears nowhere else is created for a query nothing performs.
func checkIndexes(ix *index, al *allowlist) []finding {
	var out []finding
	for _, d := range ix.declsIn(dynamoPkg) {
		if d.kind != kindConst || d.str == "" || !strings.HasPrefix(d.name, "index") {
			continue
		}
		queried := ix.usedIn(d.name, func(file string) bool { return file != d.file })
		if queried || al.allows(kindIndex, d.str) {
			continue
		}
		out = append(out, finding{
			kind: kindIndex, id: d.str, where: d.pos(),
			detail: "provisioned by the table definition and named nowhere else, so no read path queries it",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}
