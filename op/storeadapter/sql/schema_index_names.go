package oidcsql

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	createIndexNameRE = regexp.MustCompile(`(?i)CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?(\w+) ON (\w+)`)
	inlineIndexNameRE = regexp.MustCompile(`(?im)^\s*(?:UNIQUE )?(?:INDEX|KEY) (\w+)\s*\(`)
)

// declaredIndex is one index the DDL declares and the table it belongs to.
type declaredIndex struct {
	name, table string
}

// parseDDLIndexNames lists every index the DDL declares, standalone or
// inline in a CREATE TABLE body.
func parseDDLIndexNames(schema string) []declaredIndex {
	var out []declaredIndex
	for _, m := range createIndexNameRE.FindAllStringSubmatch(schema, -1) {
		out = append(out, declaredIndex{name: m[1], table: m[2]})
	}
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(schema, -1) {
		table := schema[loc[2]:loc[3]]
		body := schema[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		for _, m := range inlineIndexNameRE.FindAllStringSubmatch(body, -1) {
			out = append(out, declaredIndex{name: m[1], table: table})
		}
	}
	return out
}

// validateIndexNames rejects a name map under which an index the dialect's
// DDL declares gets an identifier longer than the engines allow. Index names
// embed the table name, so a table name that passes [validateIdentifier] can
// still push its indexes past the limit.
func (n nameMap) validateIndexNames(d Dialect) error {
	for _, idx := range parseDDLIndexNames(rewriteSchema(d.schema, n)) {
		if len(idx.name) > maxIdentifierBytes {
			return fmt.Errorf("oidcsql: index %q of table %q (%s) exceeds %d bytes; use a shorter table prefix or WithNaming name",
				idx.name, idx.table, n.keyOfTable(idx.table), maxIdentifierBytes)
		}
	}
	return nil
}

// keyOfTable returns the WithNaming key of the physical table name.
func (n nameMap) keyOfTable(table string) string {
	for i, name := range n.all() {
		if name == table {
			return logicalKeyAt(i)
		}
	}
	return table
}
