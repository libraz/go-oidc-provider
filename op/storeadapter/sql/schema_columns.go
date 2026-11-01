package oidcsql

import (
	"regexp"
	"strings"
	"sync"
)

// ddlColumns returns, by WithNaming key, every column the reference DDL of
// the dialect declares, in declaration order. Table names in the DDL are
// the defaults; columns do not change under [WithNaming].
func ddlColumns(d Dialect) map[string][]string {
	ddlColumnsMu.Lock()
	defer ddlColumnsMu.Unlock()
	if cols, ok := ddlColumnsCache[d.name]; ok {
		return cols
	}
	byTable := parseDDLColumns(d.schema)
	names := defaultNames()
	cols := make(map[string][]string, len(knownNamingKeys))
	for _, key := range knownNamingKeys {
		cols[key] = byTable[names.byKey(key)]
	}
	ddlColumnsCache[d.name] = cols
	return cols
}

var (
	ddlColumnsMu    sync.Mutex                         //nolint:gochecknoglobals // guards ddlColumnsCache.
	ddlColumnsCache = map[string]map[string][]string{} //nolint:gochecknoglobals // memo of parsed embedded DDL.
)

// parseDDLColumns returns each CREATE TABLE's column names, by table name,
// in declaration order.
func parseDDLColumns(schema []byte) map[string][]string {
	out := map[string][]string{}
	text := string(schema)
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(text, -1) {
		table := text[loc[2]:loc[3]]
		body := text[loc[1]:]
		if end := strings.Index(body, "\n);"); end >= 0 {
			body = body[:end]
		}
		for _, line := range strings.Split(body, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "--") {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "PRIMARY", "UNIQUE", "INDEX", "KEY", "CONSTRAINT", "CHECK", "FOREIGN":
				continue
			}
			out[table] = append(out[table], fields[0])
		}
	}
	return out
}

var createTableRE = regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\(`)
