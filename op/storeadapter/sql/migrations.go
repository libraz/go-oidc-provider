package oidcsql

import (
	"bytes"
	"io/fs"
	"path"
)

// Migrations returns the configured dialect's migration files with any
// [WithTablePrefix] and [WithNaming] applied. 000001_v1.0.0.up.sql creates the schema
// v1.0.0 shipped and each later file applies one release's changes, so
// applying every file in order to an empty database yields the schema
// [Store.Schema] creates. The file names follow the golang-migrate
// convention, which lets its iofs source read the result directly:
//
//	src, err := iofs.New(store.Migrations(), ".")
//	if err != nil {
//		return err
//	}
//	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
//	if err != nil {
//		return err
//	}
//	err = m.Up()
//
// A file holds several statements, so golang-migrate's MySQL driver needs
// multiStatements=true in the DSN. Atlas reads the same files with
// format=golang-migrate once `atlas migrate hash` has written atlas.sum.
// A database created before adopting these files must first be recorded
// at the last release it applied — `migrate force 4` for one at v1.3.0 —
// so that only the later files run. Give the OP's files their own version
// history, separate from the application's; schema/MIGRATIONS.md shows how
// for each tool.
//
// Stable since v1.5.
func (s *Store) Migrations() fs.FS {
	sub, err := fs.Sub(schemaFS, "schema/migrations/"+s.dialect.name)
	if err != nil {
		panic("oidcsql: missing embedded migrations for " + s.dialect.name + ": " + err.Error()) //nolint:forbidigo // build-time invariant: every dialect's migrations are bundled via go:embed.
	}
	return migrationFS{fsys: sub, names: s.names}
}

// migrationFS is a read-only view of one dialect's migration directory
// that passes every file through [rewriteSchema]. Sizes reported by Stat
// and ReadDir are those of the rewritten content.
type migrationFS struct {
	fsys  fs.FS
	names nameMap
}

var (
	_ fs.ReadDirFS  = migrationFS{}
	_ fs.ReadFileFS = migrationFS{}
)

// Open returns a directory as a listing of rewritten entries and a file
// as its rewritten content.
func (m migrationFS) Open(name string) (fs.File, error) {
	f, err := m.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		dir, ok := f.(fs.ReadDirFile)
		if !ok {
			_ = f.Close()
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
		}
		return &migrationDir{ReadDirFile: dir, fsys: m, dir: name}, nil
	}
	_ = f.Close()
	content, err := m.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return &migrationFile{Reader: bytes.NewReader(content), info: sizedInfo{info, int64(len(content))}}, nil
}

// ReadFile returns the named file with the table names rewritten.
func (m migrationFS) ReadFile(name string) ([]byte, error) {
	raw, err := fs.ReadFile(m.fsys, name)
	if err != nil {
		return nil, err
	}
	return []byte(rewriteSchema(raw, m.names)), nil
}

// ReadDir lists the named directory, sorted by file name.
func (m migrationFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(m.fsys, name)
	if err != nil {
		return nil, err
	}
	return m.wrapEntries(name, entries), nil
}

func (m migrationFS) wrapEntries(dir string, entries []fs.DirEntry) []fs.DirEntry {
	out := make([]fs.DirEntry, len(entries))
	for i, e := range entries {
		out[i] = migrationEntry{DirEntry: e, fsys: m, path: path.Join(dir, e.Name())}
	}
	return out
}

// stat reports a file's info with the size of its rewritten content.
func (m migrationFS) stat(name string, info fs.FileInfo) (fs.FileInfo, error) {
	if info.IsDir() {
		return info, nil
	}
	content, err := m.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return sizedInfo{info, int64(len(content))}, nil
}

// migrationDir is an open directory of a [migrationFS].
type migrationDir struct {
	fs.ReadDirFile
	fsys migrationFS
	dir  string
}

func (d *migrationDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.ReadDirFile.ReadDir(n)
	return d.fsys.wrapEntries(d.dir, entries), err
}

// migrationEntry is a directory entry whose Info reports the rewritten size.
type migrationEntry struct {
	fs.DirEntry
	fsys migrationFS
	path string
}

func (e migrationEntry) Info() (fs.FileInfo, error) {
	info, err := e.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	return e.fsys.stat(e.path, info)
}

// migrationFile is an open, rewritten migration file.
type migrationFile struct {
	*bytes.Reader
	info fs.FileInfo
}

func (f *migrationFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *migrationFile) Close() error               { return nil }

// sizedInfo overrides the size of an embedded file's info.
type sizedInfo struct {
	fs.FileInfo
	size int64
}

func (i sizedInfo) Size() int64 { return i.size }
