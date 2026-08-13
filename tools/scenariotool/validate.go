package main

import "fmt"

// runValidate loads the catalog, runs every structural and
// cross-file check, and reports the result.
func runValidate(dir string, lenient bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	// A root that will not resolve fails the run. This is the gate's own
	// entry point: it is the one caller that must never fall back to
	// checking the catalog against a tree that declares none of what it
	// cites, because there is nobody behind it to notice.
	root, err := repoRootFromCatalogDir(dir)
	if err != nil {
		return err
	}
	if err := cat.Validate(ValidationOptions{
		LenientCrossRefs: lenient,
		SourceRoot:       root,
	}); err != nil {
		return &exitError{code: 1, message: err.Error()}
	}
	rows := 0
	for _, f := range cat.Files {
		rows += len(f.Rows)
	}
	fmt.Printf("scenariotool: %d catalog file(s), %d row(s) — OK\n", len(cat.Files), rows)
	return nil
}
