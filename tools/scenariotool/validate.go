package main

import "fmt"

// runValidate loads the catalog, runs every structural and
// cross-file check, and reports the result.
func runValidate(dir string, lenient bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	if err := cat.Validate(ValidationOptions{LenientCrossRefs: lenient}); err != nil {
		return &exitError{code: 1, message: err.Error()}
	}
	rows := 0
	for _, f := range cat.Files {
		rows += len(f.Rows)
	}
	fmt.Printf("scenariotool: %d catalog file(s), %d row(s) — OK\n", len(cat.Files), rows)
	return nil
}
