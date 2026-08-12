package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocateTest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := `package scenarios_test

import "testing"

func TestScenario_DIS_001_DiscoveryServedWith200JSON(t *testing.T) {
	t.Parallel()
}

func TestScenario_CA_CSJWT_11_SomeBehaviour(t *testing.T) {
	t.Parallel()
}

func TestScenario_DIS_002(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DIS-002")
}
`
	if err := os.WriteFile(filepath.Join(dir, "discovery_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write test fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_auth_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write test fixture: %v", err)
	}

	dis := &Row{ID: "DIS-001", File: &FeatureFile{Feature: "discovery"}}
	loc, err := locateTest(dis, dir)
	if err != nil {
		t.Fatalf("locateTest DIS-001: %v", err)
	}
	if !loc.Found || loc.Line != 5 {
		t.Errorf("DIS-001 expected line 5 found, got %#v", loc)
	}

	dis2 := &Row{ID: "DIS-002", File: &FeatureFile{Feature: "discovery"}}
	loc2, err := locateTest(dis2, dir)
	if err != nil {
		t.Fatalf("locateTest DIS-002: %v", err)
	}
	if !loc2.Found || loc2.Line != 13 {
		t.Errorf("DIS-002 expected line 13 found (no slug suffix), got %#v", loc2)
	}

	subPrefix := &Row{ID: "CA-CSJWT-11", File: &FeatureFile{Feature: "client_auth"}}
	loc3, err := locateTest(subPrefix, dir)
	if err != nil {
		t.Fatalf("locateTest CA-CSJWT-11: %v", err)
	}
	if !loc3.Found || loc3.Line != 9 {
		t.Errorf("CA-CSJWT-11 expected line 9 (sub-prefix supported), got %#v", loc3)
	}

	missing := &Row{ID: "DIS-999", File: &FeatureFile{Feature: "discovery"}}
	loc4, err := locateTest(missing, dir)
	if err != nil {
		t.Fatalf("locateTest DIS-999 (file exists, function missing): %v", err)
	}
	if loc4.Found {
		t.Errorf("DIS-999 should not be found")
	}

	noFile := &Row{ID: "ZZZ-001", File: &FeatureFile{Feature: "ghost"}}
	loc5, err := locateTest(noFile, dir)
	if err != nil {
		t.Fatalf("locateTest no-file: %v", err)
	}
	if loc5.Found || loc5.File == "" {
		t.Errorf("ZZZ-001 expected unfound but with path set, got %#v", loc5)
	}
}
