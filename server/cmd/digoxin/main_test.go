package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPruneKeepsTheNewestCopies: a second copy made the same day is newer
// than the first, and is kept.
func TestPruneKeepsTheNewestCopies(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"digoxin-20261003-020000.db", "digoxin-20261004-020000.db", "digoxin-20261004-153000.db", "digoxin-20261005-020000.db"} {
		_ = os.WriteFile(filepath.Join(dir, name), nil, 0o640)
	}
	if err := prune(dir, 2); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(left) != 2 || filepath.Base(left[0]) != "digoxin-20261004-153000.db" || filepath.Base(left[1]) != "digoxin-20261005-020000.db" {
		t.Fatalf("kept %v", left)
	}
}

func TestServersBoundHeaders(t *testing.T) {
	if newServer("127.0.0.1:0", nil).MaxHeaderBytes != 16<<10 {
		t.Fatal("header limit")
	}
}
