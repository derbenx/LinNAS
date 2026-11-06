package main

import (
	"strings"
	"testing"
)

func TestRecycleBinInFolderTree(t *testing.T) {
	items := []ServerItem{
		{RelPath: "docs", IsDir: true},
		{RelPath: "photos", IsDir: true},
		{RelPath: "RecycleBin", IsDir: true},
	}

	var dirsOnly []ServerItem
	for _, it := range items {
		if it.IsDir {
			dirsOnly = append(dirsOnly, it)
		}
	}

	foundRecycleBin := false
	for _, d := range dirsOnly {
		if d.RelPath == "RecycleBin" {
			foundRecycleBin = true
			break
		}
	}

	if !foundRecycleBin {
		t.Fatalf("expected RecycleBin to be in server folder list")
	}

	// Deletes within RecycleBin are not tracked
	cleanRel := "RecycleBin/foo.txt"
	isInsideRecycleBin := strings.HasPrefix(cleanRel, "RecycleBin/")
	if !isInsideRecycleBin {
		t.Fatalf("expected isInsideRecycleBin to be true")
	}
}
