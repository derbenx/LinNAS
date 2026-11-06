package main

import (
	"testing"
)

func TestFolderSelectionOptOut(t *testing.T) {
	// If unselected_folders has "photos", then "photos" and "photos/2023" are not selected.
	// But "docs" is selected by default.
	selected := map[string]bool{
		"docs": true,
		"photos": false,
	}
	if !IsFolderSelected("docs/file.txt", selected) {
		t.Fatalf("expected docs/file.txt to be selected")
	}
	if IsFolderSelected("photos/vacation.jpg", selected) {
		t.Fatalf("expected photos/vacation.jpg to NOT be selected")
	}
	if !IsFolderSelected("new_folder/file.txt", selected) {
		t.Fatalf("expected new_folder/file.txt to be selected by default (opt out)")
	}
}
