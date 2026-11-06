package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ClientMetaFile struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	ModTime     int64  `json:"mod_time"`
	SHA256      string `json:"sha256"`
	LastUpdated string `json:"last_updated"`
}

type ClientLedgerEntry struct {
	RelPath   string `json:"rel_path"`
	Action    string `json:"action"` // "created", "modified", "deleted", "restored"
	Timestamp int64  `json:"timestamp"`
	ModTime   int64  `json:"mod_time"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Details   string `json:"details,omitempty"`
}

type ClientHistoryEntry struct {
	Action     string `json:"action"`
	OrigPath   string `json:"orig_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Timestamp  string `json:"timestamp"`
	ModTime    int64  `json:"mod_time,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Details    string `json:"details,omitempty"`
}

type ClientDirMeta struct {
	Directory string                    `json:"directory"`
	LastScan  string                    `json:"last_scan"`
	Files     map[string]ClientMetaFile `json:"files"`
	Deleted   map[string]int64          `json:"deleted,omitempty"` // basename -> deleted_at unix timestamp
	Ledger    []ClientLedgerEntry       `json:"ledger,omitempty"`
	History   []ClientHistoryEntry      `json:"history,omitempty"`
}

func calculateLocalSHA256(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cleanClientLedger(entries []ClientLedgerEntry) []ClientLedgerEntry {
	if len(entries) == 0 {
		return entries
	}
	counts := make(map[string]int)
	var filtered []ClientLedgerEntry
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if counts[e.RelPath] < 10 {
			counts[e.RelPath]++
			filtered = append(filtered, e)
		}
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	return filtered
}

func loadClientDirMeta(rootFolder, relSubdir string) ClientDirMeta {
	var meta ClientDirMeta
	meta.Directory = relSubdir
	meta.Files = make(map[string]ClientMetaFile)
	meta.Deleted = make(map[string]int64)
	meta.Ledger = make([]ClientLedgerEntry, 0)
	meta.History = make([]ClientHistoryEntry, 0)

	targetDir := rootFolder
	if relSubdir != "" && relSubdir != "." {
		targetDir = filepath.Join(rootFolder, filepath.FromSlash(relSubdir))
	}
	cloudDataPath := filepath.Join(targetDir, ".cloud_data")
	b, err := os.ReadFile(cloudDataPath)
	if err == nil && len(b) > 0 {
		raw := string(b)
		if strings.HasPrefix(raw, clientCloudDataHeader) {
			raw = strings.TrimPrefix(raw, clientCloudDataHeader)
		}
		_ = json.Unmarshal([]byte(raw), &meta)
		if meta.Files == nil {
			meta.Files = make(map[string]ClientMetaFile)
		}
		if meta.Deleted == nil {
			meta.Deleted = make(map[string]int64)
		}
		if meta.Ledger == nil {
			meta.Ledger = make([]ClientLedgerEntry, 0)
		}
		if meta.History == nil {
			meta.History = make([]ClientHistoryEntry, 0)
		}
	}
	return meta
}

func saveClientDirMeta(rootFolder, relSubdir string, meta ClientDirMeta) error {
	meta.LastScan = time.Now().Format(time.RFC3339)
	meta.Ledger = cleanClientLedger(meta.Ledger)
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	targetDir := rootFolder
	if relSubdir != "" && relSubdir != "." {
		targetDir = filepath.Join(rootFolder, filepath.FromSlash(relSubdir))
	}
	_ = os.MkdirAll(targetDir, 0755)
	cloudDataFile := filepath.Join(targetDir, ".cloud_data")
	contentWithHeader := append([]byte(clientCloudDataHeader), b...)
	return os.WriteFile(cloudDataFile, contentWithHeader, 0644)
}

// LoadAllClientMeta scans all subdirectories in rootFolder and loads all .cloud_data files into manifest map
func LoadAllClientMeta(rootFolder string) map[string]TrackedFile {
	manifest := make(map[string]TrackedFile)
	if rootFolder == "" {
		return manifest
	}
	_ = filepath.Walk(rootFolder, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			rel, rErr := filepath.Rel(rootFolder, p)
			if rErr != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			if relSlash == "." {
				relSlash = ""
			}
			if strings.HasPrefix(relSlash, ".cloud_meta") || filepath.Base(p) == ".cloud_meta" {
				return filepath.SkipDir
			}
			cData := filepath.Join(p, ".cloud_data")
			if _, sErr := os.Stat(cData); sErr == nil {
				meta := loadClientDirMeta(rootFolder, relSlash)
				for baseName, fMeta := range meta.Files {
					fRel := baseName
					if relSlash != "" {
						fRel = filepath.ToSlash(filepath.Join(relSlash, baseName))
					}
					manifest[fRel] = TrackedFile{
						RelPath: fRel,
						ModTime: fMeta.ModTime,
						Size:    fMeta.Size,
						SHA256:  fMeta.SHA256,
						Deleted: false,
					}
				}
				for baseName, delTime := range meta.Deleted {
					fRel := baseName
					if relSlash != "" {
						fRel = filepath.ToSlash(filepath.Join(relSlash, baseName))
					}
					manifest[fRel] = TrackedFile{
						RelPath:   fRel,
						Deleted:   true,
						DeletedAt: delTime,
					}
				}
			}
		}
		return nil
	})
	return manifest
}

// RecordClientFileUpdate updates the per-folder .cloud_data file for a given file action
func RecordClientFileUpdate(rootFolder, relPath, action, clientID string, modTime, size int64, sha string) {
	if rootFolder == "" || relPath == "" {
		return
	}
	relSlash := filepath.ToSlash(relPath)
	relDir := filepath.Dir(relSlash)
	if relDir == "." {
		relDir = ""
	}
	baseName := filepath.Base(relSlash)
	meta := loadClientDirMeta(rootFolder, relDir)

	nowUnix := time.Now().Unix()
	if action == "deleted" {
		delete(meta.Files, baseName)
		if meta.Deleted == nil {
			meta.Deleted = make(map[string]int64)
		}
		meta.Deleted[baseName] = nowUnix
	} else {
		if meta.Deleted != nil {
			delete(meta.Deleted, baseName)
		}
		meta.Files[baseName] = ClientMetaFile{
			Path:        relSlash,
			Size:        size,
			ModTime:     modTime,
			SHA256:      sha,
			LastUpdated: time.Now().Format(time.RFC3339),
		}
	}

	meta.Ledger = append(meta.Ledger, ClientLedgerEntry{
		RelPath:   relSlash,
		Action:    action,
		Timestamp: nowUnix,
		ModTime:   modTime,
		Size:      size,
		SHA256:    sha,
		ClientID:  clientID,
		Details:   action + " on client",
	})

	_ = saveClientDirMeta(rootFolder, relDir, meta)
}
