package shm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultBaseDir is the default SHM directory shared with PHP processes.
const DefaultBaseDir = "/tmp/spiffe-shared"

// CreateAll creates the SHM directory tree (baseDir, baseDir/x509, baseDir/jwt)
// and writes an initial meta.json if one does not already exist.
func CreateAll(baseDir string) error {
	dirs := []string{
		baseDir,
		filepath.Join(baseDir, "x509"),
		filepath.Join(baseDir, "jwt"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("shm: failed to create directory %s: %w", d, err)
		}
	}

	metaPath := filepath.Join(baseDir, "meta.json")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		initial := Meta{
			Version:   0,
			X509State: "idle",
			JwtState:  "idle",
			X509Count: 0,
			JwtCount:  0,
			UpdatedAt: 0,
			Error:     "",
		}
		data, err := json.Marshal(initial)
		if err != nil {
			return fmt.Errorf("shm: failed to marshal initial meta: %w", err)
		}
		if err := AtomicWrite(metaPath, data); err != nil {
			return fmt.Errorf("shm: failed to write initial meta.json: %w", err)
		}
	}

	return nil
}

// Cleanup removes all files in the x509/ and jwt/ subdirectories of baseDir.
// The directories themselves are preserved.
func Cleanup(baseDir string) error {
	for _, sub := range []string{"x509", "jwt"} {
		dir := filepath.Join(baseDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("shm: failed to read directory %s: %w", dir, err)
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("shm: failed to remove %s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// AtomicWrite writes data to path atomically: write to a temp file in the same
// directory, fsync the file, rename to the target, then fsync the parent
// directory. Readers never see partial content.
func AtomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".shm-tmp-*")
	if err != nil {
		return fmt.Errorf("shm: failed to create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// Ensure cleanup on any failure path.
	success := false
	defer func() {
		if !success {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("shm: failed to write temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("shm: failed to fsync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("shm: failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("shm: failed to rename %s → %s: %w", tmpName, path, err)
	}

	// Fsync the parent directory to ensure the rename is durable.
	parentDir, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("shm: failed to open parent dir %s: %w", dir, err)
	}
	defer parentDir.Close()

	if err := parentDir.Sync(); err != nil {
		return fmt.Errorf("shm: failed to fsync parent dir %s: %w", dir, err)
	}

	success = true
	return nil
}
