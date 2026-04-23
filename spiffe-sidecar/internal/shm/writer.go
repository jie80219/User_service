package shm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// SvidSlot represents a single X.509-SVID stored in SHM.
// Field names and JSON keys are byte-compatible with the PHP SpiffeTableReader.
type SvidSlot struct {
	SpiffeID    string `json:"spiffe_id"`
	TrustDomain string `json:"trust_domain"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	BundlePEM   string `json:"bundle_pem"`
	Hint        string `json:"hint"`
	UpdatedAt   int64  `json:"updated_at"`
}

// Meta is the seqlock metadata file (meta.json) shared with PHP readers.
type Meta struct {
	Version   int64  `json:"version"`
	X509State string `json:"x509_state"`
	JwtState  string `json:"jwt_state"`
	X509Count int    `json:"x509_count"`
	JwtCount  int    `json:"jwt_count"`
	UpdatedAt int64  `json:"updated_at"`
	Error     string `json:"error"`
}

// Writer writes SPIFFE credentials to the SHM filesystem store using a
// seqlock protocol so that PHP readers never observe partial updates.
type Writer struct {
	baseDir string
}

// NewWriter creates a Writer targeting the given base directory.
func NewWriter(baseDir string) *Writer {
	return &Writer{baseDir: baseDir}
}

// PublishX509 writes X.509-SVIDs to SHM using the seqlock protocol:
//  1. Read current meta, increment version to odd (write-in-progress).
//  2. Write each SVID slot file atomically.
//  3. Remove stale slot files from a previous larger set.
//  4. Increment version to even (write-complete), update counts and timestamp.
func (w *Writer) PublishX509(svids []SvidSlot) error {
	meta, err := w.readMeta()
	if err != nil {
		return err
	}

	// Step 1: odd version = write in progress
	meta.Version++
	if err := w.writeMeta(meta); err != nil {
		return err
	}

	// Step 2: write each SVID slot
	now := time.Now().Unix()
	for i, svid := range svids {
		svid.UpdatedAt = now
		data, err := json.Marshal(svid)
		if err != nil {
			return fmt.Errorf("shm: failed to marshal SVID slot %d: %w", i, err)
		}
		path := filepath.Join(w.baseDir, "x509", fmt.Sprintf("%d.json", i))
		if err := AtomicWrite(path, data); err != nil {
			return err
		}
	}

	// Step 3: remove stale slots
	prevCount := meta.X509Count
	for i := len(svids); i < prevCount; i++ {
		path := filepath.Join(w.baseDir, "x509", fmt.Sprintf("%d.json", i))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("shm: failed to remove stale slot %d: %w", i, err)
		}
	}

	// Step 4: even version = write complete
	meta.Version++
	meta.X509Count = len(svids)
	meta.X509State = "ready"
	meta.UpdatedAt = now
	return w.writeMeta(meta)
}

// PublishJwtBundles writes JWT bundles to SHM using the seqlock protocol.
// The bundles map is keyed by trust domain, values are JWKS JSON strings.
func (w *Writer) PublishJwtBundles(bundles map[string]string) error {
	meta, err := w.readMeta()
	if err != nil {
		return err
	}

	// Odd version = write in progress
	meta.Version++
	if err := w.writeMeta(meta); err != nil {
		return err
	}

	now := time.Now().Unix()
	for td, jwksJSON := range bundles {
		slot := struct {
			TrustDomain string `json:"trust_domain"`
			JwksJSON    string `json:"jwks_json"`
			UpdatedAt   int64  `json:"updated_at"`
		}{
			TrustDomain: td,
			JwksJSON:    jwksJSON,
			UpdatedAt:   now,
		}
		data, err := json.Marshal(slot)
		if err != nil {
			return fmt.Errorf("shm: failed to marshal JWT bundle for %s: %w", td, err)
		}
		safeName := safeTrustDomainName(td)
		path := filepath.Join(w.baseDir, "jwt", safeName+".json")
		if err := AtomicWrite(path, data); err != nil {
			return err
		}
	}

	// Even version = write complete
	meta.Version++
	meta.JwtCount = len(bundles)
	meta.JwtState = "ready"
	meta.UpdatedAt = now
	return w.writeMeta(meta)
}

// UpdateX509State sets the x509_state field in meta.json.
func (w *Writer) UpdateX509State(state string) error {
	meta, err := w.readMeta()
	if err != nil {
		return err
	}
	meta.X509State = state
	return w.writeMeta(meta)
}

// UpdateJwtState sets the jwt_state field in meta.json.
func (w *Writer) UpdateJwtState(state string) error {
	meta, err := w.readMeta()
	if err != nil {
		return err
	}
	meta.JwtState = state
	return w.writeMeta(meta)
}

// UpdateError sets the error field in meta.json.
func (w *Writer) UpdateError(msg string) error {
	meta, err := w.readMeta()
	if err != nil {
		return err
	}
	meta.Error = msg
	return w.writeMeta(meta)
}

// ClearError clears the error field in meta.json.
func (w *Writer) ClearError() error {
	return w.UpdateError("")
}

// readMeta reads and parses meta.json, returning defaults if the file is
// missing or unparseable.
func (w *Writer) readMeta() (Meta, error) {
	path := filepath.Join(w.baseDir, "meta.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Meta{
				Version:   0,
				X509State: "idle",
				JwtState:  "idle",
			}, nil
		}
		return Meta{}, fmt.Errorf("shm: failed to read meta.json: %w", err)
	}

	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		// Corrupted meta — start fresh with version 0.
		return Meta{
			Version:   0,
			X509State: "idle",
			JwtState:  "idle",
		}, nil
	}
	return meta, nil
}

// writeMeta marshals and atomically writes meta.json.
func (w *Writer) writeMeta(meta Meta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("shm: failed to marshal meta: %w", err)
	}
	return AtomicWrite(filepath.Join(w.baseDir, "meta.json"), data)
}

var unsafeCharsRe = regexp.MustCompile(`[^a-z0-9._-]`)

// safeTrustDomainName converts a trust domain string to a safe filename:
// lowercase, replace any char not in [a-z0-9._-] with underscore.
func safeTrustDomainName(td string) string {
	lower := []byte(td)
	for i := range lower {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower[i] += 32
		}
	}
	return unsafeCharsRe.ReplaceAllString(string(lower), "_")
}
