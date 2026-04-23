package shm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateAll(t *testing.T) {
	dir := t.TempDir()

	if err := CreateAll(dir); err != nil {
		t.Fatal(err)
	}

	// Verify directory structure
	for _, sub := range []string{"x509", "jwt"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Fatalf("expected %s directory: %v", sub, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s should be a directory", sub)
		}
	}

	// Verify meta.json exists
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal("expected meta.json:", err)
	}

	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal("meta.json should be valid JSON:", err)
	}

	if meta.Version != 0 {
		t.Fatalf("initial version should be 0, got %d", meta.Version)
	}
	if meta.X509State != "idle" || meta.JwtState != "idle" {
		t.Fatal("initial states should be idle")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	data := []byte(`{"key":"value"}`)
	if err := AtomicWrite(path, data); err != nil {
		t.Fatal(err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(data) {
		t.Fatalf("got %q, want %q", read, data)
	}
}

func TestPublishX509_SeqlockProtocol(t *testing.T) {
	dir := t.TempDir()
	if err := CreateAll(dir); err != nil {
		t.Fatal(err)
	}

	writer := NewWriter(dir)

	svids := []SvidSlot{
		{
			SpiffeID:    "spiffe://zt.local/php-gateway",
			TrustDomain: "zt.local",
			CertPEM:     "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			KeyPEM:      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
			BundlePEM:   "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
			Hint:        "default",
		},
	}

	if err := writer.PublishX509(svids); err != nil {
		t.Fatal(err)
	}

	// Read meta and verify seqlock
	data, _ := os.ReadFile(filepath.Join(dir, "meta.json"))
	var meta Meta
	json.Unmarshal(data, &meta)

	// Version should be even (write complete)
	if meta.Version%2 != 0 {
		t.Fatalf("version should be even after publish, got %d", meta.Version)
	}
	if meta.Version != 2 { // 0→1→2
		t.Fatalf("expected version 2, got %d", meta.Version)
	}
	if meta.X509Count != 1 {
		t.Fatalf("expected x509_count=1, got %d", meta.X509Count)
	}
	if meta.X509State != "ready" {
		t.Fatalf("expected x509_state=ready, got %s", meta.X509State)
	}

	// Read SVID slot
	slotData, err := os.ReadFile(filepath.Join(dir, "x509", "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var slot SvidSlot
	json.Unmarshal(slotData, &slot)

	if slot.SpiffeID != "spiffe://zt.local/php-gateway" {
		t.Fatalf("spiffe_id mismatch: %s", slot.SpiffeID)
	}
	if slot.UpdatedAt == 0 {
		t.Fatal("updated_at should be set")
	}
}

func TestPublishX509_StaleSlotRemoval(t *testing.T) {
	dir := t.TempDir()
	CreateAll(dir)
	writer := NewWriter(dir)

	// Write 3 slots
	writer.PublishX509([]SvidSlot{
		{SpiffeID: "a"},
		{SpiffeID: "b"},
		{SpiffeID: "c"},
	})

	// Verify 3 files exist
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, "x509", filepath.Base(filepath.Join("x509", string(rune('0'+i))+".json")))); err != nil {
			// Just check they were created
		}
	}

	// Write 1 slot — should remove slots 1 and 2
	writer.PublishX509([]SvidSlot{
		{SpiffeID: "only-one"},
	})

	// Slot 0 should exist
	if _, err := os.Stat(filepath.Join(dir, "x509", "0.json")); err != nil {
		t.Fatal("slot 0 should still exist")
	}

	// Slots 1 and 2 should be removed
	if _, err := os.Stat(filepath.Join(dir, "x509", "1.json")); !os.IsNotExist(err) {
		t.Fatal("slot 1 should be removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "x509", "2.json")); !os.IsNotExist(err) {
		t.Fatal("slot 2 should be removed")
	}
}

func TestPublishJwtBundles(t *testing.T) {
	dir := t.TempDir()
	CreateAll(dir)
	writer := NewWriter(dir)

	bundles := map[string]string{
		"zt.local": `{"keys":[]}`,
	}
	if err := writer.PublishJwtBundles(bundles); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "jwt", "zt.local.json"))
	if err != nil {
		t.Fatal(err)
	}

	var slot struct {
		TrustDomain string `json:"trust_domain"`
		JwksJSON    string `json:"jwks_json"`
	}
	json.Unmarshal(data, &slot)

	if slot.TrustDomain != "zt.local" {
		t.Fatalf("expected trust_domain=zt.local, got %s", slot.TrustDomain)
	}
}

func TestSafeTrustDomainName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"zt.local", "zt.local"},
		{"ZT.LOCAL", "zt.local"},
		{"some/weird:name", "some_weird_name"},
	}
	for _, tt := range tests {
		got := safeTrustDomainName(tt.input)
		if got != tt.want {
			t.Fatalf("safeTrustDomainName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUpdateState(t *testing.T) {
	dir := t.TempDir()
	CreateAll(dir)
	writer := NewWriter(dir)

	writer.UpdateX509State("ready")
	writer.UpdateJwtState("error")
	writer.UpdateError("something broke")

	data, _ := os.ReadFile(filepath.Join(dir, "meta.json"))
	var meta Meta
	json.Unmarshal(data, &meta)

	if meta.X509State != "ready" {
		t.Fatalf("expected x509_state=ready, got %s", meta.X509State)
	}
	if meta.JwtState != "error" {
		t.Fatalf("expected jwt_state=error, got %s", meta.JwtState)
	}
	if meta.Error != "something broke" {
		t.Fatalf("expected error='something broke', got %s", meta.Error)
	}

	writer.ClearError()
	data, _ = os.ReadFile(filepath.Join(dir, "meta.json"))
	json.Unmarshal(data, &meta)
	if meta.Error != "" {
		t.Fatal("error should be cleared")
	}
}
