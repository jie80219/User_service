package lsvid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// ─── Test helpers ────────────────────────────────────────────────────────────

// testCA creates a self-signed CA certificate and key.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey
}

// testLeafSVID creates a leaf X.509-SVID signed by the given CA.
func testLeafSVID(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	spiffeURL, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeURL},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return leafCert, leafKey
}

// encodeCertPEM encodes a certificate to PEM.
func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// encodeKeyPEM encodes an ECDSA private key to PKCS8 PEM.
func encodeKeyPEM(key *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// testMaterial creates a complete SvidMaterial for testing.
func testMaterial(t *testing.T, spiffeID string) (*SvidMaterial, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	ca, caKey := testCA(t)
	leaf, leafKey := testLeafSVID(t, ca, caKey, spiffeID)

	mat := &SvidMaterial{
		SpiffeID:  spiffeID,
		CertPEM:   encodeCertPEM(leaf),
		KeyPEM:    encodeKeyPEM(leafKey),
		BundlePEM: encodeCertPEM(ca),
	}
	return mat, leaf, leafKey
}

// ─── LSVID Parse tests ──────────────────────────────────────────────────────

func TestParse_InvalidFormat(t *testing.T) {
	_, err := Parse("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestParse_InvalidBase64(t *testing.T) {
	_, err := Parse("!!!.!!!.!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestB64UrlRoundTrip(t *testing.T) {
	data := []byte("hello world 🌍")
	encoded := B64UrlEncode(data)
	decoded, err := B64UrlDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip failed: got %q, want %q", decoded, data)
	}
}

// ─── Signer tests ───────────────────────────────────────────────────────────

func TestCreateBase_L0(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")

	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	token, err := signer.CreateBase("spiffe://zt.local/php-worker", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if token.Level() != 0 {
		t.Fatalf("expected level 0, got %d", token.Level())
	}
	if token.Issuer() != "spiffe://zt.local/php-gateway" {
		t.Fatalf("expected issuer spiffe://zt.local/php-gateway, got %s", token.Issuer())
	}
	if token.Subject() != "spiffe://zt.local/php-gateway" {
		t.Fatalf("expected subject spiffe://zt.local/php-gateway, got %s", token.Subject())
	}
	if token.Audience() != "spiffe://zt.local/php-worker" {
		t.Fatalf("expected audience spiffe://zt.local/php-worker, got %s", token.Audience())
	}
	if token.TokenID() == "" {
		t.Fatal("expected non-empty JTI")
	}
	if token.ExpiresAt() == 0 {
		t.Fatal("expected non-zero exp")
	}
	if token.Nested != nil {
		t.Fatal("L0 should not have nested token")
	}
	if token.LeafCertificatePEM() == "" {
		t.Fatal("expected non-empty leaf certificate PEM")
	}
}

func TestCreateBase_WithSubject(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	token, err := signer.CreateBase("spiffe://zt.local/php-worker", "spiffe://zt.local/client", nil)
	if err != nil {
		t.Fatal(err)
	}

	if token.Subject() != "spiffe://zt.local/client" {
		t.Fatalf("expected subject spiffe://zt.local/client, got %s", token.Subject())
	}
}

func TestExtend_L1(t *testing.T) {
	gatewayMat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	workerMat, _, _ := testMaterial(t, "spiffe://zt.local/php-worker")

	gatewaySigner := NewSigner(func() (*SvidMaterial, error) { return gatewayMat, nil }, 1800, 60)
	workerSigner := NewSigner(func() (*SvidMaterial, error) { return workerMat, nil }, 1800, 60)

	l0, err := gatewaySigner.CreateBase("spiffe://zt.local/php-worker", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	l1, err := workerSigner.Extend(l0.Raw, "spiffe://zt.local/order-service", nil)
	if err != nil {
		t.Fatal(err)
	}

	if l1.Level() != 1 {
		t.Fatalf("expected level 1, got %d", l1.Level())
	}
	if l1.Issuer() != "spiffe://zt.local/php-worker" {
		t.Fatalf("expected issuer spiffe://zt.local/php-worker, got %s", l1.Issuer())
	}
	if l1.Audience() != "spiffe://zt.local/order-service" {
		t.Fatalf("expected audience spiffe://zt.local/order-service, got %s", l1.Audience())
	}
	if l1.Nested == nil {
		t.Fatal("L1 should have nested token")
	}
	if l1.Nested.Issuer() != "spiffe://zt.local/php-gateway" {
		t.Fatalf("nested issuer mismatch: %s", l1.Nested.Issuer())
	}

	// Verify chain
	chain := l1.Chain()
	if len(chain) != 2 {
		t.Fatalf("expected chain length 2, got %d", len(chain))
	}
	if chain[0].Issuer() != "spiffe://zt.local/php-gateway" {
		t.Fatal("chain[0] should be L0 (gateway)")
	}
	if chain[1].Issuer() != "spiffe://zt.local/php-worker" {
		t.Fatal("chain[1] should be L1 (worker)")
	}
}

func TestExtend_L2(t *testing.T) {
	gatewayMat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	workerMat, _, _ := testMaterial(t, "spiffe://zt.local/php-worker")

	gatewaySigner := NewSigner(func() (*SvidMaterial, error) { return gatewayMat, nil }, 1800, 60)
	workerSigner := NewSigner(func() (*SvidMaterial, error) { return workerMat, nil }, 1800, 60)

	l0, _ := gatewaySigner.CreateBase("spiffe://zt.local/php-worker", "", nil)
	l1, _ := workerSigner.Extend(l0.Raw, "spiffe://zt.local/php-worker", nil)
	l2, err := workerSigner.Extend(l1.Raw, "spiffe://zt.local/order-service", nil)
	if err != nil {
		t.Fatal(err)
	}

	if l2.Level() != 2 {
		t.Fatalf("expected level 2, got %d", l2.Level())
	}
	chain := l2.Chain()
	if len(chain) != 3 {
		t.Fatalf("expected chain length 3, got %d", len(chain))
	}
}

func TestSigner_ReservedClaimsStripped(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	extra := map[string]any{
		"iss":       "attacker",
		"sub":       "attacker",
		"exp":       999,
		"customKey": "customValue",
	}

	token, err := signer.CreateBase("spiffe://zt.local/php-worker", "", extra)
	if err != nil {
		t.Fatal(err)
	}

	// Reserved claims should be overwritten
	if token.Issuer() == "attacker" {
		t.Fatal("iss should not be attacker")
	}
	// Custom claims should be preserved
	if v, ok := token.Payload["customKey"].(string); !ok || v != "customValue" {
		t.Fatal("custom claim should be preserved")
	}
}

func TestSigner_ExpiredCert(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spiffeURL, _ := url.Parse("spiffe://zt.local/expired")
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour), // already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeURL},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	mat := &SvidMaterial{
		SpiffeID:  "spiffe://zt.local/expired",
		CertPEM:   encodeCertPEM(leafCert),
		KeyPEM:    encodeKeyPEM(leafKey),
		BundlePEM: encodeCertPEM(caCert),
	}

	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	_, err := signer.CreateBase("spiffe://zt.local/worker", "", nil)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
}

// ─── Validator tests ────────────────────────────────────────────────────────

func TestValidate_L0_Success(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	provider := func() (*SvidMaterial, error) { return mat, nil }

	signer := NewSigner(provider, 1800, 60)
	validator := NewValidator(provider, 30, "zt.local", false, true)

	token, err := signer.CreateBase("spiffe://zt.local/php-worker", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	validated, err := validator.Validate(token.Raw, "spiffe://zt.local/php-worker", "", "")
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if validated.Issuer() != "spiffe://zt.local/php-gateway" {
		t.Fatalf("expected issuer spiffe://zt.local/php-gateway, got %s", validated.Issuer())
	}
}

func TestValidate_L1_ChainContinuity(t *testing.T) {
	gatewayMat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	workerMat, _, _ := testMaterial(t, "spiffe://zt.local/php-worker")

	// Both use same CA for trust bundle
	ca, caKey := testCA(t)
	gwLeaf, gwKey := testLeafSVID(t, ca, caKey, "spiffe://zt.local/php-gateway")
	wkLeaf, wkKey := testLeafSVID(t, ca, caKey, "spiffe://zt.local/php-worker")

	gatewayMat = &SvidMaterial{
		SpiffeID:  "spiffe://zt.local/php-gateway",
		CertPEM:   encodeCertPEM(gwLeaf),
		KeyPEM:    encodeKeyPEM(gwKey),
		BundlePEM: encodeCertPEM(ca),
	}
	workerMat = &SvidMaterial{
		SpiffeID:  "spiffe://zt.local/php-worker",
		CertPEM:   encodeCertPEM(wkLeaf),
		KeyPEM:    encodeKeyPEM(wkKey),
		BundlePEM: encodeCertPEM(ca),
	}

	gatewaySigner := NewSigner(func() (*SvidMaterial, error) { return gatewayMat, nil }, 1800, 60)
	workerSigner := NewSigner(func() (*SvidMaterial, error) { return workerMat, nil }, 1800, 60)
	validator := NewValidator(func() (*SvidMaterial, error) { return workerMat, nil }, 30, "zt.local", false, true)

	l0, _ := gatewaySigner.CreateBase("spiffe://zt.local/php-worker", "", nil)
	l1, _ := workerSigner.Extend(l0.Raw, "spiffe://zt.local/order-service", nil)

	validated, err := validator.Validate(l1.Raw, "spiffe://zt.local/order-service", "", "")
	if err != nil {
		t.Fatalf("L1 validation failed: %v", err)
	}

	if validated.Level() != 1 {
		t.Fatalf("expected level 1, got %d", validated.Level())
	}
}

func TestValidate_AudienceMismatch(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	provider := func() (*SvidMaterial, error) { return mat, nil }

	signer := NewSigner(provider, 1800, 60)
	validator := NewValidator(provider, 30, "zt.local", false, true)

	token, _ := signer.CreateBase("spiffe://zt.local/php-worker", "", nil)

	_, err := validator.Validate(token.Raw, "spiffe://zt.local/wrong-audience", "", "")
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestValidate_SubjectMismatch(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	provider := func() (*SvidMaterial, error) { return mat, nil }

	signer := NewSigner(provider, 1800, 60)
	validator := NewValidator(provider, 30, "zt.local", false, true)

	token, _ := signer.CreateBase("spiffe://zt.local/php-worker", "", nil)

	_, err := validator.Validate(token.Raw, "", "spiffe://zt.local/wrong-subject", "")
	if err == nil {
		t.Fatal("expected subject mismatch error")
	}
}

func TestValidate_TrustDomainIsolation(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://evil.domain/attacker")
	provider := func() (*SvidMaterial, error) { return mat, nil }

	signer := NewSigner(provider, 1800, 60)
	validator := NewValidator(provider, 30, "zt.local", false, false)

	token, _ := signer.CreateBase("spiffe://evil.domain/target", "", nil)

	_, err := validator.Validate(token.Raw, "", "", "")
	if err == nil {
		t.Fatal("expected trust domain isolation error")
	}
}

// ─── JTI Cache tests ────────────────────────────────────────────────────────

func TestJtiCache_FirstSeen(t *testing.T) {
	cache := NewJtiCache()
	seen := cache.SeenOrRecord("jti-1", time.Now().Add(1*time.Hour).Unix())
	if seen {
		t.Fatal("first occurrence should not be seen")
	}
}

func TestJtiCache_ReplayDetected(t *testing.T) {
	cache := NewJtiCache()
	cache.SeenOrRecord("jti-1", time.Now().Add(1*time.Hour).Unix())

	seen := cache.SeenOrRecord("jti-1", time.Now().Add(1*time.Hour).Unix())
	if !seen {
		t.Fatal("replay should be detected")
	}
}

func TestJtiCache_ExpiredEviction(t *testing.T) {
	cache := NewJtiCache()
	// Record with past expiry
	cache.entries["old-jti"] = time.Now().Add(-1 * time.Hour).Unix()

	// New recording should evict the expired entry
	cache.SeenOrRecord("new-jti", time.Now().Add(1*time.Hour).Unix())

	if _, exists := cache.entries["old-jti"]; exists {
		t.Fatal("expired entry should have been evicted")
	}
}

func TestJtiCache_JTIReplayInValidator(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	provider := func() (*SvidMaterial, error) { return mat, nil }

	signer := NewSigner(provider, 1800, 60)
	validator := NewValidator(provider, 30, "zt.local", false, true)

	token, _ := signer.CreateBase("spiffe://zt.local/php-worker", "", nil)

	// First validation
	_, err := validator.Validate(token.Raw, "spiffe://zt.local/php-worker", "", "consumer")
	if err != nil {
		t.Fatalf("first validation should succeed: %v", err)
	}

	// Replay
	_, err = validator.Validate(token.Raw, "spiffe://zt.local/php-worker", "", "consumer")
	if err == nil {
		t.Fatal("replay should be rejected")
	}

	// Different cache ID should not detect replay
	_, err = validator.Validate(token.Raw, "spiffe://zt.local/php-worker", "", "other-consumer")
	if err != nil {
		t.Fatalf("different cache should not detect replay: %v", err)
	}

	// Empty cache ID should skip JTI check
	_, err = validator.Validate(token.Raw, "spiffe://zt.local/php-worker", "", "")
	if err != nil {
		t.Fatalf("empty cache ID should skip JTI check: %v", err)
	}
}

// ─── Parse roundtrip test ───────────────────────────────────────────────────

func TestParseRoundTrip(t *testing.T) {
	mat, _, _ := testMaterial(t, "spiffe://zt.local/php-gateway")
	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	original, _ := signer.CreateBase("spiffe://zt.local/php-worker", "", map[string]any{
		"traceId": "abc123",
	})

	parsed, err := Parse(original.Raw)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Issuer() != original.Issuer() {
		t.Fatalf("issuer mismatch: %s != %s", parsed.Issuer(), original.Issuer())
	}
	if parsed.Audience() != original.Audience() {
		t.Fatalf("audience mismatch: %s != %s", parsed.Audience(), original.Audience())
	}
	if parsed.TokenID() != original.TokenID() {
		t.Fatalf("jti mismatch")
	}

	// Verify x5c leaf cert can be parsed
	leafPEM := parsed.LeafCertificatePEM()
	if leafPEM == "" {
		t.Fatal("LeafCertificatePEM should not be empty")
	}
	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil {
		t.Fatal("failed to decode leaf PEM")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse leaf certificate:", err)
	}
}

// ─── ECDSA DER/JOSE roundtrip ──────────────────────────────────────────────

func TestECDSA_DER_JOSE_Roundtrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("test data for signing")

	// Sign
	sig, err := ecdsa.SignASN1(rand.Reader, key, data)
	if err != nil {
		t.Fatal(err)
	}

	// DER → JOSE
	jose, err := ecdsaDERToJOSE(sig, elliptic.P256())
	if err != nil {
		t.Fatal("DER→JOSE failed:", err)
	}

	if len(jose) != 64 { // P-256: 32+32
		t.Fatalf("expected 64 bytes, got %d", len(jose))
	}

	// JOSE → DER
	derAgain, err := ecdsaJOSEToDER(jose, elliptic.P256())
	if err != nil {
		t.Fatal("JOSE→DER failed:", err)
	}

	// Verify with DER
	if !ecdsa.VerifyASN1(&key.PublicKey, data, derAgain) {
		t.Fatal("signature verification failed after DER→JOSE→DER roundtrip")
	}
}

// ─── LeafCertificatePEM with non-standard x5c ──────────────────────────────

func TestLeafCertificatePEM_EmptyX5C(t *testing.T) {
	l := &LSVID{
		Header: map[string]any{},
	}
	if l.LeafCertificatePEM() != "" {
		t.Fatal("expected empty PEM for missing x5c")
	}

	l.Header["x5c"] = []any{}
	if l.LeafCertificatePEM() != "" {
		t.Fatal("expected empty PEM for empty x5c array")
	}
}

func TestLeafCertificatePEM_InvalidBase64(t *testing.T) {
	l := &LSVID{
		Header: map[string]any{
			"x5c": []any{"!!!not-base64!!!"},
		},
	}
	if l.LeafCertificatePEM() != "" {
		t.Fatal("expected empty PEM for invalid base64")
	}
}

// ─── SHM writer tests ──────────────────────────────────────────────────────

func TestSHMWriterSchema_X5C_Base64Standard(t *testing.T) {
	// Verify that x5c uses standard base64 (not URL-safe), matching PHP behavior
	mat, _, _ := testMaterial(t, "spiffe://zt.local/test")
	signer := NewSigner(func() (*SvidMaterial, error) { return mat, nil }, 1800, 60)

	token, _ := signer.CreateBase("spiffe://zt.local/worker", "", nil)

	x5cArr, ok := token.Header["x5c"].([]string)
	if !ok || len(x5cArr) == 0 {
		t.Fatal("x5c header should be []string with at least one entry")
	}

	// Verify it's standard base64 (can decode with StdEncoding)
	_, err := base64.StdEncoding.DecodeString(x5cArr[0])
	if err != nil {
		t.Fatalf("x5c should be standard base64, got error: %v", err)
	}
}
