package lsvid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Validator validates LSVID tokens against a trust bundle.
type Validator struct {
	provider                   MaterialProvider
	clockSkewSeconds           int
	jtiCaches                  map[string]*JtiCache
	trustDomain                string
	requireNbf                 bool
	requireAudienceOnAllLevels bool
	mu                         sync.RWMutex

	// cached trust bundle
	bundleMu   sync.RWMutex
	bundleHash string
	bundleCAs  []*x509.Certificate
}

// NewValidator creates a new Validator.
func NewValidator(provider MaterialProvider, clockSkew int, trustDomain string, requireNbf, requireAudAll bool) *Validator {
	return &Validator{
		provider:                   provider,
		clockSkewSeconds:           clockSkew,
		jtiCaches:                  make(map[string]*JtiCache),
		trustDomain:                trustDomain,
		requireNbf:                 requireNbf,
		requireAudienceOnAllLevels: requireAudAll,
	}
}

// Validate parses and validates an LSVID token.
func (v *Validator) Validate(rawToken, expectedAudience, expectedSubject, jtiCacheID string) (*LSVID, error) {
	// 1. Parse token
	token, err := Parse(rawToken)
	if err != nil {
		return nil, fmt.Errorf("lsvid/validator: parse failed: %w", err)
	}

	// 2. Load trust bundle CAs
	cas, err := v.loadTrustBundle()
	if err != nil {
		return nil, fmt.Errorf("lsvid/validator: failed to load trust bundle: %w", err)
	}

	// 3. Walk chain root-first
	chain := token.Chain()
	for i, level := range chain {
		if err := v.verifyLevel(level, cas); err != nil {
			return nil, fmt.Errorf("lsvid/validator: verification failed at level %d: %w", i, err)
		}

		// 4. Chain continuity: for i>0, nested.aud must equal enclosing level's iss
		if i > 0 {
			prev := chain[i-1]
			if prev.Audience() != level.Issuer() {
				return nil, fmt.Errorf("lsvid/validator: chain continuity broken at level %d: nested aud=%q != enclosing iss=%q",
					i, prev.Audience(), level.Issuer())
			}
		}
	}

	// 5. requireAudienceOnAllLevels: outermost must have aud
	if v.requireAudienceOnAllLevels && token.Audience() == "" {
		return nil, fmt.Errorf("lsvid/validator: outermost level missing audience")
	}

	// 6. Expected audience check on outermost
	if expectedAudience != "" && token.Audience() != expectedAudience {
		return nil, fmt.Errorf("lsvid/validator: audience mismatch: got %q, expected %q", token.Audience(), expectedAudience)
	}

	// 7. Expected subject check on L0
	if expectedSubject != "" {
		l0 := chain[0]
		if l0.Subject() != expectedSubject {
			return nil, fmt.Errorf("lsvid/validator: L0 subject mismatch: got %q, expected %q", l0.Subject(), expectedSubject)
		}
	}

	// 8. JTI replay check on outermost
	if jtiCacheID != "" {
		jti := token.TokenID()
		if jti != "" {
			cache := v.getOrCreateCache(jtiCacheID)
			if cache.SeenOrRecord(jti, token.ExpiresAt()) {
				return nil, fmt.Errorf("lsvid/validator: JTI replay detected: %s", jti)
			}
		}
	}

	return token, nil
}

func (v *Validator) getOrCreateCache(id string) *JtiCache {
	v.mu.RLock()
	cache, ok := v.jtiCaches[id]
	v.mu.RUnlock()
	if ok {
		return cache
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	// Double-check
	if cache, ok = v.jtiCaches[id]; ok {
		return cache
	}
	cache = NewJtiCache()
	v.jtiCaches[id] = cache
	return cache
}

func (v *Validator) loadTrustBundle() ([]*x509.Certificate, error) {
	mat, err := v.provider()
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256([]byte(mat.BundlePEM))
	hashStr := fmt.Sprintf("%x", h)

	v.bundleMu.RLock()
	if v.bundleHash == hashStr && v.bundleCAs != nil {
		cas := v.bundleCAs
		v.bundleMu.RUnlock()
		return cas, nil
	}
	v.bundleMu.RUnlock()

	// Parse bundle
	cas, err := parseCertBundle(mat.BundlePEM)
	if err != nil {
		return nil, err
	}

	v.bundleMu.Lock()
	v.bundleHash = hashStr
	v.bundleCAs = cas
	v.bundleMu.Unlock()

	return cas, nil
}

func parseCertBundle(bundlePEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(bundlePEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in trust bundle")
	}
	return certs, nil
}

func (v *Validator) verifyLevel(level *LSVID, cas []*x509.Certificate) error {
	now := time.Now()
	skew := time.Duration(v.clockSkewSeconds) * time.Second

	// 1. Required claims
	for _, claim := range []string{"iss", "sub", "iat", "exp", "jti"} {
		val, ok := level.Payload[claim]
		if !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
		if s, isStr := val.(string); isStr && s == "" {
			return fmt.Errorf("empty required claim: %s", claim)
		}
	}

	// 2. requireNbf
	if v.requireNbf {
		if _, ok := level.Payload["nbf"]; !ok {
			return fmt.Errorf("missing required claim: nbf")
		}
	}

	// 3. Parse leaf cert from x5c[0]
	leafCert, err := parseX5CLeaf(level.Header)
	if err != nil {
		return fmt.Errorf("x5c parse failed: %w", err)
	}

	// 4. Verify leaf cert signed by at least one CA
	caVerified := false
	for _, ca := range cas {
		if err := leafCert.CheckSignatureFrom(ca); err == nil {
			caVerified = true
			break
		}
	}
	if !caVerified {
		return fmt.Errorf("leaf certificate not signed by any trusted CA")
	}

	// 5. Certificate temporal validity
	if now.Before(leafCert.NotBefore.Add(-skew)) {
		return fmt.Errorf("leaf certificate not yet valid (notBefore: %s)", leafCert.NotBefore)
	}
	if now.After(leafCert.NotAfter.Add(skew)) {
		return fmt.Errorf("leaf certificate expired (notAfter: %s)", leafCert.NotAfter)
	}

	// 6. Verify JWS signature
	if err := v.verifySignature(level, leafCert); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 7. Temporal checks on claims
	iat := level.IssuedAt()
	exp := level.ExpiresAt()
	if iat > 0 && now.Before(time.Unix(iat, 0).Add(-skew)) {
		return fmt.Errorf("token issued in the future (iat: %d)", iat)
	}
	if exp > 0 && now.After(time.Unix(exp, 0).Add(skew)) {
		return fmt.Errorf("token expired (exp: %d)", exp)
	}
	// nbf check: always validate if present, but only require it if configured
	if nbfVal, ok := level.Payload["nbf"]; ok {
		nbf := toInt64(nbfVal)
		if nbf > 0 && now.Before(time.Unix(nbf, 0).Add(-skew)) {
			return fmt.Errorf("token not yet valid (nbf: %d)", nbf)
		}
	}

	// 8. URI SAN continuity
	if len(leafCert.URIs) > 0 {
		certSAN := leafCert.URIs[0].String()
		if certSAN != level.Issuer() {
			return fmt.Errorf("URI SAN %q does not match issuer %q", certSAN, level.Issuer())
		}
	}

	// 9. Trust domain isolation
	if v.trustDomain != "" {
		prefix := "spiffe://" + v.trustDomain + "/"
		if !strings.HasPrefix(level.Issuer(), prefix) {
			return fmt.Errorf("issuer %q not in trust domain %q", level.Issuer(), v.trustDomain)
		}
		if !strings.HasPrefix(level.Subject(), prefix) {
			return fmt.Errorf("subject %q not in trust domain %q", level.Subject(), v.trustDomain)
		}
		if aud := level.Audience(); aud != "" && !strings.HasPrefix(aud, prefix) {
			return fmt.Errorf("audience %q not in trust domain %q", aud, v.trustDomain)
		}
	}

	return nil
}

func parseX5CLeaf(header map[string]any) (*x509.Certificate, error) {
	x5c, ok := header["x5c"]
	if !ok {
		return nil, fmt.Errorf("missing x5c header")
	}

	var leafB64 string
	switch arr := x5c.(type) {
	case []any:
		if len(arr) == 0 {
			return nil, fmt.Errorf("empty x5c array")
		}
		leafB64, ok = arr[0].(string)
		if !ok {
			return nil, fmt.Errorf("x5c[0] is not a string")
		}
	case []string:
		if len(arr) == 0 {
			return nil, fmt.Errorf("empty x5c array")
		}
		leafB64 = arr[0]
	default:
		return nil, fmt.Errorf("x5c is not an array")
	}

	der, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x5c[0]: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return cert, nil
}

func (v *Validator) verifySignature(level *LSVID, leafCert *x509.Certificate) error {
	alg, ok := level.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid alg header")
	}

	var hashAlg crypto.Hash
	switch alg {
	case "RS256", "ES256":
		hashAlg = crypto.SHA256
	case "ES384":
		hashAlg = crypto.SHA384
	case "ES512":
		hashAlg = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	}
	h.Write([]byte(level.SigningInput))
	digest := h.Sum(nil)

	switch strings.HasPrefix(alg, "RS") {
	case true:
		// RSA
		pub, ok := leafCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key for %s", alg)
		}
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, level.Signature)
	default:
		// ECDSA
		pub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ECDSA public key for %s", alg)
		}
		derSig, err := ecdsaJOSEToDER(level.Signature, pub.Curve)
		if err != nil {
			return fmt.Errorf("failed to convert JOSE signature to DER: %w", err)
		}
		if !ecdsa.VerifyASN1(pub, digest, derSig) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	}
}

// ecdsaJOSEToDER converts a JOSE-format ECDSA signature (R||S) to ASN.1 DER.
func ecdsaJOSEToDER(sig []byte, curve elliptic.Curve) ([]byte, error) {
	byteSize := curveByteSize(curve)
	if len(sig) != byteSize*2 {
		return nil, fmt.Errorf("invalid JOSE signature length: got %d, expected %d", len(sig), byteSize*2)
	}

	r := new(big.Int).SetBytes(sig[:byteSize])
	s := new(big.Int).SetBytes(sig[byteSize:])

	// Encode as ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }
	rBytes := integerDER(r)
	sBytes := integerDER(s)

	seqContent := append(rBytes, sBytes...)
	seq := []byte{0x30}
	seq = appendDERLength(seq, len(seqContent))
	seq = append(seq, seqContent...)

	return seq, nil
}

// integerDER encodes a big.Int as a DER INTEGER.
func integerDER(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	// Prepend 0x00 if high bit is set
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	result := []byte{0x02}
	result = appendDERLength(result, len(b))
	result = append(result, b...)
	return result
}

// appendDERLength appends a DER length encoding.
func appendDERLength(buf []byte, length int) []byte {
	if length < 128 {
		return append(buf, byte(length))
	}
	if length < 256 {
		return append(buf, 0x81, byte(length))
	}
	return append(buf, 0x82, byte(length>>8), byte(length))
}
