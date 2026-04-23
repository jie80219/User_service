package lsvid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// SvidMaterial holds the current X.509-SVID material for signing.
type SvidMaterial struct {
	SpiffeID  string
	CertPEM   string
	KeyPEM    string
	BundlePEM string
}

// MaterialProvider is called on every sign operation to get fresh material.
type MaterialProvider func() (*SvidMaterial, error)

// Signer creates and extends LSVID tokens.
type Signer struct {
	provider          MaterialProvider
	defaultTTLSeconds int
	certGraceSeconds  int
}

// NewSigner creates a new Signer.
func NewSigner(provider MaterialProvider, ttl, grace int) *Signer {
	return &Signer{
		provider:          provider,
		defaultTTLSeconds: ttl,
		certGraceSeconds:  grace,
	}
}

// CreateBase mints a new L0 (base) LSVID token.
func (s *Signer) CreateBase(audience string, subject string, extraClaims map[string]any) (*LSVID, error) {
	claims := mergeClaims(extraClaims)
	if subject != "" {
		claims["sub"] = subject
	}
	return s.signInternal(claims, "", audience)
}

// Extend creates a new LSVID level on top of an existing token chain.
func (s *Signer) Extend(priorRawToken, audience string, extraClaims map[string]any) (*LSVID, error) {
	claims := mergeClaims(extraClaims)
	return s.signInternal(claims, priorRawToken, audience)
}

// Sign creates or extends an LSVID (backward compatibility).
func (s *Signer) Sign(claims map[string]any, priorRawToken, audience string) (*LSVID, error) {
	c := mergeClaims(claims)
	return s.signInternal(c, priorRawToken, audience)
}

// reservedClaims are stripped from extraClaims before signing.
var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true,
	"iat": true, "exp": true, "nbf": true,
	"jti": true, "nested": true,
}

func mergeClaims(extra map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range extra {
		if !reservedClaims[k] {
			out[k] = v
		}
	}
	return out
}

func (s *Signer) signInternal(claims map[string]any, priorRawToken, audience string) (*LSVID, error) {
	// 1. Get fresh material
	mat, err := s.provider()
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: failed to get SVID material: %w", err)
	}

	// 2. Parse private key
	privKey, err := parsePrivateKey(mat.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: %w", err)
	}

	// 3. Parse leaf certificate
	leafCert, leafDER, err := parseLeafCert(mat.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: %w", err)
	}

	// Check cert not expired (with grace period)
	now := time.Now()
	graceDuration := time.Duration(s.certGraceSeconds) * time.Second
	if leafCert.NotAfter.Before(now) {
		return nil, fmt.Errorf("lsvid/signer: leaf certificate has expired (notAfter=%s)", leafCert.NotAfter)
	}
	if leafCert.NotAfter.Add(-graceDuration).Before(now) {
		return nil, fmt.Errorf("lsvid/signer: refusing to sign: leaf certificate expires within grace period (notAfter=%s, grace=%ds)", leafCert.NotAfter, s.certGraceSeconds)
	}

	// 4. Pick algorithm
	alg, hashFunc, err := pickAlgorithm(privKey)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: %w", err)
	}

	// 5. Build header
	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	header := map[string]any{
		"alg": alg,
		"typ": "LSVID",
		"x5c": []string{leafB64},
	}

	// 6-7. Build payload
	payload := make(map[string]any)
	for k, v := range claims {
		payload[k] = v
	}
	payload["iss"] = mat.SpiffeID
	if _, ok := payload["sub"]; !ok {
		payload["sub"] = mat.SpiffeID
	}
	nowUnix := now.Unix()
	payload["iat"] = nowUnix
	payload["nbf"] = nowUnix
	payload["exp"] = nowUnix + int64(s.defaultTTLSeconds)
	payload["jti"] = uuid.New().String()
	if audience != "" {
		payload["aud"] = audience
	}
	if priorRawToken != "" {
		payload["nested"] = priorRawToken
	}

	// 8. Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: failed to marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: failed to marshal payload: %w", err)
	}
	headerB64 := B64UrlEncode(headerJSON)
	payloadB64 := B64UrlEncode(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	// 9. Sign
	sigBytes, err := signData(privKey, []byte(signingInput), alg, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("lsvid/signer: %w", err)
	}

	// 10. Build raw token
	sigB64 := B64UrlEncode(sigBytes)
	raw := signingInput + "." + sigB64

	// Parse nested LSVID if present
	var nested *LSVID
	if priorRawToken != "" {
		nested, err = Parse(priorRawToken)
		if err != nil {
			return nil, fmt.Errorf("lsvid/signer: failed to parse prior token: %w", err)
		}
	}

	return FromParts(raw, signingInput, header, payload, sigBytes, nested), nil
}

func parsePrivateKey(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("PKCS8 key does not implement crypto.Signer")
	}

	// Try EC private key
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecKey, nil
	}

	// Try PKCS1 RSA
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key (tried PKCS8, EC, PKCS1)")
}

func parseLeafCert(certPEM string) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, block.Bytes, nil
}

func pickAlgorithm(key crypto.Signer) (string, crypto.Hash, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RS256", crypto.SHA256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return "ES256", crypto.SHA256, nil
		case elliptic.P384():
			return "ES384", crypto.SHA384, nil
		case elliptic.P521():
			return "ES512", crypto.SHA512, nil
		default:
			return "", 0, fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	default:
		return "", 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

func signData(key crypto.Signer, data []byte, alg string, hashAlg crypto.Hash) ([]byte, error) {
	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hashAlg)
	}
	h.Write(data)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, hashAlg, digest)
	case *ecdsa.PrivateKey:
		derSig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("ECDSA sign failed: %w", err)
		}
		return ecdsaDERToJOSE(derSig, k.Curve)
	default:
		return nil, fmt.Errorf("unsupported key type for signing: %T", key)
	}
}

// ecdsaDERToJOSE converts an ASN.1 DER-encoded ECDSA signature to JOSE format (R||S).
func ecdsaDERToJOSE(derSig []byte, curve elliptic.Curve) ([]byte, error) {
	byteSize := curveByteSize(curve)

	// Parse ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }
	r, s, err := parseECDSADER(derSig)
	if err != nil {
		return nil, err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Left-pad each to curve byte size
	out := make([]byte, byteSize*2)
	copy(out[byteSize-len(rBytes):byteSize], rBytes)
	copy(out[2*byteSize-len(sBytes):], sBytes)

	return out, nil
}

func parseECDSADER(der []byte) (*big.Int, *big.Int, error) {
	// Minimal ASN.1 DER parser for SEQUENCE { INTEGER, INTEGER }
	if len(der) < 6 || der[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid DER sequence")
	}

	idx := 2
	// Handle long-form length
	if der[1]&0x80 != 0 {
		lenBytes := int(der[1] & 0x7f)
		idx = 2 + lenBytes
	}

	// Parse first INTEGER (r)
	if idx >= len(der) || der[idx] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for r")
	}
	idx++
	rLen := int(der[idx])
	idx++
	r := new(big.Int).SetBytes(der[idx : idx+rLen])
	idx += rLen

	// Parse second INTEGER (s)
	if idx >= len(der) || der[idx] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for s")
	}
	idx++
	sLen := int(der[idx])
	idx++
	s := new(big.Int).SetBytes(der[idx : idx+sLen])

	return r, s, nil
}

func curveByteSize(curve elliptic.Curve) int {
	bits := curve.Params().BitSize
	return (bits + 7) / 8
}
