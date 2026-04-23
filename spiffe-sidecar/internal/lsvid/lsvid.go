package lsvid

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

const maxNestingDepth = 16

// LSVID represents a parsed nested Lightweight SVID token.
type LSVID struct {
	Raw          string         // Full JWS compact serialization
	SigningInput string         // header.payload (for signature verification)
	Header       map[string]any // JOSE header (alg, typ, x5c)
	Payload      map[string]any // Claims (iss, sub, aud, iat, exp, jti, nested, ...)
	Signature    []byte         // Raw signature bytes
	Nested       *LSVID         // Prior level's LSVID (nil for L0)
}

// FromParts constructs an LSVID from its constituent parts.
func FromParts(raw, signingInput string, header, payload map[string]any, signature []byte, nested *LSVID) *LSVID {
	return &LSVID{
		Raw:          raw,
		SigningInput: signingInput,
		Header:       header,
		Payload:      payload,
		Signature:    signature,
		Nested:       nested,
	}
}

// Parse recursively parses a JWS compact serialization token into an LSVID.
func Parse(raw string) (*LSVID, error) {
	return parseWithDepth(raw, 0)
}

func parseWithDepth(raw string, depth int) (*LSVID, error) {
	if depth >= maxNestingDepth {
		return nil, fmt.Errorf("lsvid: max nesting depth %d exceeded", maxNestingDepth)
	}

	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("lsvid: invalid JWS compact serialization, expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := B64UrlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("lsvid: failed to decode header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("lsvid: failed to parse header JSON: %w", err)
	}

	payloadBytes, err := B64UrlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("lsvid: failed to decode payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("lsvid: failed to parse payload JSON: %w", err)
	}

	signature, err := B64UrlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("lsvid: failed to decode signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]

	var nested *LSVID
	if nestedRaw, ok := payload["nested"].(string); ok && nestedRaw != "" {
		nested, err = parseWithDepth(nestedRaw, depth+1)
		if err != nil {
			return nil, fmt.Errorf("lsvid: failed to parse nested token at depth %d: %w", depth+1, err)
		}
	}

	return &LSVID{
		Raw:          raw,
		SigningInput: signingInput,
		Header:       header,
		Payload:      payload,
		Signature:    signature,
		Nested:       nested,
	}, nil
}

// Level returns the nesting depth: 0 for base (L0), 1 for L1, etc.
func (l *LSVID) Level() int {
	if l.Nested == nil {
		return 0
	}
	return l.Nested.Level() + 1
}

// Chain returns the full chain root-first: [L0, L1, ..., self].
func (l *LSVID) Chain() []*LSVID {
	if l.Nested == nil {
		return []*LSVID{l}
	}
	return append(l.Nested.Chain(), l)
}

// Issuer returns the "iss" claim.
func (l *LSVID) Issuer() string {
	if v, ok := l.Payload["iss"].(string); ok {
		return v
	}
	return ""
}

// Subject returns the "sub" claim.
func (l *LSVID) Subject() string {
	if v, ok := l.Payload["sub"].(string); ok {
		return v
	}
	return ""
}

// Audience returns the "aud" claim.
func (l *LSVID) Audience() string {
	if v, ok := l.Payload["aud"].(string); ok {
		return v
	}
	return ""
}

// TokenID returns the "jti" claim.
func (l *LSVID) TokenID() string {
	if v, ok := l.Payload["jti"].(string); ok {
		return v
	}
	return ""
}

// ExpiresAt returns the "exp" claim as a Unix timestamp.
func (l *LSVID) ExpiresAt() int64 {
	return toInt64(l.Payload["exp"])
}

// IssuedAt returns the "iat" claim as a Unix timestamp.
func (l *LSVID) IssuedAt() int64 {
	return toInt64(l.Payload["iat"])
}

// LeafCertificatePEM returns the leaf certificate from x5c[0] in PEM format.
func (l *LSVID) LeafCertificatePEM() string {
	x5c, ok := l.Header["x5c"]
	if !ok {
		return ""
	}

	var b64Cert string
	switch arr := x5c.(type) {
	case []any:
		if len(arr) == 0 {
			return ""
		}
		b64Cert, ok = arr[0].(string)
		if !ok {
			return ""
		}
	case []string:
		if len(arr) == 0 {
			return ""
		}
		b64Cert = arr[0]
	default:
		return ""
	}

	derBytes, err := base64.StdEncoding.DecodeString(b64Cert)
	if err != nil {
		return ""
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// B64UrlEncode encodes bytes to base64url without padding.
func B64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// B64UrlDecode decodes a base64url string without padding.
func B64UrlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// toInt64 converts a JSON number (float64) to int64.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}
