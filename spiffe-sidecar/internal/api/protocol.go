package api

// CreateBaseRequest for POST /lsvid/create-base
type CreateBaseRequest struct {
	Audience    string         `json:"audience"`
	Subject     string         `json:"subject,omitempty"`
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`
	TTLSeconds  int            `json:"ttl_seconds,omitempty"`
}

// ExtendRequest for POST /lsvid/extend
type ExtendRequest struct {
	PriorToken  string         `json:"prior_token"`
	Audience    string         `json:"audience"`
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`
}

// ValidateRequest for POST /lsvid/validate
type ValidateRequest struct {
	RawToken         string `json:"raw_token"`
	ExpectedAudience string `json:"expected_audience,omitempty"`
	ExpectedSubject  string `json:"expected_subject,omitempty"`
	JtiCacheID       string `json:"jti_cache_id,omitempty"`
}

// LsvidResponse for sign/extend responses.
type LsvidResponse struct {
	Raw       string `json:"raw"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	Level     int    `json:"level"`
	ExpiresAt int64  `json:"expires_at"`
}

// ValidateResponse for validate responses.
type ValidateResponse struct {
	Valid       bool   `json:"valid"`
	Issuer      string `json:"issuer,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Level       int    `json:"level,omitempty"`
	ChainLength int    `json:"chain_length,omitempty"`
	Error       string `json:"error,omitempty"`
}

// HealthResponse for GET /health
type HealthResponse struct {
	Running    bool   `json:"running"`
	X509Ready  bool   `json:"x509_ready"`
	JwtReady   bool   `json:"jwt_ready"`
	SpiffeID   string `json:"spiffe_id"`
	ShmVersion int64  `json:"shm_version"`
}

// IdentityResponse for GET /identity
type IdentityResponse struct {
	SpiffeID     string `json:"spiffe_id"`
	TrustDomain  string `json:"trust_domain"`
	CertNotAfter int64  `json:"cert_not_after"`
}

// ErrorResponse for error cases.
type ErrorResponse struct {
	Error string `json:"error"`
}
