package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
)

// handleCreateBase handles POST /lsvid/create-base.
func (s *Server) handleCreateBase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CreateBaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Audience == "" {
		writeError(w, http.StatusBadRequest, "audience is required")
		return
	}

	token, err := s.signer.CreateBase(req.Audience, req.Subject, req.ExtraClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create base LSVID: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, LsvidResponse{
		Raw:       token.Raw,
		Issuer:    token.Issuer(),
		Subject:   token.Subject(),
		Level:     token.Level(),
		ExpiresAt: token.ExpiresAt(),
	})
}

// handleExtend handles POST /lsvid/extend.
func (s *Server) handleExtend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ExtendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.PriorToken == "" {
		writeError(w, http.StatusBadRequest, "prior_token is required")
		return
	}
	if req.Audience == "" {
		writeError(w, http.StatusBadRequest, "audience is required")
		return
	}

	token, err := s.signer.Extend(req.PriorToken, req.Audience, req.ExtraClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to extend LSVID: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, LsvidResponse{
		Raw:       token.Raw,
		Issuer:    token.Issuer(),
		Subject:   token.Subject(),
		Level:     token.Level(),
		ExpiresAt: token.ExpiresAt(),
	})
}

// handleValidate handles POST /lsvid/validate.
// Validation failure is not a server error; it returns HTTP 200 with Valid=false.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.RawToken == "" {
		writeError(w, http.StatusBadRequest, "raw_token is required")
		return
	}

	token, err := s.validator.Validate(req.RawToken, req.ExpectedAudience, req.ExpectedSubject, req.JtiCacheID)
	if err != nil {
		// Validation failure is not a server error.
		writeJSON(w, http.StatusOK, ValidateResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, ValidateResponse{
		Valid:       true,
		Issuer:      token.Issuer(),
		Subject:     token.Subject(),
		Level:       token.Level(),
		ChainLength: len(token.Chain()),
	})
}

// handleHealth handles GET /health.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp := HealthResponse{
		Running: true,
	}

	mat, err := s.watcher.GetCurrentMaterial()
	if err == nil && mat != nil {
		resp.X509Ready = mat.CertPEM != "" && mat.KeyPEM != ""
		resp.JwtReady = false // JWT source not yet implemented
		resp.SpiffeID = mat.SpiffeID
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleIdentity handles GET /identity.
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	mat, err := s.watcher.GetCurrentMaterial()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity not available: "+err.Error())
		return
	}
	if mat == nil {
		writeError(w, http.StatusServiceUnavailable, "no SVID material available")
		return
	}

	resp := IdentityResponse{
		SpiffeID: mat.SpiffeID,
	}

	// Extract trust domain from SPIFFE ID: spiffe://<trust-domain>/...
	if parts := strings.SplitN(mat.SpiffeID, "/", 4); len(parts) >= 3 {
		resp.TrustDomain = parts[2]
	}

	// Parse the leaf certificate to get NotAfter.
	if mat.CertPEM != "" {
		block, _ := pem.Decode([]byte(mat.CertPEM))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				resp.CertNotAfter = cert.NotAfter.Unix()
			} else {
				log.Printf("[spiffe-sidecar] warning: failed to parse leaf cert: %v", err)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[spiffe-sidecar] failed to encode JSON response: %v", err)
	}
}

// writeError writes an error JSON response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
