package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all environment-based configuration for the sidecar.
type Config struct {
	// SPIRE Agent Workload API socket path.
	SpiffeEndpointSocket string

	// SHM directory for backward-compatible credential sharing with PHP.
	ShmDir string

	// Unix domain socket path for the LSVID API.
	SidecarSocket string

	// This workload's SPIFFE ID (used as issuer in LSVID tokens).
	SpiffeID string

	// Trust domain for trust-domain isolation checks.
	TrustDomain string

	// Default LSVID TTL in seconds.
	LsvidTTLSeconds int

	// Grace period: refuse to sign if cert expires within this many seconds.
	CertExpiryGraceSeconds int

	// Clock skew tolerance for LSVID validation (seconds).
	ClockSkewSeconds int

	// Whether to require nbf claim on all LSVID levels.
	RequireNbf bool

	// Whether to require audience on all LSVID levels.
	RequireAudienceOnAllLevels bool

	// Optional PEM output directory (empty = disabled).
	PemDir string

	// Health endpoint listen address (empty = disabled).
	HealthAddr string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		SpiffeEndpointSocket:       envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"),
		ShmDir:                     envOr("SPIFFE_SHM_DIR", "/tmp/spiffe-shared"),
		SidecarSocket:              envOr("SPIFFE_SIDECAR_SOCKET", "/tmp/spiffe-sidecar.sock"),
		SpiffeID:                   envOr("SPIFFE_ID", ""),
		TrustDomain:                envOr("SPIFFE_TRUST_DOMAIN", "zt.local"),
		LsvidTTLSeconds:            envInt("LSVID_TTL_SECONDS", 1800),
		CertExpiryGraceSeconds:     envInt("LSVID_CERT_GRACE_SECONDS", 60),
		ClockSkewSeconds:           envInt("LSVID_CLOCK_SKEW_SECONDS", 30),
		RequireNbf:                 envBool("LSVID_REQUIRE_NBF", false),
		RequireAudienceOnAllLevels: envBool("LSVID_REQUIRE_AUDIENCE_ALL_LEVELS", true),
		PemDir:                     envOr("SPIFFE_PEM_DIR", ""),
		HealthAddr:                 envOr("SPIFFE_HEALTH_ADDR", ":9901"),
	}
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.SpiffeEndpointSocket == "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET is required")
	}
	if c.ShmDir == "" {
		return fmt.Errorf("SPIFFE_SHM_DIR is required")
	}
	if c.SidecarSocket == "" {
		return fmt.Errorf("SPIFFE_SIDECAR_SOCKET is required")
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "yes"
}
