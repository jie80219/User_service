package watcher

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/lsvid"
	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/shm"
)

// Callback is invoked whenever SVID material is rotated.
type Callback func(svids []shm.SvidSlot)

// Watcher wraps a go-spiffe X509Source and publishes SVID material to the
// SHM store so that PHP processes can read it via SpiffeTableReader.
type Watcher struct {
	socketPath string
	shmWriter  *shm.Writer
	spiffeID   string // optional filter; empty = accept all

	mu         sync.RWMutex
	x509Source *workloadapi.X509Source
	onRotation Callback
	current    []shm.SvidSlot
}

// New creates a Watcher. socketPath is the SPIRE Agent Workload API address
// (e.g. "unix:///run/spire/sockets/agent.sock"). If spiffeID is non-empty,
// only SVIDs matching that ID are published/returned.
func New(socketPath string, shmWriter *shm.Writer, spiffeID string) *Watcher {
	return &Watcher{
		socketPath: socketPath,
		shmWriter:  shmWriter,
		spiffeID:   spiffeID,
	}
}

// OnRotation registers a callback invoked after each successful SVID rotation.
func (w *Watcher) OnRotation(cb Callback) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onRotation = cb
}

// Start creates the X509Source and begins watching for SVID updates.
// It blocks until ctx is cancelled or an unrecoverable error occurs.
// Returns an error if the initial connection to the Workload API fails.
func (w *Watcher) Start(ctx context.Context) error {
	addr := normalizeSocketAddr(w.socketPath)

	_ = w.shmWriter.UpdateX509State("connecting")

	// When a SpiffeID filter is configured, pick the matching SVID as the
	// source's default. Without this, GetX509SVID() returns the first SVID
	// in the Workload API response, which is non-deterministic when multiple
	// workloads share the same selector (e.g. unix:uid:0).
	sourceOpts := []workloadapi.X509SourceOption{
		workloadapi.WithClientOptions(workloadapi.WithAddr(addr)),
	}
	if w.spiffeID != "" {
		wanted := w.spiffeID
		sourceOpts = append(sourceOpts, workloadapi.WithDefaultX509SVIDPicker(
			func(svids []*x509svid.SVID) *x509svid.SVID {
				for _, svid := range svids {
					if svid.ID.String() == wanted {
						return svid
					}
				}
				if len(svids) > 0 {
					return svids[0]
				}
				return nil
			},
		))
	}

	source, err := workloadapi.NewX509Source(ctx, sourceOpts...)
	if err != nil {
		_ = w.shmWriter.UpdateError(fmt.Sprintf("x509source init failed: %v", err))
		return fmt.Errorf("watcher: failed to create X509Source: %w", err)
	}

	w.mu.Lock()
	w.x509Source = source
	w.mu.Unlock()

	// Perform the initial publish from the source's current SVID.
	if err := w.publishFromSource(); err != nil {
		_ = w.shmWriter.UpdateError(fmt.Sprintf("initial publish failed: %v", err))
		_ = source.Close()
		return fmt.Errorf("watcher: initial SVID publish failed: %w", err)
	}

	_ = w.shmWriter.ClearError()

	// The X509Source automatically watches for rotations via the Workload API
	// streaming RPC. We poll the source in a loop to detect changes.
	go w.watchLoop(ctx)

	return nil
}

// GetCurrentMaterial returns the current SVID material suitable for LSVID
// signing. If spiffeID is set on the watcher, only the matching SVID is
// returned. Otherwise the first (primary) SVID is returned.
func (w *Watcher) GetCurrentMaterial() (*lsvid.SvidMaterial, error) {
	w.mu.RLock()
	source := w.x509Source
	w.mu.RUnlock()

	if source == nil {
		return nil, fmt.Errorf("watcher: X509Source not initialized")
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("watcher: failed to get X509-SVID: %w", err)
	}

	if w.spiffeID != "" && svid.ID.String() != w.spiffeID {
		return nil, fmt.Errorf("watcher: current SVID %s does not match filter %s", svid.ID.String(), w.spiffeID)
	}

	certPEM := encodeCertificates(svid.Certificates)
	keyPEM, err := encodePrivateKey(svid)
	if err != nil {
		return nil, fmt.Errorf("watcher: failed to encode private key: %w", err)
	}

	bundlePEM := ""
	bundle, bErr := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if bErr == nil && bundle != nil {
		bundlePEM = encodeCertificates(bundle.X509Authorities())
	}

	return &lsvid.SvidMaterial{
		SpiffeID:  svid.ID.String(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		BundlePEM: bundlePEM,
	}, nil
}

// Close shuts down the X509Source.
func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.x509Source != nil {
		err := w.x509Source.Close()
		w.x509Source = nil
		return err
	}
	return nil
}

// watchLoop polls the X509Source for SVID changes and re-publishes to SHM.
func (w *Watcher) watchLoop(ctx context.Context) {
	// The go-spiffe X509Source internally watches the Workload API stream
	// and caches the latest SVIDs. We detect rotation by comparing SVID
	// fingerprints on each poll cycle. WaitUntilUpdated blocks until the
	// source receives new material.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// WaitUntilUpdated blocks until the source detects a rotation.
		err := w.x509Source.WaitUntilUpdated(ctx)
		if err != nil {
			// Context cancelled — normal shutdown.
			if ctx.Err() != nil {
				return
			}
			_ = w.shmWriter.UpdateError(fmt.Sprintf("watch error: %v", err))
			continue
		}

		if err := w.publishFromSource(); err != nil {
			_ = w.shmWriter.UpdateError(fmt.Sprintf("rotation publish failed: %v", err))
			continue
		}

		_ = w.shmWriter.ClearError()
	}
}

// publishFromSource reads current SVIDs from the X509Source and publishes
// them to SHM.
func (w *Watcher) publishFromSource() error {
	w.mu.RLock()
	source := w.x509Source
	w.mu.RUnlock()

	if source == nil {
		return fmt.Errorf("X509Source not initialized")
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("failed to get X509-SVID: %w", err)
	}

	// Build bundle PEM from the source's trust bundle.
	bundlePEM := ""
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err == nil && bundle != nil {
		bundlePEM = encodeCertificates(bundle.X509Authorities())
	}

	slot := shm.SvidSlot{
		SpiffeID:    svid.ID.String(),
		TrustDomain: svid.ID.TrustDomain().String(),
		CertPEM:     encodeCertificates(svid.Certificates),
		KeyPEM:      mustEncodePrivateKey(svid),
		BundlePEM:   bundlePEM,
		Hint:        svid.Hint,
	}

	// Apply SPIFFE ID filter.
	slots := []shm.SvidSlot{slot}
	if w.spiffeID != "" && slot.SpiffeID != w.spiffeID {
		// The primary SVID doesn't match our filter — skip.
		slots = nil
	}

	if len(slots) > 0 {
		if err := w.shmWriter.PublishX509(slots); err != nil {
			return err
		}
	}

	w.mu.Lock()
	w.current = slots
	cb := w.onRotation
	w.mu.Unlock()

	if cb != nil && len(slots) > 0 {
		cb(slots)
	}

	return nil
}

// normalizeSocketAddr strips "unix://" prefix if present to produce a bare
// socket path suitable for workloadapi.WithAddr.
func normalizeSocketAddr(addr string) string {
	// go-spiffe expects the address with the unix:// scheme.
	if strings.HasPrefix(addr, "unix://") {
		return addr
	}
	// If someone passed just the path, add the scheme.
	if strings.HasPrefix(addr, "/") {
		return "unix://" + addr
	}
	return addr
}

// encodeCertificates encodes a slice of x509 certificates to PEM.
func encodeCertificates(certs []*x509.Certificate) string {
	var buf strings.Builder
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		_ = pem.Encode(&buf, block)
	}
	return buf.String()
}

// encodePrivateKey marshals the SVID's private key to PKCS#8 PEM.
func encodePrivateKey(svid *x509svid.SVID) (string, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// mustEncodePrivateKey is like encodePrivateKey but returns empty string on error.
func mustEncodePrivateKey(svid *x509svid.SVID) string {
	s, _ := encodePrivateKey(svid)
	return s
}
