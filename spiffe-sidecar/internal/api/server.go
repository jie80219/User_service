package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/lsvid"
)

// WatcherInfo provides health and identity information from the SVID watcher.
type WatcherInfo interface {
	GetCurrentMaterial() (*lsvid.SvidMaterial, error)
	IsReady() bool
}

// Server is a UDS-based HTTP server exposing the LSVID API.
type Server struct {
	socketPath string
	signer     *lsvid.Signer
	validator  *lsvid.Validator
	watcher    WatcherInfo
	listener   net.Listener
	httpServer *http.Server
}

// NewServer creates a new UDS API server.
func NewServer(socketPath string, signer *lsvid.Signer, validator *lsvid.Validator, watcher WatcherInfo) *Server {
	return &Server{
		socketPath: socketPath,
		signer:     signer,
		validator:  validator,
		watcher:    watcher,
	}
}

// Start removes any stale socket file, creates a Unix listener, registers
// routes, and serves HTTP. It blocks until the context is cancelled, at which
// point it performs a graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	// Remove stale socket file if it exists.
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	var err error
	s.listener, err = net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}

	// Make the socket accessible to other processes in the same pod/container.
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		log.Printf("[spiffe-sidecar] warning: failed to chmod socket: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/lsvid/create-base", s.handleCreateBase)
	mux.HandleFunc("/lsvid/extend", s.handleExtend)
	mux.HandleFunc("/lsvid/validate", s.handleValidate)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/identity", s.handleIdentity)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[spiffe-sidecar] api server shutdown error: %v", err)
		}
	}()

	log.Printf("[spiffe-sidecar] API server listening on unix://%s", s.socketPath)
	if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Close shuts down the server and removes the socket file.
func (s *Server) Close() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return err
		}
	}
	// Clean up socket file.
	os.Remove(s.socketPath)
	return nil
}
