package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/api"
	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/config"
	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/lsvid"
	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/shm"
	"github.com/jie80219/zt-event-gateway/spiffe-sidecar/internal/watcher"
)

// watcherAdapter wraps watcher.Watcher to satisfy api.WatcherInfo.
type watcherAdapter struct {
	w *watcher.Watcher
}

func (a *watcherAdapter) GetCurrentMaterial() (*lsvid.SvidMaterial, error) {
	return a.w.GetCurrentMaterial()
}

func (a *watcherAdapter) IsReady() bool {
	_, err := a.w.GetCurrentMaterial()
	return err == nil
}

func main() {
	log.SetPrefix("[spiffe-sidecar] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// 1. Load and validate configuration.
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	log.Printf("loaded config: socket=%s, shm=%s, spiffe_id=%s, trust_domain=%s",
		cfg.SidecarSocket, cfg.ShmDir, cfg.SpiffeID, cfg.TrustDomain)

	// 2. Create SHM directory structure.
	if err := shm.CreateAll(cfg.ShmDir); err != nil {
		log.Fatalf("failed to create SHM directories: %v", err)
	}

	// 3. Create SHM writer.
	shmWriter := shm.NewWriter(cfg.ShmDir)

	// 4. Create watcher (connects to SPIRE Agent, watches SVIDs).
	w := watcher.New(cfg.SpiffeEndpointSocket, shmWriter, cfg.SpiffeID)

	// 5. Set up context with signal handling (SIGTERM, SIGINT).
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// 6. Start watcher in background (handles SPIRE Agent retry with backoff).
	go func() {
		log.Printf("starting SVID watcher, connecting to %s", cfg.SpiffeEndpointSocket)
		if err := w.Start(ctx); err != nil && err != context.Canceled {
			log.Printf("watcher stopped with error: %v", err)
		}
	}()

	// 7. Create MaterialProvider function.
	provider := lsvid.MaterialProvider(func() (*lsvid.SvidMaterial, error) {
		return w.GetCurrentMaterial()
	})

	// 8. Create LSVID signer.
	signer := lsvid.NewSigner(provider, cfg.LsvidTTLSeconds, cfg.CertExpiryGraceSeconds)

	// 9. Create LSVID validator.
	validator := lsvid.NewValidator(provider, cfg.ClockSkewSeconds, cfg.TrustDomain, cfg.RequireNbf, cfg.RequireAudienceOnAllLevels)

	// 10. Create adapter for the watcher to satisfy api.WatcherInfo interface.
	wa := &watcherAdapter{w: w}

	// 11. Create and start API server on UDS socket.
	apiServer := api.NewServer(cfg.SidecarSocket, signer, validator, wa)

	go func() {
		log.Printf("starting API server on unix://%s", cfg.SidecarSocket)
		if err := apiServer.Start(ctx); err != nil {
			log.Printf("API server stopped with error: %v", err)
		}
	}()

	// 12. Optionally start health HTTP server on TCP (separate from UDS).
	if cfg.HealthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			if wa.IsReady() {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`{"status":"ok"}`))
			} else {
				rw.WriteHeader(http.StatusServiceUnavailable)
				rw.Write([]byte(`{"status":"not_ready"}`))
			}
		})
		healthMux.HandleFunc("/readyz", func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			if wa.IsReady() {
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(`{"status":"ready"}`))
			} else {
				rw.WriteHeader(http.StatusServiceUnavailable)
				rw.Write([]byte(`{"status":"not_ready"}`))
			}
		})

		healthServer := &http.Server{
			Addr:    cfg.HealthAddr,
			Handler: healthMux,
		}

		go func() {
			log.Printf("starting health server on %s", cfg.HealthAddr)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("health server error: %v", err)
			}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			healthServer.Shutdown(shutdownCtx)
		}()
	}

	// 13. Wait for context done (signal received).
	<-ctx.Done()
	log.Printf("received shutdown signal, starting graceful shutdown...")

	// 14. Graceful shutdown: close API server, close watcher.
	if err := apiServer.Close(); err != nil {
		log.Printf("error closing API server: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Printf("error closing watcher: %v", err)
	}

	log.Printf("shutdown complete")
}
