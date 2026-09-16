package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/transparency-dev/tessera"
)

// Server wraps the REST API handler and HTTP server.
type Server struct {
	addr    string
	httpSrv *http.Server
}

// NewServer creates a Server. The REST API endpoints are registered on
// specific paths; all other paths fall through to the static tile file server
// rooted at logDir. This allows Tessera's HTTPFetcher to request tile paths
// (e.g. /tile/0/000) directly from the same server as the REST API.
func NewServer(addr, logDir string, appender *tessera.Appender, reader tessera.LogReader) *Server {
	h := New(appender, reader, logDir)
	mux := http.NewServeMux()

	// Register REST API endpoints (specific paths take precedence in ServeMux).
	h.Register(mux)

	// Checkpoint endpoint: return raw checkpoint bytes at the canonical path
	// that Tessera's HTTPFetcher expects (/checkpoint).
	mux.HandleFunc("GET /checkpoint", func(w http.ResponseWriter, r *http.Request) {
		cpRaw, err := reader.ReadCheckpoint(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(cpRaw)
	})

	// Tile file server: serve the log directory at /, so that tile paths like
	// /tile/0/000 resolve correctly for Tessera's HTTPFetcher. REST endpoints
	// above take precedence due to Go ServeMux longest-prefix matching.
	mux.Handle("/", addCacheHeaders(http.FileServer(http.Dir(logDir))))

	return &Server{
		addr: addr,
		httpSrv: &http.Server{
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		},
	}
}

// Start begins serving in a background goroutine. Returns the listening
// address and a shutdown function.
func (s *Server) Start(ctx context.Context) (string, func(), error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", nil, fmt.Errorf("listen %s: %w", s.addr, err)
	}
	addr := ln.Addr().String()
	go func() { _ = s.httpSrv.Serve(ln) }()
	shutdown := func() {
		ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(ctx2)
	}
	return addr, shutdown, nil
}

func addCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		next.ServeHTTP(w, r)
	})
}
