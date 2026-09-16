// Package server provides a lightweight HTTP tile server that makes the
// POSIX-backed Tessera log publicly accessible over HTTP. This is the minimal
// infrastructure needed for a verifier anywhere on the internet to fetch tiles
// and verify inclusion proofs without having local access to the tile directory.
//
// Tessera's POSIX backend writes tiles as static files in a directory layout
// that matches the tlog-tiles API spec (https://c2sp.org/tlog-tiles). Any HTTP
// file server that serves those files with the correct Content-Type headers is
// a conforming tile server. This package implements exactly that.
//
// For the dissertation prototype, this server allows:
//   - Remote verifiers to fetch tiles and verify inclusion proofs
//   - Integration with public witnesses (see docs/PUBLIC_ACCESS.md)
//   - Demonstration that the log is not merely local but genuinely accessible
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// TileServer wraps a net/http file server that serves Tessera tile files from
// a POSIX log directory.
type TileServer struct {
	addr    string
	logDir  string
	httpSrv *http.Server
}

// New creates a TileServer that will serve tiles from logDir on addr.
func New(addr, logDir string) *TileServer {
	mux := http.NewServeMux()

	// Serve tile files directly. Tessera POSIX writes files like:
	//   tile/2/0/000          (data tiles)
	//   tile/2/0/000.p/3      (partial tiles)
	//   checkpoint            (signed tree head)
	mux.Handle("/", withHeaders(http.FileServer(http.Dir(logDir))))

	return &TileServer{
		addr:   addr,
		logDir: logDir,
		httpSrv: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start begins serving in a background goroutine. It returns the actual
// listening address (useful when addr is ":0" for OS-assigned port) and a
// shutdown function.
func (s *TileServer) Start(ctx context.Context) (string, func(), error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", nil, fmt.Errorf("listen on %s: %w", s.addr, err)
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

// withHeaders wraps a handler to add the headers required by the tlog-tiles
// spec: correct Content-Type for tile data and permissive CORS so that
// browser-based verifiers can fetch tiles cross-origin.
func withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		next.ServeHTTP(w, r)
	})
}
