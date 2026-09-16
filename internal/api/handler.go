// Package api implements the four REST endpoints described in Chapter 3
// (Section 3.5, Table 3.3) and Chapter 4 (Section 4.4) of the dissertation.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
)

// Handler holds dependencies shared across all REST endpoints.
type Handler struct {
	appender *tessera.Appender
	reader   tessera.LogReader
	fetcher  client.FileFetcher
	awaiter  *tessera.PublicationAwaiter
}

// New creates a Handler wired to the given Tessera appender and reader.
func New(appender *tessera.Appender, reader tessera.LogReader, logDir string) *Handler {
	ctx := context.Background()
	return &Handler{
		appender: appender,
		reader:   reader,
		fetcher:  client.FileFetcher{Root: logDir},
		awaiter:  tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 200*time.Millisecond),
	}
}

// Register installs all four endpoints on the given ServeMux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /token/submit", h.handleSubmit)
	mux.HandleFunc("GET /token/prove", h.handleProve)
	mux.HandleFunc("GET /log/sth", h.handleSTH)
	mux.HandleFunc("GET /log/consistency", h.handleConsistency)
}

// ── POST /token/submit ────────────────────────────────────────────────────────

type submitRequest  struct{ Data string `json:"data"` }
type submitResponse struct {
	Index    uint64 `json:"index"`
	LeafHash string `json:"leaf_hash"`
	TreeSize uint64 `json:"tree_size"`
	Root     string `json:"root"`
}

func (h *Handler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid body: %v", err), http.StatusBadRequest)
		return
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil || len(tokenBytes) == 0 {
		http.Error(w, "invalid or empty data field", http.StatusBadRequest)
		return
	}

	leafHash := rfc6962LeafHash(tokenBytes)

	future := h.appender.Add(r.Context(), tessera.NewEntry(tokenBytes))
	idx, cpRaw, err := h.awaiter.Await(r.Context(), future)
	if err != nil {
		http.Error(w, fmt.Sprintf("append: %v", err), http.StatusInternalServerError)
		return
	}
	var cp logfmt.Checkpoint
	if _, err := cp.Unmarshal(cpRaw); err != nil {
		http.Error(w, fmt.Sprintf("checkpoint: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, submitResponse{
		Index: idx.Index, LeafHash: hex.EncodeToString(leafHash),
		TreeSize: cp.Size, Root: hex.EncodeToString(cp.Hash),
	})
}

// ── GET /token/prove?index=N ─────────────────────────────────────────────────

type proveResponse struct {
	Index    uint64   `json:"index"`
	TreeSize uint64   `json:"tree_size"`
	Root     string   `json:"root"`
	Proof    []string `json:"proof"`
}

func (h *Handler) handleProve(w http.ResponseWriter, r *http.Request) {
	idx, err := parseUint(r, "index")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cp, cpErr := h.readCP(r.Context())
	if cpErr != nil {
		http.Error(w, cpErr.Error(), http.StatusInternalServerError)
		return
	}
	if idx >= cp.Size {
		http.Error(w, fmt.Sprintf("index %d out of range (size %d)", idx, cp.Size), http.StatusNotFound)
		return
	}
	pb, err := client.NewProofBuilder(r.Context(), cp.Size, h.fetcher.ReadTile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	incProof, err := pb.InclusionProof(r.Context(), idx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, proveResponse{
		Index: idx, TreeSize: cp.Size, Root: hex.EncodeToString(cp.Hash),
		Proof: hexSlice(incProof),
	})
}

// ── GET /log/sth ─────────────────────────────────────────────────────────────

type sthResponse struct {
	Size       uint64 `json:"size"`
	Root       string `json:"root"`
	Checkpoint string `json:"checkpoint"`
}

func (h *Handler) handleSTH(w http.ResponseWriter, r *http.Request) {
	cpRaw, err := h.reader.ReadCheckpoint(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var cp logfmt.Checkpoint
	if _, err := cp.Unmarshal(cpRaw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, sthResponse{
		Size: cp.Size, Root: hex.EncodeToString(cp.Hash),
		Checkpoint: base64.StdEncoding.EncodeToString(cpRaw),
	})
}

// ── GET /log/consistency?from=M&to=N ─────────────────────────────────────────

type consistencyResponse struct {
	From    uint64   `json:"from"`
	To      uint64   `json:"to"`
	NewRoot string   `json:"new_root"`
	Proof   []string `json:"proof"`
}

func (h *Handler) handleConsistency(w http.ResponseWriter, r *http.Request) {
	from, err1 := parseUint(r, "from")
	to, err2 := parseUint(r, "to")
	if err1 != nil || err2 != nil {
		http.Error(w, "missing or invalid ?from=M&to=N", http.StatusBadRequest)
		return
	}
	if from >= to {
		http.Error(w, "from must be less than to", http.StatusBadRequest)
		return
	}
	cp, cpErr := h.readCP(r.Context())
	if cpErr != nil {
		http.Error(w, cpErr.Error(), http.StatusInternalServerError)
		return
	}
	if to > cp.Size {
		http.Error(w, fmt.Sprintf("to=%d exceeds tree size %d", to, cp.Size), http.StatusBadRequest)
		return
	}
	pb, err := client.NewProofBuilder(r.Context(), cp.Size, h.fetcher.ReadTile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	consProof, err := pb.ConsistencyProof(r.Context(), from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, consistencyResponse{
		From: from, To: to,
		NewRoot: hex.EncodeToString(cp.Hash),
		Proof:   hexSlice(consProof),
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) readCP(ctx context.Context) (logfmt.Checkpoint, error) {
	cpRaw, err := h.reader.ReadCheckpoint(ctx)
	if err != nil {
		return logfmt.Checkpoint{}, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp logfmt.Checkpoint
	if _, err := cp.Unmarshal(cpRaw); err != nil {
		return logfmt.Checkpoint{}, fmt.Errorf("parse checkpoint: %w", err)
	}
	return cp, nil
}

func parseUint(r *http.Request, name string) (uint64, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return 0, fmt.Errorf("missing ?%s", name)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %v", name, err)
	}
	return v, nil
}

func hexSlice(in [][]byte) []string {
	out := make([]string, len(in))
	for i, b := range in { out[i] = hex.EncodeToString(b) }
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// rfc6962LeafHash computes the RFC 6962 leaf hash (0x00 prefix + SHA-256).
// This must match rfc6962.DefaultHasher.HashLeaf used in the Tessera log.
func rfc6962LeafHash(data []byte) []byte {
	b := make([]byte, 1+len(data))
	b[0] = 0x00
	copy(b[1:], data)
	h := sha256.Sum256(b)
	return h[:]
}
