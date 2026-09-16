// verify is the standalone stateless Verifier CLI described in Chapter 3
// (Section 3.5) and Chapter 4 (Section 4.4) of the dissertation.
//
// Usage (local):
//
//	go run ./cmd/verify --log_dir=./data/log --index=0 --leaf_hex=<hex>
//	go run ./cmd/verify --log_dir=./data/log --from=1 --to=3 --old_root=<hex>
//
// Usage (remote HTTP):
//
//	go run ./cmd/verify --log_url=http://localhost:8081 --index=0 --leaf_hex=<hex>
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
)

var (
	logDir  = flag.String("log_dir", "", "Local POSIX log directory.")
	logURL  = flag.String("log_url", "", "Base HTTP URL of remote tile server.")
	index   = flag.Int64("index", -1, "Log index for inclusion proof.")
	leafHex = flag.String("leaf_hex", "", "Hex RFC 6962 leaf hash for inclusion proof.")
	from    = flag.Int64("from", -1, "Earlier tree size for consistency proof.")
	to      = flag.Int64("to", -1, "Later tree size for consistency proof.")
	oldRoot = flag.String("old_root", "", "Hex root hash at --from size.")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	if (*logDir == "") == (*logURL == "") {
		fatalf("supply exactly one of --log_dir or --log_url")
	}

	var tileFetcher client.TileFetcherFunc
	var cpRaw []byte
	var err error

	if *logDir != "" {
		ff := client.FileFetcher{Root: *logDir}
		tileFetcher = ff.ReadTile
		cpRaw, err = ff.ReadCheckpoint(ctx)
		fmt.Printf("[verify] local log: %s\n", *logDir)
	} else {
		u, err2 := url.Parse(*logURL + "/")
		if err2 != nil {
			fatalf("parse log_url: %v", err2)
		}
		hf, err2 := client.NewHTTPFetcher(u, &http.Client{Timeout: 10 * time.Second})
		if err2 != nil {
			fatalf("http fetcher: %v", err2)
		}
		tileFetcher = hf.ReadTile
		cpRaw, err = hf.ReadCheckpoint(ctx)
		fmt.Printf("[verify] remote log: %s\n", *logURL)
	}
	if err != nil {
		fatalf("read checkpoint: %v", err)
	}

	var cp logfmt.Checkpoint
	if _, err := cp.Unmarshal(cpRaw); err != nil {
		fatalf("parse checkpoint: %v", err)
	}
	fmt.Printf("[verify] STH: size=%d  root=%x\n\n", cp.Size, cp.Hash)

	hasher := rfc6962.DefaultHasher

	if *index >= 0 {
		if *leafHex == "" {
			fatalf("--leaf_hex required for inclusion proof")
		}
		leafHash, err := hex.DecodeString(*leafHex)
		if err != nil {
			fatalf("decode leaf_hex: %v", err)
		}
		idx := uint64(*index)
		if idx >= cp.Size {
			fatalf("index %d out of range (size %d)", idx, cp.Size)
		}
		pb, err := client.NewProofBuilder(ctx, cp.Size, tileFetcher)
		if err != nil {
			fatalf("proof builder: %v", err)
		}
		incProof, err := pb.InclusionProof(ctx, idx)
		if err != nil {
			fatalf("build proof: %v", err)
		}
		if err := proof.VerifyInclusion(hasher, idx, cp.Size, leafHash, incProof, cp.Hash); err != nil {
			fmt.Printf("[verify] FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[verify] ✓ inclusion proof VERIFIED: index=%d in tree size=%d (%d hashes)\n",
			idx, cp.Size, len(incProof))
	}

	if *from >= 0 && *to >= 0 {
		if *oldRoot == "" {
			fatalf("--old_root required for consistency proof")
		}
		oldRootBytes, err := hex.DecodeString(*oldRoot)
		if err != nil {
			fatalf("decode old_root: %v", err)
		}
		fromSize, toSize := uint64(*from), uint64(*to)
		if toSize > cp.Size {
			fatalf("--to=%d exceeds current size %d", toSize, cp.Size)
		}
		var toRoot []byte
		if toSize == cp.Size {
			toRoot = cp.Hash
		} else {
			fatalf("--to must equal current tree size %d (stored checkpoint required otherwise)", cp.Size)
		}
		pb, err := client.NewProofBuilder(ctx, cp.Size, tileFetcher)
		if err != nil {
			fatalf("proof builder: %v", err)
		}
		consProof, err := pb.ConsistencyProof(ctx, fromSize, toSize)
		if err != nil {
			fatalf("build consistency proof: %v", err)
		}
		if err := proof.VerifyConsistency(hasher, fromSize, toSize, consProof, oldRootBytes, toRoot); err != nil {
			fmt.Printf("[verify] FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[verify] ✓ consistency proof VERIFIED: size %d → size %d (%d hashes)\n",
			fromSize, toSize, len(consProof))
	}

	if *index < 0 && (*from < 0 || *to < 0) {
		fmt.Println("[verify] No operation requested. Use --index or --from/--to.")
	}
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "verify: "+f+"\n", a...)
	os.Exit(1)
}

func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
