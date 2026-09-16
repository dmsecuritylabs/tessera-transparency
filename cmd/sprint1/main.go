// sprint1 is the first milestone program for the dissertation prototype.
// It establishes a local POSIX-backed Tessera log, appends a single leaf,
// and verifies an inclusion proof for that leaf end-to-end. This is the
// Sprint 1 exit criterion described in the implementation plan (Ch.4 §4.1).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
)

var storageDir = flag.String("storage_dir", "/home/claude/tessera-transparency/data/log1", "Root directory to store log data.")

func main() {
	flag.Parse()
	ctx := context.Background()

	if err := os.RemoveAll(*storageDir); err != nil {
		fmt.Printf("warning: could not clean storage dir: %v\n", err)
	}
	if err := os.MkdirAll(*storageDir, 0o755); err != nil {
		panic(err)
	}

	skey, vkey, err := note.GenerateKey(nil, "dissertation-prototype-log")
	if err != nil {
		panic(fmt.Sprintf("GenerateKey: %v", err))
	}
	fmt.Printf("Generated log keypair.\nPublic verifier key: %s\n\n", vkey)

	signer, err := note.NewSigner(skey)
	if err != nil {
		panic(fmt.Sprintf("NewSigner: %v", err))
	}

	driver, err := posix.New(ctx, posix.Config{Path: *storageDir})
	if err != nil {
		panic(fmt.Sprintf("posix.New: %v", err))
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(1, 100*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)

	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		panic(fmt.Sprintf("NewAppender: %v", err))
	}

	leafData := []byte("dissertation-prototype: first leaf, sprint 1 milestone")
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(leafData)
	fmt.Printf("Appending leaf. RFC6962 leaf hash = %x\n", leafHash)

	future := appender.Add(ctx, tessera.NewEntry(leafData))

	await := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 100*time.Millisecond)
	idx, cpRaw, err := await.Await(ctx, future)
	if err != nil {
		panic(fmt.Sprintf("Await: %v", err))
	}
	fmt.Printf("Leaf sequenced at index: %d\n", idx.Index)
	fmt.Printf("Checkpoint (signed tree head) after append:\n%s\n", string(cpRaw))

	if err := shutdown(ctx); err != nil {
		panic(fmt.Sprintf("shutdown: %v", err))
	}

	fmt.Println("\n--- Verifying inclusion proof against the published checkpoint ---")
	fetcher := client.FileFetcher{Root: *storageDir}

	var cp log.Checkpoint
	if _, err := cp.Unmarshal(cpRaw); err != nil {
		panic(fmt.Sprintf("Checkpoint.Unmarshal: %v", err))
	}
	fmt.Printf("Checkpoint tree size: %d\n", cp.Size)
	fmt.Printf("Checkpoint root hash: %x\n", cp.Hash)

	pb, err := client.NewProofBuilder(ctx, cp.Size, fetcher.ReadTile)
	if err != nil {
		panic(fmt.Sprintf("NewProofBuilder: %v", err))
	}
	incProof, err := pb.InclusionProof(ctx, idx.Index)
	if err != nil {
		panic(fmt.Sprintf("InclusionProof: %v", err))
	}
	fmt.Printf("Inclusion proof has %d hash entries.\n", len(incProof))

	if err := proof.VerifyInclusion(hasher, idx.Index, cp.Size, leafHash, incProof, cp.Hash); err != nil {
		fmt.Printf("INCLUSION PROOF VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Inclusion proof VERIFIED successfully.")

	tamperedHash := hasher.HashLeaf([]byte("tampered data, not the original leaf"))
	if err := proof.VerifyInclusion(hasher, idx.Index, cp.Size, tamperedHash, incProof, cp.Hash); err == nil {
		fmt.Println("ERROR: tampered leaf incorrectly verified as included (this should not happen)")
		os.Exit(1)
	} else {
		fmt.Printf("Negative test passed: tampered leaf correctly REJECTED (%v)\n", err)
	}

	fmt.Println("\nSprint 1 milestone complete: append -> checkpoint -> inclusion proof -> verify, end-to-end, with negative test.")
}
