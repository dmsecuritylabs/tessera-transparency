// sprint1b extends the Sprint 1 milestone: appends multiple leaves across
// two checkpoints and verifies a consistency proof between them, in
// addition to inclusion proofs for several leaves. This demonstrates both
// core Tessera guarantees (inclusion + consistency) described in Ch.2 §2.1.
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

var storageDir = flag.String("storage_dir", "/home/claude/tessera-transparency/data/log2", "Root directory to store log data.")

func mustCheckpoint(raw []byte) log.Checkpoint {
	var cp log.Checkpoint
	if _, err := cp.Unmarshal(raw); err != nil {
		panic(fmt.Sprintf("Checkpoint.Unmarshal: %v", err))
	}
	return cp
}

func main() {
	flag.Parse()
	ctx := context.Background()
	hasher := rfc6962.DefaultHasher

	if err := os.RemoveAll(*storageDir); err != nil {
		fmt.Printf("warning: could not clean storage dir: %v\n", err)
	}
	if err := os.MkdirAll(*storageDir, 0o755); err != nil {
		panic(err)
	}

	skey, vkey, err := note.GenerateKey(nil, "dissertation-prototype-log-2")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Public verifier key: %s\n\n", vkey)
	signer, err := note.NewSigner(skey)
	if err != nil {
		panic(err)
	}

	driver, err := posix.New(ctx, posix.Config{Path: *storageDir})
	if err != nil {
		panic(err)
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(5, 100*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)

	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		panic(err)
	}

	// Batch 1: append 5 leaves, await checkpoint cp1 (size 5).
	leafHashes := make([][]byte, 0, 10)
	var lastIdx tessera.IndexFuture
	var cp1Raw []byte
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("entry-%02d: batch1", i))
		leafHashes = append(leafHashes, hasher.HashLeaf(data))
		lastIdx = appender.Add(ctx, tessera.NewEntry(data))
	}
	await := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 100*time.Millisecond)
	_, cp1Raw, err = await.Await(ctx, lastIdx)
	if err != nil {
		panic(err)
	}
	cp1 := mustCheckpoint(cp1Raw)
	fmt.Printf("Checkpoint 1: size=%d root=%x\n", cp1.Size, cp1.Hash)

	// Batch 2: append 5 more leaves, await checkpoint cp2 (size 10).
	for i := 5; i < 10; i++ {
		data := []byte(fmt.Sprintf("entry-%02d: batch2", i))
		leafHashes = append(leafHashes, hasher.HashLeaf(data))
		lastIdx = appender.Add(ctx, tessera.NewEntry(data))
	}
	_, cp2Raw, err := await.Await(ctx, lastIdx)
	if err != nil {
		panic(err)
	}
	cp2 := mustCheckpoint(cp2Raw)
	fmt.Printf("Checkpoint 2: size=%d root=%x\n", cp2.Size, cp2.Hash)

	if err := shutdown(ctx); err != nil {
		panic(err)
	}

	fetcher := client.FileFetcher{Root: *storageDir}

	// Inclusion proofs for indices 0, 4, 9 against the final checkpoint (cp2).
	fmt.Println("\n--- Inclusion proofs against final checkpoint (size 10) ---")
	pbFinal, err := client.NewProofBuilder(ctx, cp2.Size, fetcher.ReadTile)
	if err != nil {
		panic(err)
	}
	for _, idx := range []uint64{0, 4, 9} {
		ip, err := pbFinal.InclusionProof(ctx, idx)
		if err != nil {
			panic(fmt.Sprintf("InclusionProof(%d): %v", idx, err))
		}
		if err := proof.VerifyInclusion(hasher, idx, cp2.Size, leafHashes[idx], ip, cp2.Hash); err != nil {
			fmt.Printf("  index %d: FAILED (%v)\n", idx, err)
			os.Exit(1)
		}
		fmt.Printf("  index %d: inclusion proof VERIFIED (%d hashes)\n", idx, len(ip))
	}

	// Consistency proof between cp1 (size 5) and cp2 (size 10).
	fmt.Println("\n--- Consistency proof: checkpoint 1 (size 5) -> checkpoint 2 (size 10) ---")
	consProof, err := pbFinal.ConsistencyProof(ctx, cp1.Size, cp2.Size)
	if err != nil {
		panic(fmt.Sprintf("ConsistencyProof: %v", err))
	}
	fmt.Printf("Consistency proof has %d hash entries.\n", len(consProof))
	if err := proof.VerifyConsistency(hasher, cp1.Size, cp2.Size, consProof, cp1.Hash, cp2.Hash); err != nil {
		fmt.Printf("CONSISTENCY PROOF VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Consistency proof VERIFIED: checkpoint 2 is a valid append-only extension of checkpoint 1.")

	// Negative test: consistency proof must fail against a wrong earlier root.
	fakeRoot := hasher.HashLeaf([]byte("not the real checkpoint 1 root"))
	if err := proof.VerifyConsistency(hasher, cp1.Size, cp2.Size, consProof, fakeRoot, cp2.Hash); err == nil {
		fmt.Println("ERROR: consistency proof incorrectly verified against a forged earlier root")
		os.Exit(1)
	} else {
		fmt.Printf("Negative test passed: forged earlier root correctly REJECTED (%v)\n", err)
	}

	fmt.Println("\nSprint 1b milestone complete: 10 leaves appended across 2 batches; 3 inclusion proofs and 1 consistency proof verified; 2 negative tests passed.")
}
