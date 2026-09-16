// sprint2 wires the HTT and BTT Proto3 schemas (defined in internal/schema)
// into the Tessera log as real signed entries, replacing the placeholder byte
// strings used in Sprint 1. This is the Sprint 2 exit criterion described in
// the implementation plan (Chapter 4, Section 4.3).
//
// What this program demonstrates:
//  1. Entry Signer: Ed25519 keys are generated once and persisted; the same
//     key is reused on subsequent runs (required for public log consistency).
//  2. Real HTT token: a synthetic but schema-valid host attestation is signed,
//     appended, and its inclusion proof is verified.
//  3. Real BTT tokens: both a BUILD and a DEPLOYMENT event are signed, appended,
//     and verified — demonstrating the two-variant single-schema design.
//  4. Signature verification: the embedded Ed25519 signature on each token is
//     checked before its inclusion proof is verified, proving end-to-end integrity.
//  5. Tile server: the log is served over HTTP on localhost so that any verifier
//     with network access can independently audit the log without local file access.
//  6. Negative tests: a tampered token is correctly rejected; a token with a
//     forged signature is correctly rejected at the signature-check step.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/dmsecuritylabs/tessera-transparency/internal/api"
	"github.com/dmsecuritylabs/tessera-transparency/internal/schema"
	"github.com/dmsecuritylabs/tessera-transparency/internal/signer"
)

var (
	logDataDir = flag.String("log_dir", "./data/sprint2-log", "Directory for Tessera tile storage.")
	keyDir     = flag.String("key_dir", "./data/sprint2-keys", "Directory for the persistent entry signing key.")
	fresh      = flag.Bool("fresh", false, "If true, wipe log_dir before starting (use for a clean run).")
	serveAddr  = flag.String("serve", ":8080", "Address for the HTTP tile server. Set to empty to disable.")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	hasher := rfc6962.DefaultHasher

	// ── 1. Optional fresh start ───────────────────────────────────────────────
	if *fresh {
		fmt.Println("[main] --fresh: wiping log directory.")
		if err := os.RemoveAll(*logDataDir); err != nil {
			fatalf("remove log dir: %v", err)
		}
	}
	must(os.MkdirAll(*logDataDir, 0o755))

	// ── 2. Entry Signer: load or create persistent Ed25519 keypair ────────────
	entrySigner, err := signer.New(*keyDir, "tessera-prototype-entry-signer")
	if err != nil {
		fatalf("create entry signer: %v", err)
	}
	fmt.Printf("[main] Entry signer public key:\n  %s\n\n", entrySigner.PublicKeyString())

	// ── 3. Tessera log: checkpoint signing keypair (separate from entry key) ──
	// The checkpoint signer authenticates the Signed Tree Head (STH); the entry
	// signer authenticates individual token payloads. Separating these keys is
	// intentional: different parties may operate the log and issue entries.
	cpKeyPath := *keyDir + "/checkpoint-key.txt"
	cpSkey, cpVkey, err := loadOrGenKey(cpKeyPath, "tessera-prototype-checkpoint")
	if err != nil {
		fatalf("checkpoint key: %v", err)
	}
	fmt.Printf("[main] Checkpoint signer public key:\n  %s\n\n", cpVkey)

	cpSigner, err := note.NewSigner(cpSkey)
	if err != nil {
		fatalf("note.NewSigner: %v", err)
	}

	// ── 4. Open POSIX-backed Tessera log ─────────────────────────────────────
	driver, err := posix.New(ctx, posix.Config{Path: *logDataDir})
	if err != nil {
		fatalf("posix.New: %v", err)
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cpSigner).
		WithBatching(3, 200*time.Millisecond).
		WithCheckpointInterval(200 * time.Millisecond)

	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		fatalf("NewAppender: %v", err)
	}

	// ── 5. Start HTTP tile server ─────────────────────────────────────────────
	if *serveAddr != "" {
		ts := api.NewServer(*serveAddr, *logDataDir, appender, reader)
		addr, stopServer, err := ts.Start(ctx)
		if err != nil {
			fmt.Printf("[server] WARNING: could not start tile server: %v\n", err)
		} else {
			defer stopServer()
			fmt.Printf("[server] Tile server listening on http://%s\n", addr)
			fmt.Printf("[server] Any verifier can fetch tiles from that address.\n\n")
		}
	}

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 200*time.Millisecond)

	// ── 6. Append a Host Transparency Token ──────────────────────────────────
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Appending Host Transparency Token (HTT)")
	fmt.Println("═══════════════════════════════════════════════════════")

	// Synthetic but schema-valid HTT fields.
	bootTime := uint64(time.Now().Unix())
	tpmHash := sha256sum([]byte("synthetic-tpm-quote-pcr0-pcr1-pcr7"))
	cfgHash  := sha256sum([]byte("approved-baseline-config-v1.2.3"))

	htt := &schema.HostTransparencyToken{
		TokenID:              "htt-" + shortHex(tpmHash),
		HostID:               "host-" + shortHex(cfgHash), // pseudonymised
		AttestationServiceID: "attestation-svc-prototype-v1",
		BootTimestampUTC:     bootTime,
		TPMMeasurementHash:   tpmHash,
		BaselineConfigHash:   cfgHash,
		SecureBootVerified:   true,
		BaselineMatch:        true,
	}

	httData, err := entrySigner.SignHTT(htt)
	if err != nil {
		fatalf("sign HTT: %v", err)
	}
	fmt.Printf("  Token ID:     %s\n", htt.TokenID)
	fmt.Printf("  Host ID:      %s\n", htt.HostID)
	fmt.Printf("  Signature:    %x…\n", htt.Signature[:8])
	fmt.Printf("  Payload size: %d bytes\n", len(httData))

	// Verify the Ed25519 signature before submitting.
	parsed, _ := schema.UnmarshalHTT(httData)
	if err := entrySigner.VerifyHTT(parsed); err != nil {
		fatalf("HTT signature self-check failed: %v", err)
	}
	fmt.Println("  ✓ Entry signer signature verified before submission.")

	httFuture := appender.Add(ctx, tessera.NewEntry(httData))
	httIdx, httCP, err := awaiter.Await(ctx, httFuture)
	if err != nil {
		fatalf("await HTT: %v", err)
	}
	fmt.Printf("  ✓ HTT appended at log index %d\n\n", httIdx.Index)

	// ── 7. Append a Binary Transparency Token (BUILD event) ──────────────────
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Appending Binary Transparency Token — BUILD event")
	fmt.Println("═══════════════════════════════════════════════════════")

	binHash    := sha256sum([]byte("example-binary-v2.1.0-linux-amd64"))
	commitHash := sha256sum([]byte("git-commit-abc123def456"))

	bttBuild := &schema.BinaryTransparencyToken{
		TokenID:            "btt-build-" + shortHex(binHash),
		BinaryHash:         binHash,
		EventType:          schema.EventTypeBuild,
		IssuerID:           "github-actions-build-svc",
		EventTimestamp:     uint64(time.Now().Unix()),
		SourceCommitHash:   commitHash,
		BuildProvenanceURI: "https://github.com/dmendoza/example/attestations/slsa/v1?sha=" + hex.EncodeToString(commitHash),
	}

	bttBuildData, err := entrySigner.SignBTT(bttBuild)
	if err != nil {
		fatalf("sign BTT BUILD: %v", err)
	}
	fmt.Printf("  Token ID:       %s\n", bttBuild.TokenID)
	fmt.Printf("  Binary hash:    %x…\n", binHash[:8])
	fmt.Printf("  Event type:     %s\n", bttBuild.EventType)
	fmt.Printf("  Provenance URI: %s\n", bttBuild.BuildProvenanceURI)

	parsedBuild, _ := schema.UnmarshalBTT(bttBuildData)
	if err := entrySigner.VerifyBTT(parsedBuild); err != nil {
		fatalf("BTT BUILD signature self-check failed: %v", err)
	}
	fmt.Println("  ✓ Entry signer signature verified before submission.")

	bttBuildFuture := appender.Add(ctx, tessera.NewEntry(bttBuildData))
	bttBuildIdx, _, err := awaiter.Await(ctx, bttBuildFuture)
	if err != nil {
		fatalf("await BTT BUILD: %v", err)
	}
	fmt.Printf("  ✓ BTT BUILD appended at log index %d\n\n", bttBuildIdx.Index)

	// ── 8. Append a Binary Transparency Token (DEPLOYMENT event) ─────────────
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Appending Binary Transparency Token — DEPLOYMENT event")
	fmt.Println("═══════════════════════════════════════════════════════")

	verifEvidHash := sha256sum([]byte("signature-check-passed+provenance-verified"))

	bttDeploy := &schema.BinaryTransparencyToken{
		TokenID:                  "btt-deploy-" + shortHex(binHash),
		BinaryHash:               binHash, // same binary as BUILD event
		EventType:                schema.EventTypeDeployment,
		IssuerID:                 "deployment-gating-svc-prod",
		EventTimestamp:           uint64(time.Now().Unix()),
		VerificationEvidenceHash: verifEvidHash,
	}

	bttDeployData, err := entrySigner.SignBTT(bttDeploy)
	if err != nil {
		fatalf("sign BTT DEPLOY: %v", err)
	}
	fmt.Printf("  Token ID:   %s\n", bttDeploy.TokenID)
	fmt.Printf("  Event type: %s\n", bttDeploy.EventType)
	fmt.Printf("  Verif hash: %x…\n", verifEvidHash[:8])

	parsedDeploy, _ := schema.UnmarshalBTT(bttDeployData)
	if err := entrySigner.VerifyBTT(parsedDeploy); err != nil {
		fatalf("BTT DEPLOY signature self-check failed: %v", err)
	}
	fmt.Println("  ✓ Entry signer signature verified before submission.")

	bttDeployFuture := appender.Add(ctx, tessera.NewEntry(bttDeployData))
	bttDeployIdx, bttDeployCP, err := awaiter.Await(ctx, bttDeployFuture)
	if err != nil {
		fatalf("await BTT DEPLOY: %v", err)
	}
	fmt.Printf("  ✓ BTT DEPLOY appended at log index %d\n\n", bttDeployIdx.Index)

	// ── 9. Shutdown the appender to flush all tiles ───────────────────────────
	if err := shutdown(ctx); err != nil {
		fatalf("shutdown: %v", err)
	}

	// ── 10. Verify inclusion proofs for all three tokens ─────────────────────
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Verifying inclusion proofs (read-only, via tile fetcher)")
	fmt.Println("═══════════════════════════════════════════════════════")

	fetcher := client.FileFetcher{Root: *logDataDir}

	// Parse the final checkpoint.
	var finalCP logfmt.Checkpoint
	if _, err := finalCP.Unmarshal(bttDeployCP); err != nil {
		fatalf("unmarshal final checkpoint: %v", err)
	}
	fmt.Printf("  Final checkpoint: tree size=%d  root=%x…\n\n",
		finalCP.Size, finalCP.Hash[:8])

	pb, err := client.NewProofBuilder(ctx, finalCP.Size, fetcher.ReadTile)
	if err != nil {
		fatalf("NewProofBuilder: %v", err)
	}

	for _, tc := range []struct {
		name string
		idx  uint64
		data []byte
		cp   []byte
	}{
		{"HTT", httIdx.Index, httData, httCP},
		{"BTT BUILD", bttBuildIdx.Index, bttBuildData, nil},
		{"BTT DEPLOY", bttDeployIdx.Index, bttDeployData, bttDeployCP},
	} {
		leafHash := hasher.HashLeaf(tc.data)
		incProof, err := pb.InclusionProof(ctx, tc.idx)
		if err != nil {
			fatalf("InclusionProof(%s): %v", tc.name, err)
		}
		if err := proof.VerifyInclusion(hasher, tc.idx, finalCP.Size, leafHash, incProof, finalCP.Hash); err != nil {
			fmt.Printf("  ✗ %s inclusion proof FAILED: %v\n", tc.name, err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ %s (index %d): inclusion proof verified (%d hashes)\n",
			tc.name, tc.idx, len(incProof))
	}

	// ── 11. Consistency proof: HTT checkpoint → final checkpoint ─────────────
	fmt.Println()
	var httCheckpoint logfmt.Checkpoint
	if _, err := httCheckpoint.Unmarshal(httCP); err != nil {
		fatalf("unmarshal HTT checkpoint: %v", err)
	}
	if httCheckpoint.Size < finalCP.Size {
		consProof, err := pb.ConsistencyProof(ctx, httCheckpoint.Size, finalCP.Size)
		if err != nil {
			fatalf("ConsistencyProof: %v", err)
		}
		if err := proof.VerifyConsistency(hasher, httCheckpoint.Size, finalCP.Size,
			consProof, httCheckpoint.Hash, finalCP.Hash); err != nil {
			fmt.Printf("  ✗ Consistency proof FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ Consistency proof: cp(size=%d) → cp(size=%d) verified (%d hashes)\n",
			httCheckpoint.Size, finalCP.Size, len(consProof))
	}

	// ── 12. Negative test: tampered token payload ─────────────────────────────
	fmt.Println()
	tamperedData := append([]byte(nil), httData...)
	tamperedData[len(tamperedData)/2] ^= 0xFF // flip a byte in the middle
	tamperedLeaf := hasher.HashLeaf(tamperedData)
	httIncProof, _ := pb.InclusionProof(ctx, httIdx.Index)
	if err := proof.VerifyInclusion(hasher, httIdx.Index, finalCP.Size,
		tamperedLeaf, httIncProof, finalCP.Hash); err == nil {
		fmt.Println("  ✗ ERROR: tampered HTT incorrectly verified as included")
		os.Exit(1)
	}
	fmt.Println("  ✓ Negative test: tampered HTT payload correctly rejected")

	// ── 13. Negative test: forged signature ──────────────────────────────────
	parsedAgain, _ := schema.UnmarshalHTT(httData)
	parsedAgain.Signature[0] ^= 0xFF // corrupt first byte of signature
	if err := entrySigner.VerifyHTT(parsedAgain); err == nil {
		fmt.Println("  ✗ ERROR: forged HTT signature incorrectly accepted")
		os.Exit(1)
	}
	fmt.Println("  ✓ Negative test: forged HTT signature correctly rejected")

	// ── 14. Summary ───────────────────────────────────────────────────────────
	fmt.Printf(`
═══════════════════════════════════════════════════════
  Sprint 2 milestone complete
═══════════════════════════════════════════════════════
  Tokens appended:
    • 1 × Host Transparency Token (HTT)       index %d
    • 1 × Binary Transparency Token (BUILD)   index %d
    • 1 × Binary Transparency Token (DEPLOY)  index %d

  Verified:
    ✓ Ed25519 signatures on all 3 tokens
    ✓ Inclusion proofs for all 3 tokens
    ✓ Consistency proof (HTT → final checkpoint)
    ✓ Tampered payload rejected
    ✓ Forged signature rejected

  Log tiles available at: http://%s
  Entry signer public key: %s
`,
		httIdx.Index, bttBuildIdx.Index, bttDeployIdx.Index,
		*serveAddr,
		entrySigner.PublicKeyString(),
	)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func shortHex(b []byte) string {
	return hex.EncodeToString(b[:6])
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func loadOrGenKey(path, name string) (skey, vkey string, err error) {
	if data, err := os.ReadFile(path); err == nil {
		parts := splitLines(string(data))
		if len(parts) >= 2 {
			fmt.Printf("[main] Loaded checkpoint key from %s\n", path)
			return parts[0], parts[1], nil
		}
	}
	sk, vk, err2 := note.GenerateKey(nil, name)
	if err2 != nil {
		return "", "", err2
	}
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, []byte(sk+"\n"+vk+"\n"), 0o600))
	fmt.Printf("[main] Generated checkpoint key; saved to %s\n", path)
	return sk, vk, nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
