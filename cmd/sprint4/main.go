// sprint4 is the benchmarking and correctness-verification harness for the
// dissertation Chapter 5 (Evaluation). All four parts are complete.
//
// Part 1: throughput benchmark — Run A (1,000/sec) and Run B (10,000/sec),
//         each 30 s against fresh POSIX-backed Tessera logs.
// Part 2: proof-latency benchmark — Run A log re-opened and served via the
//         REST API; GET /token/prove measured at concurrency 10 and 50.
// Part 3: correctness suite — 1,000-entry log; 1,000 inclusion proofs,
//         9 consecutive consistency proofs, 50 negative tamper tests.
// Part 4: final formatted summary table; deferred CSV writes; clean shutdown.
//
// Exit codes: 0 = all correctness tests passed; 1 = any failure.
//
// Usage:
//
//	go run ./cmd/sprint4              # --fresh=true: runs all parts
//	go run ./cmd/sprint4 --fresh=false # skips throughput/latency, runs only correctness
package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"

	logfmt "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/dmendoza/tessera-transparency/internal/api"
	"github.com/dmendoza/tessera-transparency/internal/schema"
	"github.com/dmendoza/tessera-transparency/internal/signer"
)

// ── Top-level paths ──────────────────────────────────────────────────────────

const (
	outputDir      = "./data/sprint4"
	logRunADir     = "./data/sprint4/log-runA"
	logRunBDir     = "./data/sprint4/log-runB"
	keysDir        = "./data/sprint4/keys"
	correctnessDir = "./data/sprint4/correctness-log"

	benchDur = 30 * time.Second
)

var freshFlag = flag.Bool("fresh", true,
	"Run all phases from scratch (wipes ./data/sprint4/). "+
		"Set false to skip throughput/latency and re-run only the correctness suite.")

// ── Result types ─────────────────────────────────────────────────────────────

type throughputResult struct {
	label      string
	target     int
	duration   float64
	confirmed  int64
	rate       float64
	leafHashes [][]byte // leafHashes[logIndex] = rfc6962.HashLeaf(tokenBytes)
}

type latencyResult struct {
	concurrency int
	duration    float64
	totalReqs   int64
	p50ms       float64
	p99ms       float64
}

type proveRespJSON struct {
	Index    uint64   `json:"index"`
	TreeSize uint64   `json:"tree_size"`
	Root     string   `json:"root"`
	Proof    []string `json:"proof"`
}

type entryRecord struct {
	logIndex  uint64
	tokenData []byte
	leafHash  []byte
}

type corrResult struct {
	inclusionTotal    int
	inclusionPassed   int
	inclusionFailed   int
	consistencyTotal  int
	consistencyPassed int
	consistencyFailed int
	negativeTotal     int
	negativePassed    int
	negativeFailed    int
}

// ── Entry point ───────────────────────────────────────────────────────────────

// main is a thin wrapper so that deferred functions in run() execute before
// the process exits, including the deferred CSV writes and summary print.
func main() {
	os.Exit(run())
}

// run performs all benchmark phases and returns the exit code (0 = pass, 1 = fail).
// All CSV files and the final summary are written inside a single defer so they
// are guaranteed to be flushed on any return path (including early returns).
// Note: os.Exit calls inside phase functions (via fatalf) bypass this defer;
// those are reserved for unrecoverable infrastructure failures where no
// meaningful partial data exists to save.
func run() int {
	flag.Parse()
	klog.SetOutput(io.Discard)
	ctx := context.Background()

	// ── Output directory ───────────────────────────────────────────────────
	if *freshFlag {
		fmt.Println("[sprint4] --fresh: wiping ./data/sprint4/")
		if err := os.RemoveAll(outputDir); err != nil {
			fatalf("remove output dir: %v", err)
		}
	} else {
		fmt.Println("[sprint4] --fresh=false: skipping throughput and latency benchmarks.")
	}
	must(os.MkdirAll(outputDir, 0o755))
	must(os.MkdirAll(keysDir, 0o755))

	entrySigner, err := signer.New(keysDir, "sprint4-entry-signer")
	if err != nil {
		fatalf("create entry signer: %v", err)
	}

	// Declare all result variables here so the deferred closure below can
	// capture them by reference and read their final values on any return.
	var (
		resultA, resultB throughputResult
		storageBytes     int64
		bytesPerEntry    float64
		latResults       []latencyResult
		corrRes          corrResult
	)

	// Deferred: write all applicable CSV files and print the final summary
	// table regardless of which return path is taken. This ensures partial
	// results from completed phases are always persisted.
	defer func() {
		if *freshFlag {
			writeThroughputCSV(resultA, resultB)
			writeStorageCSV(resultA.confirmed, storageBytes, bytesPerEntry)
			if len(latResults) > 0 {
				writeLatencyCSV(latResults)
			}
		}
		writeCorrectnessCSV(corrRes)
		printFinalSummary(resultA, resultB, storageBytes, bytesPerEntry, latResults, corrRes)
	}()

	// ══════════════════════════════════════════════════════════════════════
	// PART 1 & 2 — Throughput + Latency (skipped when --fresh=false)
	// ══════════════════════════════════════════════════════════════════════

	if *freshFlag {
		fmt.Println()
		printBanner("Run A — target 1,000 entries/sec for 30 s")
		resultA = runThroughput(ctx, "A", logRunADir, 1_000, benchDur, entrySigner)
		fmt.Printf("[sprint4] Run A done: %d confirmed in %.2f s = %.1f entries/sec\n\n",
			resultA.confirmed, resultA.duration, resultA.rate)

		storageBytes = measureDirBytes(logRunADir)
		if resultA.confirmed > 0 {
			bytesPerEntry = float64(storageBytes) / float64(resultA.confirmed)
		}
		fmt.Printf("[sprint4] Storage (Run A): %d bytes / %d entries = %.0f bytes/entry\n\n",
			storageBytes, resultA.confirmed, bytesPerEntry)

		printBanner("Run B — target 10,000 entries/sec for 30 s")
		resultB = runThroughput(ctx, "B", logRunBDir, 10_000, benchDur, entrySigner)
		fmt.Printf("[sprint4] Run B done: %d confirmed in %.2f s = %.1f entries/sec\n\n",
			resultB.confirmed, resultB.duration, resultB.rate)

		printBanner("Proof Latency Benchmark — Run A log via REST API")
		latResults = runLatencyPhase(ctx, resultA)
	}

	// ══════════════════════════════════════════════════════════════════════
	// PART 3 — Correctness verification suite (always runs)
	// ══════════════════════════════════════════════════════════════════════

	printBanner("Correctness Verification Suite — 1,000-entry log")
	corrRes = runCorrectnessPhase(ctx, entrySigner)

	// The deferred function above will write CSVs and print the summary.
	if corrRes.inclusionFailed > 0 || corrRes.consistencyFailed > 0 || corrRes.negativeFailed > 0 {
		fmt.Fprintln(os.Stderr, "[sprint4] FAIL: one or more correctness tests failed.")
		return 1
	}
	return 0
}

// ── Part 1: Throughput benchmark ─────────────────────────────────────────────

func runThroughput(
	ctx context.Context,
	label, logDir string,
	targetRate int,
	dur time.Duration,
	entrySigner *signer.Signer,
) throughputResult {

	must(os.RemoveAll(logDir))
	must(os.MkdirAll(logDir, 0o755))

	cpKeyPath := filepath.Join(keysDir, "cp-key-run"+strings.ToLower(label)+".txt")
	cpSkey, _, err := loadOrGenKey(cpKeyPath, "sprint4-checkpoint-run"+label)
	if err != nil {
		fatalf("checkpoint key run %s: %v", label, err)
	}
	cpSigner, err := note.NewSigner(cpSkey)
	if err != nil {
		fatalf("note.NewSigner run %s: %v", label, err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: logDir})
	if err != nil {
		fatalf("posix.New run %s: %v", label, err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cpSigner).
		WithBatching(256, 50*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		fatalf("NewAppender run %s: %v", label, err)
	}
	// Deferred shutdown: runs after wg.Wait() completes (wg.Wait is called
	// before runThroughput returns), so the appender is idle by then.
	defer func() {
		if err := shutdown(ctx); err != nil {
			fmt.Printf("  [run%s] WARNING: shutdown: %v\n", label, err)
		}
	}()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 50*time.Millisecond)
	hasher := rfc6962.DefaultHasher

	tickInterval := time.Second / time.Duration(targetRate)
	if tickInterval < time.Millisecond {
		tickInterval = time.Millisecond
	}
	ticksPerSec := int(time.Second / tickInterval)
	entriesPerTick := targetRate / ticksPerSec
	if entriesPerTick < 1 {
		entriesPerTick = 1
	}
	fmt.Printf("  [run%s] tick=%v  entries/tick=%d  effective_target=%d/sec\n",
		label, tickInterval, entriesPerTick, ticksPerSec*entriesPerTick)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	progress := time.NewTicker(5 * time.Second)
	defer progress.Stop()
	deadlineCh := time.After(dur)

	var confirmed atomic.Int64
	var lhMu sync.Mutex
	leafHashes := make([][]byte, 0, 65536)
	var wg sync.WaitGroup
	entryIdx := 0
	start := time.Now()

loop:
	for {
		select {
		case <-deadlineCh:
			break loop
		case <-progress.C:
			elapsed := time.Since(start).Seconds()
			c := confirmed.Load()
			fmt.Printf("  [run%s] %5.0f s | confirmed: %7d | %.0f/sec\n",
				label, elapsed, c, float64(c)/elapsed)
		case <-ticker.C:
			for k := 0; k < entriesPerTick; k++ {
				i := entryIdx
				entryIdx++
				// `data` is a new variable per iteration (var inside loop body);
				// safe to capture in the goroutine closure below.
				var data []byte
				if i%2 == 0 {
					data = makeHTT(i, entrySigner)
				} else {
					data = makeBTT(i, entrySigner)
				}
				future := appender.Add(ctx, tessera.NewEntry(data))
				wg.Add(1)
				go func() {
					defer wg.Done()
					idx, _, awaitErr := awaiter.Await(ctx, future)
					if awaitErr == nil {
						confirmed.Add(1)
						lh := hasher.HashLeaf(data)
						lhMu.Lock()
						need := idx.Index + 1
						for uint64(len(leafHashes)) < need {
							leafHashes = append(leafHashes, nil)
						}
						leafHashes[idx.Index] = lh
						lhMu.Unlock()
					}
				}()
			}
		}
	}

	// Record the submission window before waiting for trailing confirmations.
	elapsedSubmit := time.Since(start)
	// Wait for the last batch to publish (≤ one 50 ms batch interval).
	wg.Wait()
	// Deferred shutdown() runs on return.

	c := confirmed.Load()
	return throughputResult{
		label:      label,
		target:     targetRate,
		duration:   elapsedSubmit.Seconds(),
		confirmed:  c,
		rate:       float64(c) / elapsedSubmit.Seconds(),
		leafHashes: leafHashes,
	}
}

// ── Part 2: Proof latency benchmark ──────────────────────────────────────────

func runLatencyPhase(ctx context.Context, runAResult throughputResult) []latencyResult {
	if runAResult.confirmed == 0 || len(runAResult.leafHashes) == 0 {
		fmt.Println("[sprint4] Skipping latency benchmark: Run A has no confirmed entries.")
		return nil
	}

	cpKeyPath := filepath.Join(keysDir, "cp-key-runa.txt")
	cpSkey, _, err := loadOrGenKey(cpKeyPath, "sprint4-checkpoint-runA")
	if err != nil {
		fatalf("reload Run A checkpoint key: %v", err)
	}
	cpSigner, err := note.NewSigner(cpSkey)
	if err != nil {
		fatalf("re-create cp signer: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: logRunADir})
	if err != nil {
		fatalf("re-open Run A posix driver: %v", err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cpSigner).
		WithBatching(1, 50*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)
	appender, shutdownA, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		fatalf("re-open NewAppender Run A: %v", err)
	}
	// Deferred shutdowns: stopSrv runs first (registered last → LIFO),
	// then shutdownA runs, matching the correct dependency order.
	defer func() {
		if err := shutdownA(ctx); err != nil {
			fmt.Printf("[sprint4] WARNING: shutdown Run A (latency phase): %v\n", err)
		}
	}()

	srv := api.NewServer(":0", logRunADir, appender, reader)
	addr, stopSrv, err := srv.Start(ctx)
	if err != nil {
		fatalf("start API server: %v", err)
	}
	defer stopSrv() // registered after shutdownA → runs first (LIFO)

	baseURL := "http://" + addr
	fmt.Printf("[sprint4] REST API for latency test: %s\n", baseURL)
	time.Sleep(100 * time.Millisecond)

	results := make([]latencyResult, 0, 2)
	for _, concurrency := range []int{10, 50} {
		fmt.Printf("\n[sprint4] Latency level: concurrency=%d, duration=30 s\n", concurrency)
		r := runLatencyLevel(ctx, baseURL, runAResult.leafHashes, concurrency, benchDur)
		fmt.Printf("[sprint4]   done: %d verified requests, p50=%.1f ms, p99=%.1f ms\n",
			r.totalReqs, r.p50ms, r.p99ms)
		results = append(results, r)
	}
	return results
	// Deferred stopSrv() and shutdownA() run here.
}

func runLatencyLevel(
	ctx context.Context,
	baseURL string,
	leafHashes [][]byte,
	concurrency int,
	dur time.Duration,
) latencyResult {

	hasher := rfc6962.DefaultHasher
	httpClient := &http.Client{Timeout: 5 * time.Second}

	var mu sync.Mutex
	var durations []time.Duration
	var totalReqs atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	start := time.Now()

	stopProgress := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fmt.Printf("  [latency c=%2d] %5.0f s | verified requests: %d\n",
					concurrency, time.Since(start).Seconds(), totalReqs.Load())
			case <-stopProgress:
				return
			}
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				idx := uint64(rand.Int63n(int64(len(leafHashes))))
				if leafHashes[idx] == nil {
					continue
				}
				url := fmt.Sprintf("%s/token/prove?index=%d", baseURL, idx)

				reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				req, reqErr := http.NewRequestWithContext(reqCtx, "GET", url, nil)
				if reqErr != nil {
					cancel()
					continue
				}

				t0 := time.Now()
				resp, httpErr := httpClient.Do(req)
				if httpErr != nil {
					cancel()
					continue
				}
				var pr proveRespJSON
				decErr := json.NewDecoder(resp.Body).Decode(&pr)
				resp.Body.Close()
				elapsed := time.Since(t0)
				cancel()

				if decErr != nil || resp.StatusCode != http.StatusOK {
					continue
				}

				rootBytes, rootErr := hex.DecodeString(pr.Root)
				if rootErr != nil {
					continue
				}
				proofHashes := make([][]byte, len(pr.Proof))
				validHex := true
				for j, h := range pr.Proof {
					b, hexErr := hex.DecodeString(h)
					if hexErr != nil {
						validHex = false
						break
					}
					proofHashes[j] = b
				}
				if !validHex {
					continue
				}
				if err := proof.VerifyInclusion(
					hasher, idx, pr.TreeSize,
					leafHashes[idx], proofHashes, rootBytes,
				); err != nil {
					continue
				}

				totalReqs.Add(1)
				mu.Lock()
				durations = append(durations, elapsed)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(stopProgress)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	n := len(durations)
	var p50, p99 float64
	if n > 0 {
		p50 = float64(durations[n*50/100]) / float64(time.Millisecond)
		p99idx := n * 99 / 100
		if p99idx >= n {
			p99idx = n - 1
		}
		p99 = float64(durations[p99idx]) / float64(time.Millisecond)
	}
	return latencyResult{
		concurrency: concurrency,
		duration:    time.Since(start).Seconds(),
		totalReqs:   totalReqs.Load(),
		p50ms:       p50,
		p99ms:       p99,
	}
}

// ── Part 3: Correctness verification suite ───────────────────────────────────

const (
	corrTotal      = 1000
	corrBatch      = 100
	corrSnapshots  = corrTotal / corrBatch // 10
	corrConsProofs = corrSnapshots - 1     // 9
	corrNegTests   = 50
)

func runCorrectnessPhase(ctx context.Context, entrySigner *signer.Signer) corrResult {
	must(os.RemoveAll(correctnessDir))
	must(os.MkdirAll(correctnessDir, 0o755))

	cpKeyPath := filepath.Join(keysDir, "cp-key-correctness.txt")
	cpSkey, _, err := loadOrGenKey(cpKeyPath, "sprint4-checkpoint-correctness")
	if err != nil {
		fatalf("correctness checkpoint key: %v", err)
	}
	cpSigner, err := note.NewSigner(cpSkey)
	if err != nil {
		fatalf("correctness note.NewSigner: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: correctnessDir})
	if err != nil {
		fatalf("correctness posix.New: %v", err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cpSigner).
		WithBatching(256, 50*time.Millisecond).
		WithCheckpointInterval(100 * time.Millisecond)
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		fatalf("correctness NewAppender: %v", err)
	}

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 50*time.Millisecond)
	hasher := rfc6962.DefaultHasher

	// ── Append phase ──────────────────────────────────────────────────────
	// appender.Add is called in the outer loop (deterministic order), so
	// log index == submission index. Goroutines only await; they write to
	// non-overlapping slice indices so no mutex is needed on records[].
	records := make([]entryRecord, corrTotal)
	snapshots := make([][]byte, corrSnapshots)

	for b := 0; b < corrSnapshots; b++ {
		var bwg sync.WaitGroup
		for k := 0; k < corrBatch; k++ {
			i := b*corrBatch + k
			var tokenData []byte
			if i < 500 {
				tokenData = makeHTT(i, entrySigner)
			} else {
				tokenData = makeBTT(i, entrySigner)
			}
			leafHash := hasher.HashLeaf(tokenData)
			future := appender.Add(ctx, tessera.NewEntry(tokenData))
			bwg.Add(1)
			go func(entryI int, data, lh []byte) {
				defer bwg.Done()
				idx, _, awaitErr := awaiter.Await(ctx, future)
				if awaitErr != nil {
					fatalf("correctness await entry %d: %v", entryI, awaitErr)
				}
				records[idx.Index] = entryRecord{
					logIndex:  idx.Index,
					tokenData: data,
					leafHash:  lh,
				}
			}(i, tokenData, leafHash)
		}
		bwg.Wait()

		cpRaw, cpErr := reader.ReadCheckpoint(ctx)
		if cpErr != nil {
			fatalf("read checkpoint after correctness batch %d: %v", b+1, cpErr)
		}
		snapshots[b] = cpRaw
		var cp logfmt.Checkpoint
		if _, err := cp.Unmarshal(cpRaw); err != nil {
			fatalf("unmarshal checkpoint after batch %d: %v", b+1, err)
		}
		fmt.Printf("  [correctness] Batch %2d/%d confirmed: tree size=%d\n",
			b+1, corrSnapshots, cp.Size)
	}

	// Explicit shutdown before using FileFetcher: all tiles must be flushed
	// to disk before we read them for proof verification.
	if err := shutdown(ctx); err != nil {
		fmt.Printf("  [correctness] WARNING: shutdown: %v\n", err)
	}

	fetcher := client.FileFetcher{Root: correctnessDir}
	var finalCP logfmt.Checkpoint
	if _, err := finalCP.Unmarshal(snapshots[corrSnapshots-1]); err != nil {
		fatalf("unmarshal final correctness checkpoint: %v", err)
	}
	pb, err := client.NewProofBuilder(ctx, finalCP.Size, fetcher.ReadTile)
	if err != nil {
		fatalf("correctness NewProofBuilder: %v", err)
	}

	var res corrResult
	res.inclusionTotal = corrTotal
	res.consistencyTotal = corrConsProofs
	res.negativeTotal = corrNegTests

	// ── Inclusion proofs ──────────────────────────────────────────────────
	fmt.Printf("  [correctness] Verifying inclusion proofs for all %d entries...\n", corrTotal)
	for i, rec := range records {
		if rec.tokenData == nil {
			res.inclusionFailed++
			continue
		}
		incProof, proofErr := pb.InclusionProof(ctx, rec.logIndex)
		if proofErr != nil {
			res.inclusionFailed++
			continue
		}
		if err := proof.VerifyInclusion(
			hasher, rec.logIndex, finalCP.Size,
			rec.leafHash, incProof, finalCP.Hash,
		); err != nil {
			res.inclusionFailed++
		} else {
			res.inclusionPassed++
		}
		if (i+1)%200 == 0 {
			fmt.Printf("  [correctness]   ... %d/%d checked\n", i+1, corrTotal)
		}
	}
	fmt.Printf("  [correctness] Inclusion proofs: %d passed, %d failed\n",
		res.inclusionPassed, res.inclusionFailed)

	// ── Consistency proofs ────────────────────────────────────────────────
	fmt.Printf("  [correctness] Verifying %d consistency proofs...\n", corrConsProofs)
	for i := 0; i < corrConsProofs; i++ {
		var fromCP, toCP logfmt.Checkpoint
		if _, err := fromCP.Unmarshal(snapshots[i]); err != nil {
			res.consistencyFailed++
			continue
		}
		if _, err := toCP.Unmarshal(snapshots[i+1]); err != nil {
			res.consistencyFailed++
			continue
		}
		if fromCP.Size == toCP.Size {
			res.consistencyPassed++ // trivially consistent
			continue
		}
		consPB, consPBErr := client.NewProofBuilder(ctx, toCP.Size, fetcher.ReadTile)
		if consPBErr != nil {
			res.consistencyFailed++
			continue
		}
		consProof, consErr := consPB.ConsistencyProof(ctx, fromCP.Size, toCP.Size)
		if consErr != nil {
			res.consistencyFailed++
			continue
		}
		if err := proof.VerifyConsistency(
			hasher, fromCP.Size, toCP.Size,
			consProof, fromCP.Hash, toCP.Hash,
		); err != nil {
			res.consistencyFailed++
		} else {
			res.consistencyPassed++
		}
	}
	fmt.Printf("  [correctness] Consistency proofs: %d passed, %d failed\n",
		res.consistencyPassed, res.consistencyFailed)

	// ── Negative tests ────────────────────────────────────────────────────
	fmt.Printf("  [correctness] Running %d negative (tamper) tests...\n", corrNegTests)
	for n := 0; n < corrNegTests; n++ {
		rec := records[rand.Intn(corrTotal)]
		if rec.tokenData == nil {
			res.negativeFailed++
			continue
		}
		tampered := make([]byte, len(rec.tokenData))
		copy(tampered, rec.tokenData)
		tampered[len(tampered)/2] ^= 0xFF
		tamperedHash := hasher.HashLeaf(tampered)

		incProof, proofErr := pb.InclusionProof(ctx, rec.logIndex)
		if proofErr != nil {
			res.negativeFailed++
			continue
		}
		if err := proof.VerifyInclusion(
			hasher, rec.logIndex, finalCP.Size,
			tamperedHash, incProof, finalCP.Hash,
		); err != nil {
			res.negativePassed++ // correctly rejected
		} else {
			res.negativeFailed++ // incorrectly accepted
		}
	}
	fmt.Printf("  [correctness] Negative tests: %d passed, %d failed\n",
		res.negativePassed, res.negativeFailed)

	return res
}

// ── Token generators ─────────────────────────────────────────────────────────

func makeHTT(i int, s *signer.Signer) []byte {
	h1 := sha256.Sum256([]byte(fmt.Sprintf("sprint4-htt-%d-tpm", i)))
	h2 := sha256.Sum256([]byte(fmt.Sprintf("sprint4-htt-%d-cfg", i)))
	htt := &schema.HostTransparencyToken{
		TokenID:              fmt.Sprintf("token-%d", i),
		HostID:               fmt.Sprintf("host-%d", i%1000),
		AttestationServiceID: "sprint4-bench-attest-svc",
		BootTimestampUTC:     uint64(time.Now().Unix()),
		TPMMeasurementHash:   h1[:],
		BaselineConfigHash:   h2[:],
		SecureBootVerified:   true,
		BaselineMatch:        true,
	}
	data, err := s.SignHTT(htt)
	if err != nil {
		fatalf("SignHTT(%d): %v", i, err)
	}
	return data
}

func makeBTT(i int, s *signer.Signer) []byte {
	h1 := sha256.Sum256([]byte(fmt.Sprintf("sprint4-btt-%d-bin", i)))
	h2 := sha256.Sum256([]byte(fmt.Sprintf("sprint4-btt-%d-src", i)))
	btt := &schema.BinaryTransparencyToken{
		TokenID:            fmt.Sprintf("token-%d", i),
		BinaryHash:         h1[:],
		EventType:          schema.EventTypeBuild,
		IssuerID:           "sprint4-bench-build-svc",
		EventTimestamp:     uint64(time.Now().Unix()),
		SourceCommitHash:   h2[:],
		BuildProvenanceURI: fmt.Sprintf("https://example.com/slsa?entry=%d", i),
	}
	data, err := s.SignBTT(btt)
	if err != nil {
		fatalf("SignBTT(%d): %v", i, err)
	}
	return data
}

// ── Storage measurement ───────────────────────────────────────────────────────

func measureDirBytes(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ── CSV writers ───────────────────────────────────────────────────────────────

func writeThroughputCSV(results ...throughputResult) {
	path := filepath.Join(outputDir, "throughput.csv")
	f, err := os.Create(path)
	if err != nil {
		fatalf("create throughput.csv: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	must(w.Write([]string{"run", "target_rate", "duration_s", "entries_appended", "actual_rate", "backend"}))
	for _, r := range results {
		must(w.Write([]string{
			r.label,
			strconv.Itoa(r.target),
			fmt.Sprintf("%.2f", r.duration),
			strconv.FormatInt(r.confirmed, 10),
			fmt.Sprintf("%.2f", r.rate),
			"POSIX",
		}))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fatalf("flush throughput.csv: %v", err)
	}
	fmt.Printf("[sprint4] Wrote %s\n", path)
}

func writeStorageCSV(entries, totalBytes int64, bytesPerEntry float64) {
	path := filepath.Join(outputDir, "storage.csv")
	f, err := os.Create(path)
	if err != nil {
		fatalf("create storage.csv: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	must(w.Write([]string{"log_size_entries", "bytes_total", "bytes_per_entry"}))
	must(w.Write([]string{"0", "0", "0"}))
	must(w.Write([]string{
		strconv.FormatInt(entries, 10),
		strconv.FormatInt(totalBytes, 10),
		fmt.Sprintf("%.0f", bytesPerEntry),
	}))
	w.Flush()
	if err := w.Error(); err != nil {
		fatalf("flush storage.csv: %v", err)
	}
	fmt.Printf("[sprint4] Wrote %s\n", path)
}

func writeLatencyCSV(results []latencyResult) {
	path := filepath.Join(outputDir, "latency.csv")
	f, err := os.Create(path)
	if err != nil {
		fatalf("create latency.csv: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	must(w.Write([]string{"concurrency", "duration_s", "total_requests", "p50_ms", "p99_ms"}))
	for _, r := range results {
		must(w.Write([]string{
			strconv.Itoa(r.concurrency),
			fmt.Sprintf("%.2f", r.duration),
			strconv.FormatInt(r.totalReqs, 10),
			fmt.Sprintf("%.2f", r.p50ms),
			fmt.Sprintf("%.2f", r.p99ms),
		}))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fatalf("flush latency.csv: %v", err)
	}
	fmt.Printf("[sprint4] Wrote %s\n", path)
}

func writeCorrectnessCSV(r corrResult) {
	path := filepath.Join(outputDir, "correctness.csv")
	f, err := os.Create(path)
	if err != nil {
		fatalf("create correctness.csv: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	must(w.Write([]string{"test", "total", "passed", "failed"}))
	must(w.Write([]string{"inclusion_proofs",
		strconv.Itoa(r.inclusionTotal), strconv.Itoa(r.inclusionPassed), strconv.Itoa(r.inclusionFailed)}))
	must(w.Write([]string{"consistency_proofs",
		strconv.Itoa(r.consistencyTotal), strconv.Itoa(r.consistencyPassed), strconv.Itoa(r.consistencyFailed)}))
	must(w.Write([]string{"negative_tampered",
		strconv.Itoa(r.negativeTotal), strconv.Itoa(r.negativePassed), strconv.Itoa(r.negativeFailed)}))
	w.Flush()
	if err := w.Error(); err != nil {
		fatalf("flush correctness.csv: %v", err)
	}
	fmt.Printf("[sprint4] Wrote %s\n", path)
}

// ── Part 4: Final formatted summary table ────────────────────────────────────

const summaryBorder = "════════════════════════════════════════════════════════════"

func printFinalSummary(
	rA, rB throughputResult,
	storageBytes int64, bytesPerEntry float64,
	latResults []latencyResult,
	corr corrResult,
) {
	notRun := "(not run — pass --fresh to include)"

	fmt.Println()
	fmt.Println(summaryBorder)
	fmt.Println("  Sprint 4 — Benchmark & Correctness Summary")
	fmt.Println(summaryBorder)

	// ── THROUGHPUT ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  THROUGHPUT  (Table 5.1 data)")
	if rA.confirmed > 0 {
		// %-9s pads "1,000/s" to 9 chars so "→" aligns for both target widths.
		fmt.Printf("  Target %-9s→ actual %-9s (%d entries, %.0f s, POSIX backend)\n",
			commaf(float64(rA.target))+"/s", commaf(rA.rate)+"/s",
			rA.confirmed, rA.duration)
		fmt.Printf("  Target %-9s→ actual %-9s (%d entries, %.0f s, POSIX backend)\n",
			commaf(float64(rB.target))+"/s", commaf(rB.rate)+"/s",
			rB.confirmed, rB.duration)
	} else {
		fmt.Println(" ", notRun)
	}

	// ── PROOF LATENCY ─────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  PROOF LATENCY  (Table 5.1 data)")
	if len(latResults) > 0 {
		for _, r := range latResults {
			fmt.Printf("  %-22s p50=%.0f ms   p99=%.0f ms\n",
				fmt.Sprintf("%d concurrent clients:", r.concurrency),
				r.p50ms, r.p99ms)
		}
	} else {
		fmt.Println(" ", notRun)
	}

	// ── STORAGE GROWTH ────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  STORAGE GROWTH")
	if storageBytes > 0 {
		fmt.Printf("  %s bytes/entry  (total %.1f MB for %d entries, POSIX backend)\n",
			commaf(bytesPerEntry), float64(storageBytes)/1e6, rA.confirmed)
	} else {
		fmt.Println(" ", notRun)
	}

	// ── CORRECTNESS ───────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  CORRECTNESS  (Table 5.2 data)")
	if corr.inclusionTotal > 0 {
		fmt.Printf("  %-20s %4d/%-4d %s\n",
			"Inclusion proofs:",
			corr.inclusionPassed, corr.inclusionTotal,
			passOrFail(corr.inclusionPassed, corr.inclusionTotal))
		fmt.Printf("  %-20s %4d/%-4d %s\n",
			"Consistency proofs:",
			corr.consistencyPassed, corr.consistencyTotal,
			passOrFail(corr.consistencyPassed, corr.consistencyTotal))
		fmt.Printf("  %-20s %4d/%-4d %s\n",
			"Negative tests:",
			corr.negativePassed, corr.negativeTotal,
			passOrFail(corr.negativePassed, corr.negativeTotal))
	} else {
		fmt.Println("  (not run)")
	}

	fmt.Println()
	fmt.Println("  Raw data: ./data/sprint4/")
	fmt.Println(summaryBorder)
	fmt.Println()
}

// passOrFail returns "PASS" if passed == total (and total > 0), else "FAIL".
func passOrFail(passed, total int) string {
	if total > 0 && passed == total {
		return "PASS"
	}
	return "FAIL"
}

// ── Formatting helpers ────────────────────────────────────────────────────────

func commaf(v float64) string {
	s := fmt.Sprintf("%.0f", v)
	n := len(s)
	if n <= 3 {
		return s
	}
	b := make([]byte, 0, n+(n-1)/3)
	for i, c := range s {
		if i > 0 && (n-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func printBanner(msg string) {
	line := strings.Repeat("═", len(msg)+4)
	fmt.Printf("[sprint4] %s\n[sprint4] ║ %s ║\n[sprint4] %s\n", line, msg, line)
}

// ── Key management ────────────────────────────────────────────────────────────

func loadOrGenKey(path, name string) (skey, vkey string, err error) {
	if data, err2 := os.ReadFile(path); err2 == nil {
		if lines := splitLines(string(data)); len(lines) >= 2 {
			return lines[0], lines[1], nil
		}
	}
	sk, vk, err2 := note.GenerateKey(nil, name)
	if err2 != nil {
		return "", "", fmt.Errorf("generate key: %w", err2)
	}
	if err2 := os.MkdirAll(filepath.Dir(path), 0o755); err2 != nil {
		return "", "", fmt.Errorf("mkdir: %w", err2)
	}
	if err2 := os.WriteFile(path, []byte(sk+"\n"+vk+"\n"), 0o600); err2 != nil {
		return "", "", fmt.Errorf("write key file: %w", err2)
	}
	return sk, vk, nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// ── Error helpers ─────────────────────────────────────────────────────────────

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[sprint4] FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}
