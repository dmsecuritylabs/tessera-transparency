# Tessera Transparency Prototype — Dissertation Working Repository

CYM500 Cyber Security Project (University of London, MSc Cybersecurity)
"Tessera as General-Purpose Transparency Infrastructure"

## What this is

This is the prototype implementation supporting the dissertation. It uses
`github.com/transparency-dev/tessera` v1.0.2 against a local POSIX-backed
append-only Merkle log to demonstrate general-purpose transparency
infrastructure for Host Transparency Tokens (HTT) and Binary Transparency
Tokens (BTT).

## Status: All sprints complete

| Sprint | Program | Description |
|--------|---------|-------------|
| 1 | `cmd/sprint1` | Single-leaf append, inclusion proof, negative tamper test |
| 1b | `cmd/sprint1b` | Multi-leaf append, inclusion + consistency proofs |
| 2 | `cmd/sprint2` | HTT/BTT token signing and appending via `internal/signer` |
| 3 | `cmd/sprint3` | Full REST API integration test (all four endpoints) |
| 4 | `cmd/sprint4` | Throughput benchmark, proof-latency benchmark, correctness suite |
| — | `cmd/verify` | Standalone stateless Verifier CLI (local filesystem or HTTP) |

See `docs/implementation_log.md` for a detailed, timestamped log of what was
built, problems encountered, and how they were resolved — source material for
Chapter 4's engineering account.

## Requirements

- Go 1.24 or later (Tessera v1.0.2 requires `go >= 1.24.0`)
- Internet access to github.com (dependencies fetched from GitHub mirrors; see
  "A note on go.mod" below)

## How to run

```bash
# Build everything
go build ./...

# Sprint 1: single leaf append/prove/verify
go run ./cmd/sprint1

# Sprint 1b: multi-leaf, inclusion + consistency proofs
go run ./cmd/sprint1b

# Sprint 2: HTT + BTT token signing and log append
go run ./cmd/sprint2

# Sprint 3: REST API integration test (starts server, exercises all endpoints)
go run ./cmd/sprint3 --fresh=true

# Sprint 4: full benchmark + correctness suite (Chapter 5 evaluation data)
go run ./cmd/sprint4 --fresh=true

# Verifier CLI — local filesystem
go run ./cmd/verify --log_dir=./data/log --index=0 --leaf_hex=<hex>

# Verifier CLI — remote HTTP
go run ./cmd/verify --log_url=http://localhost:8081 --index=0 --leaf_hex=<hex>
```

Each program creates its own log data directory under `data/` (gitignored).

## Sprint 4 — Benchmark & Correctness Suite

`cmd/sprint4` is the Chapter 5 evaluation harness. It runs three phases:

- **Throughput** — two 30-second runs at target rates of 1,000 and 10,000
  entries/sec on fresh POSIX logs, measuring confirmed append rate and storage
  growth. Output: `data/sprint4/throughput.csv`, `data/sprint4/storage.csv`.
- **Proof latency** — re-opens the Run A log behind the REST API and measures
  `GET /token/prove` round-trip latency at 10 and 50 concurrent clients (p50,
  p99). Output: `data/sprint4/latency.csv`.
- **Correctness** — appends 1,000 entries (500 HTT + 500 BTT) to a fresh log,
  takes 10 checkpoint snapshots, verifies all 1,000 inclusion proofs, 9
  consecutive consistency proofs, and 50 negative tamper tests. Exits 1 on any
  failure. Output: `data/sprint4/correctness.csv`.

Use `--fresh=false` to skip throughput/latency and re-run only the correctness
suite.

## Internal packages

| Package | Description |
|---------|-------------|
| `internal/schema` | Proto3-derived Go structs for HTT and BTT |
| `internal/signer` | Ed25519 entry signer with persistent key management |
| `internal/api` | REST API handler and HTTP server (4 endpoints) |

## REST API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/token/submit` | Append a token; returns index, leaf hash, tree size, root |
| `GET` | `/token/prove?index=N` | Inclusion proof for entry at index N |
| `GET` | `/log/sth` | Current Signed Tree Head (size, root, raw checkpoint) |
| `GET` | `/log/consistency?from=M&to=N` | Consistency proof between two tree sizes |

## A note on go.mod — why there are so many `replace` directives

This module was developed in a network-sandboxed environment that allowlists
`github.com` but does not allowlist `golang.org`, `go.opentelemetry.io`,
`k8s.io`, or `gopkg.in`. `replace` directives map each vanity import path to
its canonical GitHub mirror at the exact required version.

On a normal unrestricted network these directives are harmless — they pin to
the same code via a different path. You can delete them and run `go mod tidy`
if you prefer canonical import paths.

This is documented in `docs/implementation_log.md` and referenced in
Chapter 4 §4.1 as a concrete example of a project challenge.

## Repository layout

```
.
├── cmd/
│   ├── sprint1/        single-leaf append/prove/verify
│   ├── sprint1b/       multi-leaf, inclusion + consistency proofs
│   ├── sprint2/        HTT/BTT token signing and append
│   ├── sprint3/        REST API integration test
│   ├── sprint4/        benchmark and correctness suite (Ch. 5)
│   └── verify/         standalone Verifier CLI
├── internal/
│   ├── api/            REST API handler and server
│   ├── schema/         HTT and BTT token types
│   └── signer/         Ed25519 entry signer
├── proto/              HTT and BTT Proto3 definitions
├── docs/
│   └── implementation_log.md   timestamped build log for Ch. 4
├── data/               runtime log storage (gitignored)
├── go.mod
├── go.sum
└── README.md
```
