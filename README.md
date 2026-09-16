# Tessera Transparency Prototype — Dissertation Working Repository

CYM500 Cyber Security Project (University of London, MSc Cybersecurity)
"Tessera as General-Purpose Transparency Infrastructure"

## What this is

This is the in-progress prototype implementation supporting Chapter 4
(Implementation) of the dissertation. It uses 
`github.com/transparency-dev/tessera` v1.0.2 library  against a local POSIX-backed log.

## Status: Sprint 1 complete

- `cmd/sprint1` — appends a single leaf, fetches a checkpoint, builds
  and verifies an inclusion proof, and runs a negative (tamper) test.
- `cmd/sprint1b` — appends 10 leaves across two batches, verifies
  inclusion proofs for three of them, and verifies a consistency
  proof between the two checkpoints, plus a negative test on a forged
  root.

See `docs/implementation_log.md` for a detailed, timestamped log of
what was built, what problems were encountered (including real
environment/dependency issues), and how they were resolved. This log
is intended as source material for Chapter 4's account of the
engineering decisions made during implementation.

## Requirements

- Go 1.24 or later (Tessera v1.0.2 requires `go >= 1.24.0`)
- Internet access to github.com (the module and its dependencies are
  fetched directly from GitHub mirrors; see "A note on go.mod" below)

## How to run

```bash
# from the repository root
go build ./...

# Sprint 1: single leaf append/prove/verify
go run ./cmd/sprint1

# Sprint 1b: multi-leaf append, inclusion + consistency proofs
go run ./cmd/sprint1b
```

Each program creates its own log data directory under `data/` (wiped
and recreated on every run, so it is safe to re-run repeatedly) and
prints a full trace of every step: key generation, append, checkpoint
issuance, proof construction, proof verification, and negative tests.

## A note on go.mod — why there are so many `replace` directives

This module was developed in a network-sandboxed environment that
allowlists `github.com`, `codeload.github.com`, and a small number of
other domains, but does not allowlist `golang.org`, `go.opentelemetry.io`,
`k8s.io`, or `gopkg.in`. Go's standard module resolution fetches
"vanity import path" metadata directly from the domain named in the
import path (e.g. `golang.org/x/crypto`), even when `GOPROXY=direct`
is set. Because several of Tessera's dependencies use such vanity
import paths, `replace` directives were added in `go.mod` to map each
one to its canonical GitHub mirror at the exact required version.

If you are running this on a normal, unrestricted network connection,
these `replace` directives are not required, but they are harmless to
leave in place: they pin to the same code, just fetched via a
different path. You are welcome to delete them and run
`go mod tidy` if you prefer the canonical import paths and have
unrestricted network access.

This entire process — including the exact errors encountered and the
reasoning behind each fix — is documented in
`docs/implementation_log.md` and is referenced in Chapter 4 §4.1 of
the dissertation as a concrete example of project challenge.

## Repository layout

```
.
├── cmd/
│   ├── sprint1/      single-leaf append/prove/verify milestone
│   └── sprint1b/      multi-leaf, inclusion + consistency proof milestone
├── docs/
│   └── implementation_log.md   timestamped build log for Ch.4
├── data/              local log storage (created at runtime, gitignored)
├── go.mod
├── go.sum
└── README.md           this file
```

## Next steps (not yet implemented)

- Host Transparency Token and Binary Transparency Token Proto3 schemas
  (designed in Chapter 3) need to be wired into the Entry Signer and
  appended as real log entries, replacing the placeholder string leaves
  used in Sprint 1/1b.
- Verifier CLI as a standalone, reusable tool (currently the
  verification logic lives inline in the sprint programs).
- REST API layer.
- Performance benchmarking harness for Chapter 5.
# tessera-transparency
