# Implementation Log — Tessera Transparency Prototype

## Sprint 1: Environment Setup

### Entry 1 — 2026-06-30 16:32 UTC
**Task:** Establish Go development environment and confirm Tessera library is fetchable.

**Actions:**
- Checked environment: no Go toolchain pre-installed.
- Installed Go via `apt-get install golang-go` → resolved to Go 1.22.2.

**Problem 1 — Tessera requires Go >= 1.24:**
`go get github.com/transparency-dev/trillian-tessera@latest` failed:
`requires go >= 1.24.0 (running go 1.22.2)`. Go's automatic toolchain
switching attempted to fetch a newer toolchain from `golang.org`, which
is outside the network egress allowlist available in this environment.

**Resolution:** Installed `golang-1.24-go` via apt (available in
`noble-updates`), and used `update-alternatives` to set it as the
default `go` binary. Confirmed `go version` → `go1.24.4 linux/amd64`.

**Problem 2 — Module path renamed:**
`go get github.com/transparency-dev/trillian-tessera@latest` resolved
v1.0.2, but failed with:
`module declares its path as: github.com/transparency-dev/tessera
but was required as: github.com/transparency-dev/trillian-tessera`

This is a real finding for the literature review / background chapter:
the project has been renamed from `trillian-tessera` to `tessera`
between when prior documentation was reviewed and now. The correct,
current import path is `github.com/transparency-dev/tessera`.

**Resolution:** Re-ran `go get github.com/transparency-dev/tessera@v1.0.2`.

**Problem 3 — Restricted network egress blocks golang.org/x/* and
go.opentelemetry.io and k8s.io vanity import paths:**
Go resolves "vanity" import paths (e.g. `golang.org/x/crypto`,
`go.opentelemetry.io/otel`, `k8s.io/klog/v2`) by fetching an HTML
meta tag from the vanity domain itself to discover the actual VCS
repository, even when `GOPROXY=direct` is set. The sandboxed network
environment used for this project allowlists `github.com` and
`codeload.github.com` but not `golang.org`, `go.opentelemetry.io`, or
`k8s.io`, so these resolutions failed with 403 Forbidden / "Host not
in allowlist" errors for six distinct import paths:
- golang.org/x/crypto
- golang.org/x/mod
- golang.org/x/sync
- k8s.io/klog/v2
- go.opentelemetry.io/otel (+ /metric, /trace)
- go.opentelemetry.io/auto/sdk

**Resolution:** Added explicit `replace` directives in `go.mod`
mapping each vanity import path to its canonical GitHub mirror
repository at the exact required version/commit tag, e.g.:
```
replace golang.org/x/crypto => github.com/golang/crypto v0.48.0
replace go.opentelemetry.io/otel => github.com/open-telemetry/opentelemetry-go v1.40.0
```
Tag existence for each exact required version was confirmed via
`git ls-remote --tags` against each mirror before adding the
directive. All eight replace directives were required before the
full dependency graph resolved successfully.

**Outcome:** `go get github.com/transparency-dev/tessera@v1.0.2`
completed successfully, resolving 18 packages. A minimal program
importing the `tessera` package was written and compiled successfully
with `go build`, confirming the library is usable in this environment.

**Time spent:** ~25 minutes, almost entirely on network/dependency
resolution rather than application logic. This is a legitimate
implementation challenge worth reporting in Chapter 4 §4.1: a
production-grade Go library with a healthy dependency tree assumes
unrestricted access to a handful of well-known vanity domains that
are not, in general, guaranteed to be reachable in constrained or
air-gapped build environments — a real-world consideration for
infrastructure transparency tooling, which is often deployed in
exactly such constrained environments.

**Go module versions resolved:**
- github.com/transparency-dev/tessera v1.0.2
- github.com/transparency-dev/merkle v0.0.2
- github.com/transparency-dev/formats v0.0.0-20251017110053-404c0d5b696c
- (+ 15 transitive dependencies, see go.sum)

## Sprint 1 (continued): First Working Append/Prove/Verify Cycle

### Entry 2 — 2026-06-30 16:39 UTC
**Task:** Append a leaf to a real POSIX-backed Tessera log, fetch a
checkpoint, build and verify an inclusion proof, and confirm a tampered
leaf is correctly rejected (Sprint 1 exit criterion).

**Implementation notes (API discovery):**
The actual Tessera v1.0.2 client API differs in several specifics from
what might be assumed from the README alone, and from earlier
documentation referenced in Chapter 2:
- Leaf hashing must use `rfc6962.DefaultHasher.HashLeaf()` from the
  `github.com/transparency-dev/merkle/rfc6962` package, not a raw
  `sha256.Sum256()` of the leaf bytes. RFC 6962 leaf hashes include a
  domain-separation prefix byte (0x00) precisely to prevent a
  second-preimage attack where an internal node hash collides with a
  leaf hash; using a raw hash bypasses this protection.
- Checkpoints are returned as note-formatted, Ed25519-signed byte
  blobs (origin line, size line, base64 root hash line, blank line,
  signature line). They must be parsed with
  `formats/log.Checkpoint.Unmarshal()` to extract the tree size and
  root hash before they are usable in proof verification.
- Inclusion and consistency proof construction
  (`client.NewProofBuilder`, `.InclusionProof()`,
  `.ConsistencyProof()`) and proof verification
  (`merkle/proof.VerifyInclusion()`, `.VerifyConsistency()`) are in two
  separate packages: the client package only builds proofs by fetching
  tiles, while the actual cryptographic verification logic lives in
  the `transparency-dev/merkle` module, independent of Tessera itself.
  This is a direct illustration of the operator/verifier separation
  discussed in Ch.2 §2.1: a verifier needs only the `merkle` module
  and the published checkpoint, not the Tessera log-writing library.

**Outcome (Sprint 1, `cmd/sprint1`):**
A single leaf was appended to a fresh POSIX-backed log. The returned
checkpoint (tree size 1) was parsed, an inclusion proof was built and
verified successfully against the real RFC 6962 leaf hash, and a
negative test using a tampered leaf hash was correctly rejected by
`VerifyInclusion`.

**Outcome (Sprint 1b, `cmd/sprint1b`):**
Ten leaves were appended across two batches (5 + 5), producing two
checkpoints, cp1 (size 5) and cp2 (size 10). Inclusion proofs were
built and verified for leaves at indices 0, 4, and 9 against cp2.
A consistency proof between cp1 and cp2 was built and verified,
confirming cp2 is a valid append-only extension of cp1. A negative
test using a forged cp1 root hash was correctly rejected by
`VerifyConsistency`.

**Significance for the dissertation:** this is the first complete,
working demonstration of the append-prove-verify cycle described in
the methodology (proposal §1.2, Phase 3) and satisfies the first half
of Objective O4 (full append-prove-verify cycle demonstrated; the
remaining half of O4 is extending this to the Host and Binary
Transparency Token schemas designed in Chapter 3, rather than raw
byte leaves, which is the next implementation step).

**Time spent:** ~35 minutes, split roughly evenly between reading the
real Tessera/merkle API (the official `cmd/examples/posix-oneshot`
example was used as a reference) and writing/debugging the two
milestone programs.
