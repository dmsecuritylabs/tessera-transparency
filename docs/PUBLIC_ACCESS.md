# Making the Log Publicly Accessible

This document describes three approaches to serving the Tessera transparency log
publicly, from simplest to most infrastructure-intensive. All three build on the
same POSIX tile directory that `cmd/sprint2` writes.

---

## Why public access matters for the dissertation

A transparency log only fulfils its security purpose if independent verifiers
can audit it. "Running it locally" is proof of concept; "making it verifiable
by anyone" is the actual research contribution. This guide bridges that gap.

The tile-based design of Tessera (Chapter 2, Section 2.2) makes public access
particularly straightforward: tiles are static, immutable, content-addressed
files. Any HTTP file server that serves them with the correct path layout is a
conforming tile server. No dynamic computation is required at serve time.

---

## Option A: GitHub Pages (recommended for the dissertation prototype)

This is the simplest approach and requires no cloud account or server.

### Step 1: Initialise a repository

```bash
cd tessera-transparency
git init
git remote add origin git@github.com:<your-username>/tessera-transparency.git
```

### Step 2: Run the log and commit the tiles

```bash
go run ./cmd/sprint2 --log_dir=./data/log --key_dir=./data/keys
```

Add a GitHub Actions workflow that runs this on a schedule and pushes tiles:

```yaml
# .github/workflows/append.yml
name: Append log entries
on:
  schedule:
    - cron: '0 * * * *'   # hourly
  workflow_dispatch:

jobs:
  append:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.24' }
      - run: go run ./cmd/sprint2 --log_dir=./data/log --key_dir=./data/keys
      - name: Commit tiles
        run: |
          git config user.email "action@github.com"
          git config user.name "GitHub Actions"
          git add data/log/
          git diff --staged --quiet || git commit -m "Append log entries $(date -u)"
          git push
```

### Step 3: Enable GitHub Pages

In your repository settings, set the Pages source to the `main` branch, root
directory. GitHub Pages will serve the tile files at:

    https://<your-username>.github.io/tessera-transparency/data/log/

### Step 4: Verify remotely

Any verifier can now fetch tiles and verify inclusion proofs:

```bash
# Fetch the current checkpoint
curl https://<your-username>.github.io/tessera-transparency/data/log/checkpoint

# Use the verifier CLI (Sprint 3) with the public URL:
go run ./cmd/verify \
  --log_url=https://<your-username>.github.io/tessera-transparency/data/log \
  --token_index=0
```

---

## Option B: Cloudflare Pages or Netlify (faster CDN, zero config)

Identical to Option A but the static files are served by Cloudflare or Netlify
rather than GitHub Pages. Both support deploying from a GitHub repository.
Advantage: global CDN with better cache hit rates for tiles (the tlog-tiles
design was explicitly optimised for CDN deployment — see Chapter 2, Section 2.2).

1. Connect your GitHub repository to Cloudflare Pages or Netlify.
2. Set the publish directory to `data/log`.
3. The tile server URL will be `https://<your-site>.pages.dev/`.

---

## Option C: Add a Public Witness (cross-ecosystem trust anchor)

A *witness* is an independent party that checks consistency proofs between
consecutive checkpoints and counter-signs the checkpoint if the log has behaved
correctly (append-only). Witnessed checkpoints are stronger trust anchors than
unwitnessed ones: they prove the log has never forked.

The C2SP witness protocol (https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)
defines a standard HTTP API for witnesses. The transparency.dev ecosystem
maintains public witnesses at:

    https://github.com/transparency-dev/witness

### How to get your log witnessed

1. **Register your log** with a public witness by creating a pull request to the
   witness's log registry, providing your log's name, URL, and public verifier key.
   Your verifier key is printed by `cmd/sprint2` as "Entry signer public key".

2. **Submit checkpoints** after each append run:

```bash
# Fetch your latest checkpoint
CHECKPOINT=$(curl -s https://<your-log-url>/checkpoint)

# POST it to a witness
curl -X POST https://<witness-url>/add-checkpoint \
  -H "Content-Type: text/plain" \
  --data "$CHECKPOINT"
```

3. The witness returns a counter-signed checkpoint. Store it and serve it at
   `/checkpoint` alongside the original signature so verifiers can see both.

### For the dissertation

Witnessing is listed as a future work direction in Chapter 6, Section 6.3.
The fact that Tessera's checkpoint format is natively compatible with the C2SP
witness protocol (both use the note format) means that a witnessed version of
this prototype log requires no code changes — only the operational steps above.

---

## Running the built-in tile server locally for testing

The Sprint 2 program includes a lightweight tile server (`internal/server`) that
serves the POSIX tile directory over HTTP on localhost. To expose it publicly
during development, use a tunnel:

```bash
# Start the log and tile server on port 8080
go run ./cmd/sprint2 --serve=":8080"

# In another terminal, expose port 8080 with cloudflared (free):
cloudflared tunnel --url http://localhost:8080

# Or with ngrok:
ngrok http 8080
```

The tunnel URL printed by cloudflared or ngrok is a working public tile server
URL for the duration of the tunnel session. This is suitable for demonstration
and for submitting checkpoints to a witness.

---

## Quick-reference: key files to publish

| File | Purpose |
|------|---------|
| `data/keys/entry-signing-key.txt` (line 2 only — the public key) | Entry token authentication |
| `data/keys/checkpoint-key.txt` (line 2 only) | Checkpoint STH authentication |
| `data/log/checkpoint` | Current signed tree head |
| `data/log/tile/...` | Tile data (served by HTTP file server) |

**Never publish line 1 of either key file** (the private key).
