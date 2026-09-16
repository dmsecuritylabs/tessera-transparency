// Package signer implements the Entry Signer component described in Chapter 3
// (Section 3.5) and Chapter 4 (Section 4.3) of the dissertation.
//
// The Entry Signer is responsible for:
//   - Managing the Ed25519 signing keypair (created once, persisted across runs)
//   - Signing the canonical encoding of fields 1–8 of each token
//   - Embedding the Ed25519 signature as field 9
//   - Serialising the complete signed token for submission to the Tessera log
//
// Key management: the signing key is stored as a note-format key pair in a file
// with mode 0600. A public log needs a stable key across runs so verifiers can
// authenticate tokens consistently across log sessions.
//
// Note key format (golang.org/x/mod/sumdb/note):
//   Private: "PRIVATE+KEY+<name>+<keyid>+<base64(1-byte-type + 32-byte-seed)>"
//   Public:  "<name>+<keyid>+<base64(1-byte-type + 32-byte-pubkey)>"
// Parsing splits the key string using strings.SplitN to preserve any '+' that
// appear inside the base64 data.
package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/dmendoza/tessera-transparency/internal/schema"
)

const keyFileName = "entry-signing-key.txt"

// Signer holds an Ed25519 signing key and provides methods to sign and verify
// HTT and BTT tokens.
type Signer struct {
	vkey string           // note-format public verifier key (for publishing)
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// New creates or loads a Signer. If keyDir already contains a saved key the
// same keypair is reused; otherwise a fresh one is generated and persisted.
func New(keyDir, keyName string) (*Signer, error) {
	keyPath := filepath.Join(keyDir, keyFileName)

	if data, err := os.ReadFile(keyPath); err == nil {
		lines := splitLines(string(data))
		if len(lines) >= 2 {
			s, err := fromNoteStrings(lines[0], lines[1])
			if err == nil {
				fmt.Printf("[signer] Loaded signing key from %s\n", keyPath)
				return s, nil
			}
		}
	}

	// Generate fresh keypair.
	skey, vkey, err := note.GenerateKey(nil, keyName)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(skey+"\n"+vkey+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	fmt.Printf("[signer] Generated signing key; saved to %s\n", keyPath)
	return fromNoteStrings(skey, vkey)
}

func fromNoteStrings(skey, vkey string) (*Signer, error) {
	priv, err := privFromNoteKey(skey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, err := pubFromNoteKey(vkey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return &Signer{vkey: vkey, priv: priv, pub: pub}, nil
}

// PublicKeyString returns the note-format public verifier key. This must be
// published alongside the log URL so that verifiers can authenticate tokens.
func (s *Signer) PublicKeyString() string { return s.vkey }

// SignHTT signs the token (fields 1–8) and returns the complete marshalled token.
func (s *Signer) SignHTT(t *schema.HostTransparencyToken) ([]byte, error) {
	t.Signature = nil
	msg, err := t.MarshalForSigning()
	if err != nil {
		return nil, fmt.Errorf("marshal HTT for signing: %w", err)
	}
	t.Signature = ed25519.Sign(s.priv, msg)
	return t.Marshal()
}

// SignBTT signs the token (fields 1–8) and returns the complete marshalled token.
func (s *Signer) SignBTT(t *schema.BinaryTransparencyToken) ([]byte, error) {
	t.Signature = nil
	msg, err := t.MarshalForSigning()
	if err != nil {
		return nil, fmt.Errorf("marshal BTT for signing: %w", err)
	}
	t.Signature = ed25519.Sign(s.priv, msg)
	return t.Marshal()
}

// VerifyHTT checks the Ed25519 signature embedded in the token.
func (s *Signer) VerifyHTT(t *schema.HostTransparencyToken) error {
	sig := t.Signature
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length %d (expected %d)", len(sig), ed25519.SignatureSize)
	}
	t.Signature = nil
	msg, err := t.MarshalForSigning()
	t.Signature = sig
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return fmt.Errorf("HTT signature verification failed")
	}
	return nil
}

// VerifyBTT checks the Ed25519 signature embedded in the token.
func (s *Signer) VerifyBTT(t *schema.BinaryTransparencyToken) error {
	sig := t.Signature
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length %d (expected %d)", len(sig), ed25519.SignatureSize)
	}
	t.Signature = nil
	msg, err := t.MarshalForSigning()
	t.Signature = sig
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.pub, msg, sig) {
		return fmt.Errorf("BTT signature verification failed")
	}
	return nil
}

// ── note key parsing ─────────────────────────────────────────────────────────
//
// Note private key format:  "PRIVATE+KEY+<name>+<keyid>+<base64payload>"
// Note public key format:   "<name>+<keyid>+<base64payload>"
//
// The base64 payload is 33 bytes: 1-byte type tag + 32-byte key material.
// strings.SplitN is used with an explicit limit so that any '+' characters
// inside the base64 data are preserved as part of the last segment.

func privFromNoteKey(skey string) (ed25519.PrivateKey, error) {
	// "PRIVATE+KEY+<name>+<keyid>+<base64>" → SplitN with N=5
	parts := strings.SplitN(strings.TrimSpace(skey), "+", 5)
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return nil, fmt.Errorf("not a note private key (parts=%d)", len(parts))
	}
	payload, err := decodeBase64Payload(parts[4])
	if err != nil {
		return nil, err
	}
	// payload[0] = type tag; payload[1:] = 32-byte ed25519 seed
	return ed25519.NewKeyFromSeed(payload[1:]), nil
}

func pubFromNoteKey(vkey string) (ed25519.PublicKey, error) {
	// "<name>+<keyid>+<base64>" → SplitN with N=3
	parts := strings.SplitN(strings.TrimSpace(vkey), "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a note public key (parts=%d)", len(parts))
	}
	payload, err := decodeBase64Payload(parts[2])
	if err != nil {
		return nil, err
	}
	// payload[0] = type tag; payload[1:] = 32-byte ed25519 public key
	return ed25519.PublicKey(payload[1:]), nil
}

func decodeBase64Payload(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64 decode key payload: %w", err)
		}
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("key payload: expected 33 bytes, got %d", len(raw))
	}
	return raw, nil
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
