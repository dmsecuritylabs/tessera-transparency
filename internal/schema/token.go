// Package schema defines the Go structs for the Host Transparency Token (HTT)
// and Binary Transparency Token (BTT) entry schemas specified in Chapter 3 of
// the dissertation. The structs mirror the Proto3 definitions in proto/htt.proto
// and proto/btt.proto exactly, field-for-field and in the same field order.
//
// Serialisation uses encoding/json rather than generated protobuf code. Go's
// json.Marshal is deterministic for structs: fields are always encoded in the
// order they appear in the struct definition, which matches the Proto3 field
// numbering order. This guarantees that the same logical token always produces
// the same byte sequence, which is required for the RFC 6962 leaf hash to be
// reproducible across the Entry Signer and the Verifier CLI.
//
// The decision to use JSON rather than generated protobuf code is documented in
// the implementation log (docs/implementation_log.md). Both produce
// deterministic output for these fixed-schema messages; JSON was chosen to keep
// the toolchain dependency surface minimal in the prototype environment.
package schema

import (
	"encoding/json"
	"fmt"
)

// BinaryEventType mirrors the Proto3 enum of the same name.
type BinaryEventType int

const (
	EventTypeBuild      BinaryEventType = 0
	EventTypeDeployment BinaryEventType = 1
)

func (e BinaryEventType) String() string {
	switch e {
	case EventTypeBuild:
		return "BUILD"
	case EventTypeDeployment:
		return "DEPLOYMENT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(e))
	}
}

// HostTransparencyToken mirrors the Proto3 message HostTransparencyToken.
// Fields are in Proto3 field-number order (1–9). Field 9 (Signature) covers
// the Ed25519 signature over the canonical encoding of fields 1–8.
type HostTransparencyToken struct {
	TokenID              string `json:"token_id"`               // field 1: UUID
	HostID               string `json:"host_id"`                // field 2: pseudonymised host ID (C1 subject)
	AttestationServiceID string `json:"attestation_service_id"` // field 3: issuer ID (C1)
	BootTimestampUTC     uint64 `json:"boot_timestamp_utc"`     // field 4: Unix epoch seconds (C2)
	TPMMeasurementHash   []byte `json:"tpm_measurement_hash"`   // field 5: SHA-256 of TPM quote (C3)
	BaselineConfigHash   []byte `json:"baseline_config_hash"`   // field 6: SHA-256 of config (C3)
	SecureBootVerified   bool   `json:"secure_boot_verified"`   // field 7: attestation outcome (C4)
	BaselineMatch        bool   `json:"baseline_match"`         // field 8: attestation outcome (C4)
	Signature            []byte `json:"signature,omitempty"`    // field 9: Ed25519 over fields 1-8
}

// BinaryTransparencyToken mirrors the Proto3 message BinaryTransparencyToken.
type BinaryTransparencyToken struct {
	TokenID                  string          `json:"token_id"`                   // field 1
	BinaryHash               []byte          `json:"binary_hash"`                // field 2: SHA-256 of artefact
	EventType                BinaryEventType `json:"event_type"`                 // field 3: BUILD or DEPLOYMENT (C2)
	IssuerID                 string          `json:"issuer_id"`                  // field 4: build system or gating svc (C1)
	EventTimestamp           uint64          `json:"event_timestamp"`            // field 5: Unix epoch seconds (C2)
	SourceCommitHash         []byte          `json:"source_commit_hash"`         // field 6: BUILD only (C3)
	BuildProvenanceURI       string          `json:"build_provenance_uri"`       // field 7: SLSA URI (C3)
	VerificationEvidenceHash []byte          `json:"verification_evidence_hash"` // field 8: DEPLOYMENT only (C3)
	Signature                []byte          `json:"signature,omitempty"`        // field 9: Ed25519 over fields 1-8
}

// MarshalForSigning returns the canonical JSON encoding of the HTT with the
// Signature field cleared. This is the byte sequence that the Entry Signer
// signs and that the Verifier must reproduce to check the signature.
func (h *HostTransparencyToken) MarshalForSigning() ([]byte, error) {
	copy := *h
	copy.Signature = nil
	return json.Marshal(copy)
}

// Marshal returns the canonical JSON encoding of the complete HTT including
// the Signature field. This is the byte sequence submitted to the Tessera log.
func (h *HostTransparencyToken) Marshal() ([]byte, error) {
	return json.Marshal(h)
}

// MarshalForSigning returns the canonical JSON encoding of the BTT with the
// Signature field cleared.
func (b *BinaryTransparencyToken) MarshalForSigning() ([]byte, error) {
	copy := *b
	copy.Signature = nil
	return json.Marshal(copy)
}

// Marshal returns the canonical JSON encoding of the complete BTT.
func (b *BinaryTransparencyToken) Marshal() ([]byte, error) {
	return json.Marshal(b)
}

// UnmarshalHTT deserialises a byte slice into a HostTransparencyToken.
func UnmarshalHTT(data []byte) (*HostTransparencyToken, error) {
	var t HostTransparencyToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal HTT: %w", err)
	}
	return &t, nil
}

// UnmarshalBTT deserialises a byte slice into a BinaryTransparencyToken.
func UnmarshalBTT(data []byte) (*BinaryTransparencyToken, error) {
	var t BinaryTransparencyToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal BTT: %w", err)
	}
	return &t, nil
}
