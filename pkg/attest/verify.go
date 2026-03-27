// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"fmt"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	"github.com/sigstore/sigstore-go/pkg/verify"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type VerificationOptions struct {
	ExpectedIssuer string
	ExpectedSan    string
	// PublicKey is used for DSSE verification (if provided)
	PublicKey string
}

const (
	// ExpectedIssuer is the OIDC issuer found in the sigstore bundles
	ExpectedIssuer = "https://token.actions.githubusercontent.com"

	// Expected SAN is the expected identity of the workflow signing the
	// provenance and VSAs.
	ExpectedSan = "https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"

	// OldExpectedSan is the old singer identity before splitting out the actions to their own repo
	// this constant is part of a compatibility hack that should be reverted once the latests attestations
	// of the repos are signed with the new identity.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	OldExpectedSan = "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main"
)

// TODO: Update ExpectedSan to support regex so we can get the branches/tags we really think
// folks should be using (they won't all run from main).
var DefaultVerifierOptions = VerificationOptions{
	ExpectedIssuer: ExpectedIssuer,
	ExpectedSan:    ExpectedSan,
}

type Verifier interface {
	Verify(data string) (*verify.VerificationResult, error)
}

type BndVerifier struct {
	Options VerificationOptions
}

func (bv *BndVerifier) Verify(data string) (*verify.VerificationResult, error) {
	// Try to parse as DSSE first
	if bv.Options.PublicKey != "" {
		stmt, err := bv.verifyDSSE(data)
		if err == nil && stmt != nil {
			// Return a minimal verification result for DSSE
			return &verify.VerificationResult{
				Statement: stmt,
			}, nil
		}
		// If DSSE verification fails or no public key, fall through to sigstore
	}

	// Verify the signed bundle (sigstore)
	verifier := signer.NewVerifier()

	// Verify the signed bundle
	vr, err := verifier.VerifyInlineBundle(
		[]byte(data),
		options.WithExpectedIdentity(
			bv.Options.ExpectedIssuer, bv.Options.ExpectedSan,
		),
	)
	if err != nil {
		return nil, err
	}
	return vr, nil
}

// verifyDSSE verifies a DSSE envelope and returns the statement
func (bv *BndVerifier) verifyDSSE(data string) (*spb.Statement, error) {
	// Try to parse as DSSE
	envelope := &sdsse.Envelope{}
	if err := protojson.Unmarshal([]byte(data), envelope); err != nil {
		return nil, err
	}

	// Check if this looks like DSSE (has payload and payloadType fields)
	if len(envelope.Payload) == 0 || envelope.PayloadType == "" {
		return nil, fmt.Errorf("not a valid DSSE envelope: missing payload or payloadType")
	}

	// Parse the public key
	publicKey, err := key.NewParser().ParsePublicKey([]byte(bv.Options.PublicKey))
	if err != nil {
		return nil, err
	}

	// Verify the DSSE envelope
	verifier := signer.NewVerifier()
	result, err := verifier.VerifyParsedDSSE(envelope, []key.PublicKeyProvider{publicKey})
	if err != nil {
		return nil, err
	}
	if result == nil || !result.Verified {
		return nil, fmt.Errorf("DSSE verification failed")
	}

	// The payload is already decoded by protojson (stored as []byte in the proto)
	// Just use it directly
	payloadBytes := envelope.Payload

	// Parse as in-toto statement
	statement := &spb.Statement{}
	if err := protojson.Unmarshal(payloadBytes, statement); err != nil {
		return nil, err
	}

	return statement, nil
}

type DSSEVerifier struct {
	PublicKey string
}

// Verify verifies a DSSE envelope
func (dv *DSSEVerifier) Verify(data string) (*spb.Statement, error) {
	// Try to parse as DSSE
	envelope := &sdsse.Envelope{}
	if err := protojson.Unmarshal([]byte(data), envelope); err != nil {
		return nil, err
	}

	// Check if this looks like DSSE (has payload and payloadType fields)
	if len(envelope.Payload) == 0 || envelope.PayloadType == "" {
		return nil, fmt.Errorf("not a valid DSSE envelope: missing payload or payloadType")
	}

	// Parse the public key
	publicKey, err := key.NewParser().ParsePublicKey([]byte(dv.PublicKey))
	if err != nil {
		return nil, err
	}

	// Verify the DSSE envelope
	verifier := signer.NewVerifier()
	result, err := verifier.VerifyParsedDSSE(envelope, []key.PublicKeyProvider{publicKey})
	if err != nil {
		return nil, err
	}
	if result == nil || !result.Verified {
		return nil, fmt.Errorf("DSSE verification failed")
	}

	// The payload is already decoded by protojson (stored as []byte in the proto)
	// Just use it directly
	payloadBytes := envelope.Payload

	// Parse as in-toto statement
	statement := &spb.Statement{}
	if err := protojson.Unmarshal(payloadBytes, statement); err != nil {
		return nil, err
	}

	return statement, nil
}

// isDSSE checks if a string looks like a DSSE envelope
func isDSSE(data string) bool {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(data), &obj); err != nil {
		return false
	}
	// DSSE has payload, payloadType, and signatures fields
	_, hasPayload := obj["payload"]
	_, hasPayloadType := obj["payloadType"]
	_, hasSignatures := obj["signatures"]
	return hasPayload && hasPayloadType && hasSignatures
}

func NewBndVerifier(opts VerificationOptions) *BndVerifier {
	return &BndVerifier{Options: opts}
}

func GetDefaultVerifier() Verifier {
	return NewBndVerifier(DefaultVerifierOptions)
}
