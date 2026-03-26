// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	"google.golang.org/protobuf/encoding/protojson"
)

func Sign(data string) (string, error) {
	bundle, err := signer.NewSigner().SignStatement(
		[]byte(data), options.WithPayloadType("application/vnd.in-toto+json"),
	)
	if err != nil {
		return "", err
	}

	json, err := protojson.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(json), nil
}

// parsePEMPrivateKey parses a PEM-encoded private key and returns a key.Private
func parsePEMPrivateKey(keyData []byte) (*key.Private, error) {
	blk, _ := pem.Decode(keyData)
	if blk == nil || blk.Bytes == nil {
		return nil, errors.New("unable to decode PEM private key")
	}

	// Try to parse as different key types
	var privKey crypto.PrivateKey
	var keyType key.Type
	var scheme key.Scheme
	var hashType crypto.Hash

	// Try PKCS8 first (works for all key types)
	privKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		// Try PKCS1 (RSA only)
		privKey, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			// Try ECPrivateKey
			privKey, err = x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing private key: %w", err)
			}
		}
	}

	// Determine key type and set defaults
	switch pk := privKey.(type) {
	case *rsa.PrivateKey:
		keyType = key.RSA
		scheme = key.RsaSsaPssSha256
		hashType = crypto.SHA256
	case *ecdsa.PrivateKey:
		keyType = key.ECDSA
		switch pk.Curve.Params().Name {
		case elliptic.P256().Params().Name:
			scheme = key.EcdsaSha2nistP256
			hashType = crypto.SHA256
		case elliptic.P384().Params().Name:
			scheme = key.EcdsaSha2nistP384
			hashType = crypto.SHA384
		case elliptic.P521().Params().Name:
			scheme = key.EcdsaSha2nistP521
			hashType = crypto.SHA512
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", pk.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		keyType = key.ED25519
		scheme = key.Ed25519
		hashType = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privKey)
	}

	// Marshal back to PEM for storage
	pemData, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pemData,
	})

	return &key.Private{
		Type:     keyType,
		Scheme:   scheme,
		HashType: hashType,
		Data:     string(pemBlock),
		Key:      privKey.(crypto.PublicKey),
	}, nil
}

// SignWithPrivateKey signs data using a PEM-encoded private key.
func SignWithPrivateKey(data string, privateKeyPath string) (string, error) {
	// Read the private key file
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("reading private key file: %w", err)
	}

	// Parse the private key
	privKey, err := parsePEMPrivateKey(keyData)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	// Create a signer
	s := signer.NewSigner()

	// Sign using DSSE only (not sigstore bundle)
	envelope, err := s.SignMessageToDSSE(
		[]byte(data), options.WithPayloadType("application/vnd.in-toto+json"), options.WithKey(privKey),
	)
	if err != nil {
		return "", err
	}

	// Wrap in a minimal DSSE bundle format (without sigstore)
	// This is the DSSE-only format that can be verified with the public key
	json, err := protojson.Marshal(envelope)
	if err != nil {
		return "", err
	}

	return string(json), nil
}
