// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"iter"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/vcs"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

type Auditor struct {
	conn     vcs.VcsConnection
	provider vcscontrol.ControlProvider
	// TODO: This should probably be turned into a pointer.
	verifier attest.Verifier
	pa       *attest.ProvenanceAttestor
}

type AuditCommitResult struct {
	Commit   string
	VsaPred  *vpb.VerificationSummary
	ProvPred *provenance.SourceProvenancePred
	// The previous commit reported by VCS.
	GhPriorCommit   string
	GhControlStatus vcscontrol.ControlStatus
}

// IsGood returns true if the audit result passes validation criteria:
// - Must have a VSA
// - Must have provenance
// - Provenance's prevCommit must match the VCS prior commit
func (ar *AuditCommitResult) IsGood() bool {
	// Have to have a VSA
	good := ar.VsaPred != nil

	// Have to have provenance
	if ar.ProvPred == nil {
		good = false
	} else if ar.ProvPred.GetPrevCommit() != ar.GhPriorCommit {
		// Commits need to be the same.
		good = false
	}

	return good
}

// NewAuditor creates a new Auditor with vcscontrol components
func NewAuditor(conn vcscontrol.Connection, provider vcscontrol.ControlProvider, pa *attest.ProvenanceAttestor, verifier attest.Verifier) *Auditor {
	return &Auditor{
		conn:     conn,
		provider: provider,
		verifier: verifier,
		pa:       pa,
	}
}

func (a *Auditor) AuditCommit(ctx context.Context, commit string) (ar *AuditCommitResult, err error) {
	ar = &AuditCommitResult{Commit: commit}

	_, vsa, err := attest.GetVsa(ctx, a.conn, a.verifier, commit, vcs.AnyReference)
	if err != nil {
		return nil, fmt.Errorf("getting vsa for revision %s: %w", commit, err)
	}
	ar.VsaPred = vsa

	_, prov, err := a.pa.GetProvenance(ctx, commit, a.conn.GetFullRef())
	if err != nil {
		return nil, fmt.Errorf("getting prov for revision %s: %w", commit, err)
	}
	ar.ProvPred = prov

	// Note: GetPriorCommit needs to be provided by the connection
	// For now, we'll need to handle this differently based on the VCS type
	ghPrior, err := a.getPriorCommit(ctx, commit)
	if err != nil {
		return nil, fmt.Errorf("could not get prior commit for revision %s: %w", commit, err)
	}
	ar.GhPriorCommit = ghPrior

	var controlStatus vcscontrol.ControlStatus
	if prov == nil {
		// If there's no provenance, let's check the controls to see how they're looking.
		// It could be that provenance generation failed, but the controls were still
		// in place.
		controlStatus, err = a.provider.GetBranchControlsAtCommit(ctx, commit, a.conn.GetFullRef())
		if err != nil {
			// Let's still return ar so they can continue if they want.
			return ar, fmt.Errorf("could not get controls for %s on %s: %w", commit, a.conn.GetFullRef(), err)
		}
	}
	ar.GhControlStatus = controlStatus

	return ar, nil
}

// getPriorCommit attempts to get the prior commit using GetPriorCommit if available
// This is a temporary solution until we add this to the vcscontrol interfaces
func (a *Auditor) getPriorCommit(ctx context.Context, commit string) (string, error) {
	// Try to use GetPriorCommit if the connection supports it
	if cp, ok := a.conn.(interface {
		GetPriorCommit(ctx context.Context, sha string) (string, error)
	}); ok {
		return cp.GetPriorCommit(ctx, commit)
	}
	// Fallback: try to use the vcscontrol connection
	if cp, ok := a.conn.(*vcscontrol.VcsControl); ok {
		return cp.GetPriorCommit(ctx, commit)
	}
	return "", fmt.Errorf("connection does not support GetPriorCommit")
}

func (a *Auditor) AuditBranch(ctx context.Context, branch string) iter.Seq2[*AuditCommitResult, error] {
	// Try to get the latest commit using GetLatestCommit if available
	var latestCommit string
	var err error

	if lc, ok := a.conn.(interface {
		GetLatestCommit(ctx context.Context, targetBranch string) (string, error)
	}); ok {
		latestCommit, err = lc.GetLatestCommit(ctx, branch)
	} else if vc, ok := a.conn.(*vcscontrol.VcsControl); ok {
		latestCommit, err = vc.GetLatestCommit(ctx, branch)
	} else {
		err = fmt.Errorf("connection does not support GetLatestCommit")
	}

	return func(yield func(*AuditCommitResult, error) bool) {
		if err != nil {
			yield(nil, err)
			return
		}
		nextCommit := latestCommit
		for ok := true; ok; ok = (nextCommit != "") {
			ar, err := a.AuditCommit(ctx, nextCommit)
			if !yield(ar, err) {
				return
			}
			nextCommit = ar.GhPriorCommit
		}
	}
}
