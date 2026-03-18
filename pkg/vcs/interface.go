// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package vcs provides a unified interface for VCS (Version Control System) connections
// that works with both GitHub and Gitea.
package vcs

import (
	"context"
	"time"

	"github.com/slsa-framework/source-tool/pkg/slsa"
)

// VcsConnection is a common interface for VCS connections (GitHub, Gitea, etc.)
// that provides methods needed for SLSA source verification.
type VcsConnection interface {
	// Owner returns the repository owner
	Owner() string
	// Repo returns the repository name
	Repo() string
	// GetFullRef returns the full reference (e.g., refs/heads/main)
	GetFullRef() string
	// GetRepoUri returns the full repository URI
	GetRepoUri() string
	// GetNotesForCommit returns git notes for a commit
	GetNotesForCommit(ctx context.Context, commit string) (string, error)
}

// ControlStatus is a common interface for control status from different VCS providers
type ControlStatus interface {
	// GetCommitPushTime returns when the commit was pushed
	GetCommitPushTime() time.Time
	// GetControls returns the controls that are enabled
	GetControls() slsa.Controls
}

// AnyReference is a wildcard constant for matching any reference
const AnyReference = "*"
