// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package vcscontrol provides a unified interface for VCS control operations
// that works with both GitHub and Gitea.
package vcscontrol

import (
	"context"
	"time"

	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/giteacontrol"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VcsType represents the type of VCS
type VcsType string

const (
	VcsTypeGitHub VcsType = "github"
	VcsTypeGitea  VcsType = "gitea"
)

// Connection provides a unified interface for VCS connections
type Connection interface {
	// VcsType returns the type of VCS
	VcsType() VcsType
	// Owner returns the repository owner
	Owner() string
	// Repo returns the repository name
	Repo() string
	// GetFullRef returns the full reference (e.g., refs/heads/main)
	GetFullRef() string
	// GetRepoUri returns the full repository URI
	GetRepoUri() string
	// GetLatestCommit returns the latest commit SHA for a branch
	GetLatestCommit(ctx context.Context, targetBranch string) (string, error)
	// GetPriorCommit returns the parent commit SHA
	GetPriorCommit(ctx context.Context, sha string) (string, error)
	// GetNotesForCommit returns git notes for a commit
	GetNotesForCommit(ctx context.Context, commit string) (string, error)
	// BranchToFullRef converts a branch name to a full ref (e.g., "main" -> "refs/heads/main")
	BranchToFullRef(branch string) string
	// TagToFullRef converts a tag name to a full ref (e.g., "v1.0" -> "refs/tags/v1.0")
	TagToFullRef(tag string) string
}

// ControlStatus provides a unified interface for control status from different VCS
type ControlStatus interface {
	// GetCommitPushTime returns when the commit was pushed
	GetCommitPushTime() time.Time
	// GetActorLogin returns the login of the actor who pushed
	GetActorLogin() string
	// GetActivityType returns the type of activity
	GetActivityType() string
	// GetControls returns the controls that are enabled
	GetControls() slsa.Controls
}

// ControlProvider provides methods to get branch and tag controls
type ControlProvider interface {
	// GetBranchControls returns controls for a specific branch
	GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error)
	// GetBranchControlsAtCommit returns controls at a specific commit
	GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (ControlStatus, error)
	// GetTagControls returns tag controls
	GetTagControls(ctx context.Context) (ControlStatus, error)
}

// gitHubConnection wraps GitHub connection
type gitHubConnection struct {
	conn *ghcontrol.GitHubConnection
}

func (g *gitHubConnection) VcsType() VcsType   { return VcsTypeGitHub }
func (g *gitHubConnection) Owner() string      { return g.conn.Owner() }
func (g *gitHubConnection) Repo() string       { return g.conn.Repo() }
func (g *gitHubConnection) GetFullRef() string { return g.conn.GetFullRef() }
func (g *gitHubConnection) GetRepoUri() string { return g.conn.GetRepoUri() }

func (g *gitHubConnection) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	return g.conn.GetLatestCommit(ctx, targetBranch)
}

func (g *gitHubConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	return g.conn.GetPriorCommit(ctx, sha)
}

func (g *gitHubConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	return g.conn.GetNotesForCommit(ctx, commit)
}

func (g *gitHubConnection) BranchToFullRef(branch string) string {
	return ghcontrol.BranchToFullRef(branch)
}

func (g *gitHubConnection) TagToFullRef(tag string) string {
	return ghcontrol.TagToFullRef(tag)
}

// gitHubControlStatus wraps GitHub control status
type gitHubControlStatus struct {
	status *ghcontrol.GhControlStatus
}

func (s *gitHubControlStatus) GetCommitPushTime() time.Time { return s.status.CommitPushTime }
func (s *gitHubControlStatus) GetActorLogin() string        { return s.status.ActorLogin }
func (s *gitHubControlStatus) GetActivityType() string      { return s.status.ActivityType }
func (s *gitHubControlStatus) GetControls() slsa.Controls   { return s.status.Controls }

// gitHubControlProvider wraps GitHub connection with control methods
type gitHubControlProvider struct {
	conn *ghcontrol.GitHubConnection
}

func (p *gitHubControlProvider) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	return p.conn.GetBranchControls(ctx, ref)
}

func (p *gitHubControlProvider) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (ControlStatus, error) {
	status, err := p.conn.GetBranchControlsAtCommit(ctx, commit, ref)
	if err != nil {
		return nil, err
	}
	return &gitHubControlStatus{status: status}, nil
}

func (p *gitHubControlProvider) GetTagControls(ctx context.Context) (ControlStatus, error) {
	status, err := p.conn.GetTagControls(ctx, "", "")
	if err != nil {
		return nil, err
	}
	return &gitHubControlStatus{status: status}, nil
}

// giteaConnection wraps Gitea connection
type giteaConnection struct {
	conn *giteacontrol.GiteaConnection
}

func (g *giteaConnection) VcsType() VcsType   { return VcsTypeGitea }
func (g *giteaConnection) Owner() string      { return g.conn.Owner() }
func (g *giteaConnection) Repo() string       { return g.conn.Repo() }
func (g *giteaConnection) GetFullRef() string { return g.conn.GetFullRef() }
func (g *giteaConnection) GetRepoUri() string { return g.conn.GetRepoUri() }

func (g *giteaConnection) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	return g.conn.GetLatestCommit(ctx, targetBranch)
}

func (g *giteaConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	return g.conn.GetPriorCommit(ctx, sha)
}

func (g *giteaConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	return g.conn.GetNotesForCommit(ctx, commit)
}

func (g *giteaConnection) BranchToFullRef(branch string) string {
	return giteacontrol.BranchToFullRef(branch)
}

func (g *giteaConnection) TagToFullRef(tag string) string {
	return giteacontrol.TagToFullRef(tag)
}

// giteaControlStatus wraps Gitea control status
type giteaControlStatus struct {
	status *giteacontrol.GiteaControlStatus
}

func (s *giteaControlStatus) GetCommitPushTime() time.Time { return s.status.CommitPushTime }
func (s *giteaControlStatus) GetActorLogin() string        { return s.status.ActorLogin }
func (s *giteaControlStatus) GetActivityType() string      { return s.status.ActivityType }
func (s *giteaControlStatus) GetControls() slsa.Controls   { return s.status.Controls }

// giteaControlProvider wraps Gitea connection with control methods
type giteaControlProvider struct {
	conn *giteacontrol.GiteaConnection
}

func (p *giteaControlProvider) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	return p.conn.GetBranchControls(ctx, ref)
}

func (p *giteaControlProvider) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (ControlStatus, error) {
	status, err := p.conn.GetBranchControlsAtCommit(ctx, commit, ref)
	if err != nil {
		return nil, err
	}
	return &giteaControlStatus{status: status}, nil
}

func (p *giteaControlProvider) GetTagControls(ctx context.Context) (ControlStatus, error) {
	status, err := p.conn.GetTagControls(ctx)
	if err != nil {
		return nil, err
	}
	return &giteaControlStatus{status: status}, nil
}

// ControlInfo holds combined control information
type ControlInfo struct {
	Connection      Connection
	ControlProvider ControlProvider
}

// NewGitHubConnection creates a new GitHub connection
func NewGitHubConnection(owner, repo, ref string) (*gitHubConnection, error) {
	conn := ghcontrol.NewGhConnection(owner, repo, ref)
	return &gitHubConnection{conn: conn}, nil
}

// NewGitHubConnectionWithToken creates a new GitHub connection with auth token
func NewGitHubConnectionWithToken(owner, repo, ref, token string) (*gitHubConnection, error) {
	conn := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(token)
	return &gitHubConnection{conn: conn}, nil
}

// NewGitHubControlProvider creates a new GitHub control provider
func NewGitHubControlProvider(owner, repo, ref, token string) (*gitHubControlProvider, error) {
	conn := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(token)
	return &gitHubControlProvider{conn: conn}, nil
}

// NewGiteaConnection creates a new Gitea connection
func NewGiteaConnection(owner, repo, ref, baseURL string) (*giteaConnection, error) {
	conn, err := giteacontrol.NewGiteaConnection(owner, repo, ref, baseURL)
	if err != nil {
		return nil, err
	}
	return &giteaConnection{conn: conn}, nil
}

// NewGiteaConnectionFromTokenFile creates a new Gitea connection using token from file
func NewGiteaConnectionFromTokenFile(owner, repo, ref, baseURL string) (*giteaConnection, error) {
	conn, err := giteacontrol.NewGiteaConnectionFromTokenFile(owner, repo, ref, baseURL)
	if err != nil {
		return nil, err
	}
	return &giteaConnection{conn: conn}, nil
}

// NewGiteaControlProvider creates a new Gitea control provider
func NewGiteaControlProvider(owner, repo, ref, baseURL string) (*giteaControlProvider, error) {
	conn, err := giteacontrol.NewGiteaConnection(owner, repo, ref, baseURL)
	if err != nil {
		return nil, err
	}
	return &giteaControlProvider{conn: conn}, nil
}

// VcsControl provides unified VCS control operations
type VcsControl struct {
	conn     Connection
	provider ControlProvider
}

// NewVcsControl creates a new VCS control for GitHub
func NewVcsControlGitHub(owner, repo, ref, token string) (*VcsControl, error) {
	conn := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(token)
	return &VcsControl{
		conn:     &gitHubConnection{conn: conn},
		provider: &gitHubControlProvider{conn: conn},
	}, nil
}

// NewVcsControlGitea creates a new VCS control for Gitea
func NewVcsControlGitea(owner, repo, ref, baseURL string) (*VcsControl, error) {
	conn, err := giteacontrol.NewGiteaConnection(owner, repo, ref, baseURL)
	if err != nil {
		return nil, err
	}
	return &VcsControl{
		conn:     &giteaConnection{conn: conn},
		provider: &giteaControlProvider{conn: conn},
	}, nil
}

// VcsType returns the type of VCS
func (v *VcsControl) VcsType() VcsType {
	return v.conn.VcsType()
}

// Owner returns the repository owner
func (v *VcsControl) Owner() string {
	return v.conn.Owner()
}

// Repo returns the repository name
func (v *VcsControl) Repo() string {
	return v.conn.Repo()
}

// GetFullRef returns the full reference
func (v *VcsControl) GetFullRef() string {
	return v.conn.GetFullRef()
}

// GetRepoUri returns the full repository URI
func (v *VcsControl) GetRepoUri() string {
	return v.conn.GetRepoUri()
}

// GetLatestCommit returns the latest commit SHA for a branch
func (v *VcsControl) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	return v.conn.GetLatestCommit(ctx, targetBranch)
}

// GetPriorCommit returns the parent commit SHA
func (v *VcsControl) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	return v.conn.GetPriorCommit(ctx, sha)
}

// GetNotesForCommit returns git notes for a commit
func (v *VcsControl) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	return v.conn.GetNotesForCommit(ctx, commit)
}

// BranchToFullRef converts a branch name to a full ref
func (v *VcsControl) BranchToFullRef(branch string) string {
	return v.conn.BranchToFullRef(branch)
}

// TagToFullRef converts a tag name to a full ref
func (v *VcsControl) TagToFullRef(tag string) string {
	return v.conn.TagToFullRef(tag)
}

// GetBranchControls returns controls for a specific branch
func (v *VcsControl) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	return v.provider.GetBranchControls(ctx, ref)
}

// GetBranchControlsAtCommit returns controls at a specific commit
func (v *VcsControl) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (ControlStatus, error) {
	return v.provider.GetBranchControlsAtCommit(ctx, commit, ref)
}

// GetTagControls returns tag controls
func (v *VcsControl) GetTagControls(ctx context.Context) (ControlStatus, error) {
	return v.provider.GetTagControls(ctx)
}

// GetControlInfo returns the underlying connection and provider
func (v *VcsControl) GetControlInfo() ControlInfo {
	return ControlInfo{
		Connection:      v.conn,
		ControlProvider: v.provider,
	}
}

// Helper function to convert ControlStatus to provenance controls with timestamp
func ControlStatusToProvenanceControl(cs ControlStatus, controlName slsa.ControlName) *provenance.Control {
	if cs == nil {
		return nil
	}
	return &provenance.Control{
		Name:  controlName.String(),
		Since: timestamppb.New(cs.GetCommitPushTime()),
	}
}

// Helper to check if a control was active when commit was pushed
func IsControlActiveAtCommit(cs ControlStatus, since time.Time) bool {
	if cs == nil {
		return false
	}
	return cs.GetCommitPushTime().After(since)
}
