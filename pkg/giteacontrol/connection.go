// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package giteacontrol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"code.gitea.io/sdk/gitea"
	"github.com/hashicorp/go-retryablehttp"
)

const tokenEnvVar = "GITEA_TOKEN" //nolint:gosec // These are not credentials

// Manages a connection to a Gitea repository.
type GiteaConnection struct {
	client           *gitea.Client
	Options          Options
	owner, repo, ref string
	baseURL          string
}

func NewGiteaConnection(owner, repo, ref, baseURL string) (*GiteaConnection, error) {
	opts := defaultOptions
	return NewGiteaConnectionWithClient(owner, repo, ref, baseURL, nil, &opts)
}

func NewGiteaConnectionWithOptions(owner, repo, ref, baseURL string, opts *Options) (*GiteaConnection, error) {
	return NewGiteaConnectionWithClient(owner, repo, ref, baseURL, nil, opts)
}

func NewGiteaConnectionWithClient(owner, repo, ref, baseURL string, client *gitea.Client, opts *Options) (*GiteaConnection, error) {
	if opts == nil {
		opts = &defaultOptions
	}

	// If the token is in the environment capture it now.
	if t := os.Getenv(tokenEnvVar); t != "" {
		opts.accessToken = t
	}

	return &GiteaConnection{
		client:  client,
		owner:   owner,
		repo:    repo,
		ref:     ref,
		baseURL: baseURL,
		Options: *opts,
	}, nil
}

// NewGiteaConnectionFromTokenFile creates a Gitea connection using a token from a file
// The token file is typically stored at ~/.config/slsa/sourcetool.gitea.token
func NewGiteaConnectionFromTokenFile(owner, repo, ref, baseURL string) (*GiteaConnection, error) {
	opts := defaultOptions

	// Try to read token from file first
	dir, err := os.UserConfigDir()
	if err == nil {
		tokenFile := filepath.Join(dir, "slsa", "sourcetool.gitea.token")
		data, err := os.ReadFile(tokenFile)
		if err == nil {
			opts.accessToken = string(data)
		}
	}

	// Fall back to environment variable
	if opts.accessToken == "" {
		if t := os.Getenv(tokenEnvVar); t != "" {
			opts.accessToken = t
		}
	}

	return &GiteaConnection{
		client:  nil,
		owner:   owner,
		repo:    repo,
		ref:     ref,
		baseURL: baseURL,
		Options: opts,
	}, nil
}

func (gc *GiteaConnection) Client() *gitea.Client {
	if gc.client == nil {
		gc.client = gc.createClient()
	}
	return gc.client
}

func (gc *GiteaConnection) createClient() *gitea.Client {
	rClient := retryablehttp.NewClient()
	rClient.RetryMax = int(gc.Options.ApiRetries)
	rClient.Logger = nil

	client, err := gitea.NewClient(
		gc.baseURL,
		gitea.SetToken(gc.Options.accessToken),
		gitea.SetHTTPClient(rClient.StandardClient()),
	)
	if err != nil {
		return nil
	}
	return client
}

func (gc *GiteaConnection) GetClient() (*gitea.Client, error) {
	if gc.client == nil {
		gc.client = gc.createClient()
	}
	if gc.client == nil {
		return nil, fmt.Errorf("failed to create Gitea client")
	}
	return gc.client, nil
}

func (gc *GiteaConnection) Owner() string {
	return gc.owner
}

func (gc *GiteaConnection) Repo() string {
	return gc.repo
}

func (gc *GiteaConnection) GetFullRef() string {
	return gc.ref
}

// Uses the provided token for auth.
func (gc *GiteaConnection) WithAuthToken(token string) *GiteaConnection {
	if token != "" {
		gc.Options.accessToken = token
		gc.client = nil // Reset client to recreate with new token
	}
	return gc
}

// Returns the URI of the repo this connection tracks.
func (gc *GiteaConnection) GetRepoUri() string {
	return fmt.Sprintf("%s/%s/%s", gc.baseURL, gc.Owner(), gc.Repo())
}

// Gets the previous commit to 'sha' if it has one.
// If there are more than one parents this fails with an error.
func (gc *GiteaConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	client, err := gc.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	commit, _, err := client.GetSingleCommit(gc.Owner(), gc.Repo(), sha)
	if err != nil {
		return "", fmt.Errorf("cannot get commit data for %s: %w", sha, err)
	}

	if len(commit.Parents) == 0 {
		return "", fmt.Errorf("there is no commit earlier than %s, that isn't yet supported", sha)
	}

	if len(commit.Parents) > 1 {
		return "", fmt.Errorf("commit %s has more than one parent (%v), which is not supported", sha, commit.Parents)
	}

	return commit.Parents[0].SHA, nil
}

func (gc *GiteaConnection) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	client, err := gc.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	branchName := targetBranch
	if len(targetBranch) > 11 && targetBranch[:11] == "refs/heads/" {
		branchName = targetBranch[11:]
	}

	branch, _, err := client.GetRepoBranch(gc.Owner(), gc.Repo(), branchName)
	if err != nil {
		return "", fmt.Errorf("could not get info on specified branch %s: %w", targetBranch, err)
	}
	return branch.Commit.ID, nil
}

// GetDefaultBranch reads the default repository branch from the Gitea API
func (gc *GiteaConnection) GetDefaultBranch(ctx context.Context) (string, error) {
	client, err := gc.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	repo, _, err := client.GetRepo(gc.Owner(), gc.Repo())
	if err != nil {
		return "", fmt.Errorf("fetching repository data: %w", err)
	}

	return repo.DefaultBranch, nil
}
