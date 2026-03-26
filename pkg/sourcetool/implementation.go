// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/repo"
	roptions "github.com/slsa-framework/source-tool/pkg/repo/options"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/backends/attestation/notes"
	giteabackend "github.com/slsa-framework/source-tool/pkg/sourcetool/backends/vcs/gitea"
	ghbackend "github.com/slsa-framework/source-tool/pkg/sourcetool/backends/vcs/github"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/options"
)

// toolImplementation defines the mockable implementation of source tool
//
//counterfeiter:generate . toolImplementation
type toolImplementation interface {
	VerifyOptionsForFullOnboard(*auth.Authenticator, *options.Options) error
	CheckPolicyFork(*options.Options) error
	CreatePolicyPR(*auth.Authenticator, *options.Options, *models.Repository, *policy.RepoPolicy) (*models.PullRequest, error)
	CheckForks(*options.Options) error
	SearchPullRequest(context.Context, *auth.Authenticator, *models.Repository, string) (*models.PullRequest, error)
	GetVcsBackend(*models.Repository) (models.VcsBackend, error)
	GetAttestationReader(*models.Repository) (models.AttestationStorageReader, error)
	GetBranchControls(context.Context, models.VcsBackend, *models.Repository, *models.Branch) (*slsa.ControlSetStatus, error)
	GetBranchControlsAtCommit(context.Context, models.VcsBackend, *models.Repository, *models.Branch, *models.Commit) (*slsa.ControlSetStatus, error)
	ConfigureControls(models.VcsBackend, *models.Repository, []*models.Branch, []models.ControlConfiguration) error
	GetPolicyStatus(context.Context, *auth.Authenticator, *options.Options, *models.Repository) (*slsa.ControlStatus, error)
	CreateRepositoryFork(context.Context, *auth.Authenticator, *models.Repository, string) error
}

type defaultToolImplementation struct{}

func (impl *defaultToolImplementation) ConfigureControls(
	backend models.VcsBackend, r *models.Repository,
	branches []*models.Branch, configs []models.ControlConfiguration,
) error {
	return backend.ConfigureControls(r, branches, configs)
}

func (impl *defaultToolImplementation) GetBranchControls(
	ctx context.Context, backend models.VcsBackend, r *models.Repository, branch *models.Branch,
) (*slsa.ControlSetStatus, error) {
	return backend.GetBranchControls(ctx, r, branch)
}

func (impl *defaultToolImplementation) GetBranchControlsAtCommit(
	ctx context.Context, backend models.VcsBackend, r *models.Repository, branch *models.Branch, commit *models.Commit,
) (*slsa.ControlSetStatus, error) {
	return backend.GetBranchControlsAtCommit(ctx, r, branch, commit)
}

// GetAttestationReader returns the att reader object
func (impl *defaultToolImplementation) GetAttestationReader(_ *models.Repository) (models.AttestationStorageReader, error) {
	// We only have the notes backend for now
	return notes.New(), nil
}

// GetVcsBackend returns the VCS backend to handle the repository defined in the options
func (impl *defaultToolImplementation) GetVcsBackend(repo *models.Repository) (models.VcsBackend, error) {
	host := repo.Hostname
	if host == "" {
		host = "github.com"
	}

	// Use GitHub for github.com, otherwise use Gitea
	if host == "github.com" {
		return ghbackend.New(), nil
	}

	return giteabackend.New(), nil
}

// VerifyOptions checks options are in good shape to run
// TODO(puerco): To be completed
func (impl *defaultToolImplementation) VerifyOptionsForFullOnboard(a *auth.Authenticator, opts *options.Options) error {
	errs := []error{}
	uid, err := a.WhoAmI()
	if err != nil {
		errs = append(errs, err)
	}
	if uid == nil {
		errs = append(errs, errors.New("sourcetool is not logged in"))
	}

	return errors.Join(errs...)
}

// CreatePolicyPR creates a pull request to push the policy
func (impl *defaultToolImplementation) CreatePolicyPR(a *auth.Authenticator, opts *options.Options, r *models.Repository, p *policy.RepoPolicy) (*models.PullRequest, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	user, err := a.WhoAmI()
	if err != nil {
		return nil, err
	}

	repoOwner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	// Check the repository clone in the user's account is ready to push
	if err := impl.CheckPolicyFork(opts); err != nil {
		return nil, fmt.Errorf("checking policy repository fork: %w", err)
	}

	// Marshal the policy json
	policyJson, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling policy data: %w", err)
	}

	// Create a pull request manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(a))
	prManager.Options.UseFork = true

	// Define the policy repo...
	policyRepoOwner := policy.SourcePolicyRepoOwner
	policyRepoName := policy.SourcePolicyRepo
	policyRepoHostname := "github.com"
	// ... but honor if there is one in the options
	if opts.PolicyRepo != "" {
		var ok bool
		policyRepoOwner, policyRepoName, ok = strings.Cut(opts.PolicyRepo, "/")
		if !ok {
			return nil, fmt.Errorf("invalid policy repository")
		}
		// Extract hostname if present in the policy repo (e.g., "gitea.example.com/owner/repo")
		if strings.Contains(policyRepoOwner, "/") {
			parts := strings.Split(policyRepoOwner, "/")
			if len(parts) >= 2 {
				policyRepoHostname = parts[0]
				policyRepoOwner = strings.Join(parts[1:], "/")
			}
		}
	}

	policyRepo := &models.Repository{
		Hostname:      policyRepoHostname,
		Path:          fmt.Sprintf("%s/%s", policyRepoOwner, policyRepoName),
		DefaultBranch: "main",
	}

	// Open the pull request
	pr, err := prManager.PullRequestFileList(
		policyRepo,
		&roptions.PullRequestFileListOptions{
			Title: fmt.Sprintf("Add %s/%s SLSA Source policy file", repoOwner, repoName),
			Body:  fmt.Sprintf(`This pull request adds the SLSA source policy for %s/%s/%s`, policyRepoHostname, repoOwner, repoName),
			CommitOptions: roptions.CommitOptions{
				Name:  user.GetLogin(),
				Email: user.GetLogin() + "@users.noreply.github.com",
			},
		},
		[]*repo.PullRequestFileEntry{
			{
				Path:   fmt.Sprintf("policy/%s/%s/%s/source-policy.json", policyRepoHostname, repoOwner, repoName),
				Reader: bytes.NewReader(policyJson),
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("creating policy pull request: %w", err)
	}
	return pr, nil
}

// CheckForks checks that the user has forks of the required repositories
func (impl *defaultToolImplementation) CheckForks(opts *options.Options) error {
	errs := []error{}
	if err := impl.CheckPolicyFork(opts); err != nil {
		errs = append(errs, err)
	}

	// Here, we had the workflow fork but it does not belong here anymore

	return errors.Join(errs...)
}

func (impl *defaultToolImplementation) CheckPolicyFork(opts *options.Options) error {
	manager := repo.NewPullRequestManager()
	if _, err := manager.CheckFork(&models.Repository{
		Hostname: "github.com", Path: opts.PolicyRepo,
	}, ""); err != nil {
		return err
	}
	return nil
}

// SearchPullRequest searches the last pull requests on a repo for one whose
// title matches the query string
func (impl *defaultToolImplementation) SearchPullRequest(ctx context.Context, a *auth.Authenticator, r *models.Repository, query string) (*models.PullRequest, error) {
	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	client, err := a.GetGitHubClient()
	if err != nil {
		return nil, err
	}

	prs, _, err := client.PullRequests.List(
		ctx, owner, repoName, &github.PullRequestListOptions{
			State: "open",
			// Only search the first 100
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 100,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		if strings.Contains(pr.GetTitle(), query) {
			return &models.PullRequest{
				Title:  pr.GetTitle(),
				Body:   pr.GetBody(),
				Time:   pr.CreatedAt.GetTime(),
				Head:   pr.GetHead().GetRef(),
				Base:   pr.GetBase().GetRef(),
				Number: pr.GetNumber(),
				Repo:   r,
			}, nil
		}
	}
	return nil, nil
}

// GetPolicyStatus returns the status of the policy as a slsa ControlStatus
func (impl *defaultToolImplementation) GetPolicyStatus(
	ctx context.Context, a *auth.Authenticator, opts *options.Options, r *models.Repository,
) (*slsa.ControlStatus, error) {
	// Create policy evaluator with Gitea support if needed
	pe := policy.NewPolicyEvaluator()
	isGitea := r.Hostname != "" && r.Hostname != "github.com"
	if isGitea {
		pe.GiteaURL = fmt.Sprintf("https://%s", r.Hostname)
	}
	// Pass the policy repo to the evaluator

	pe.PolicyRepo = opts.PolicyRepo
	pe.PolicyHostname = opts.PolicyHostname
	pe.PolicyPathOwner = opts.PolicyPathOwner

	// First: Look for the policy. If found then we are done
	pcy, _, err := pe.GetPolicy(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("checking if the repository has a policy %w in %s", err, pe.PolicyRepo)
	}

	if pcy != nil {
		t := time.Now()
		if len(pcy.GetProtectedBranches()) > 0 {
			t = pcy.GetProtectedBranches()[0].GetSince().AsTime()
		}
		return &slsa.ControlStatus{
			Name:              slsa.PolicyAvailable,
			State:             slsa.StateActive,
			Since:             &t,
			Message:           fmt.Sprintf("A repository policy exists for %s", r.Path),
			RecommendedAction: nil,
		}, nil
	}

	// If there is no policy, check if we have a pull request open
	policyRepoOwner := policy.SourcePolicyRepoOwner
	policyRepoRepo := policy.SourcePolicyRepo
	po, pr, ok := strings.Cut(opts.PolicyRepo, "/")
	if ok {
		policyRepoOwner = po
		policyRepoRepo = pr
	}

	// For Gitea repos, skip PR check since policy repo doesn't exist there
	if isGitea {
		return &slsa.ControlStatus{
			Name:    slsa.PolicyAvailable,
			State:   slsa.StateNotEnabled,
			Message: "No policy found (policy repository not available on Gitea)",
		}, nil
	}

	host := r.Hostname
	if host == "" {
		host = "github.com"
	}
	prNr, err := impl.SearchPullRequest(ctx, a, &models.Repository{
		Hostname: host,
		Path:     fmt.Sprintf("%s/%s", policyRepoOwner, policyRepoRepo),
	}, fmt.Sprintf("Add %s SLSA Source policy file", r.Path))
	if err != nil {
		return nil, fmt.Errorf("GetPolicyStatus searching for policy pull request: %w", err)
	}

	// No pull request found. Not implemented
	if prNr == nil {
		return &slsa.ControlStatus{
			Name:    slsa.PolicyAvailable,
			State:   slsa.StateNotEnabled,
			Since:   nil,
			Message: fmt.Sprintf("Repository policy not found for %s", r.Path),
			RecommendedAction: &slsa.ControlRecommendedAction{
				Message: "Create a policy for the repository",
				Command: fmt.Sprintf("buildtool policy create %s", r.Path),
			},
		}, nil
	}

	return &slsa.ControlStatus{
		Name:    slsa.PolicyAvailable,
		State:   slsa.StateInProgress,
		Since:   prNr.Time,
		Message: fmt.Sprintf("PR %s/%s#%d waiting to merge", policyRepoOwner, policyRepoRepo, prNr.Number),
		RecommendedAction: &slsa.ControlRecommendedAction{
			Message: "Wait for the policy pull request to merge",
		},
	}, nil
}

// CreateRepositoryFork creates a fork of a repo into the logged-in user's org.
// Optionally the fork can have a different name than the original.
func (impl *defaultToolImplementation) CreateRepositoryFork(
	ctx context.Context, a *auth.Authenticator, src *models.Repository, forkName string,
) error {
	client, err := a.GetGitHubClient()
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	srcOrg, srcName, err := src.PathAsGitHubOwnerName()
	if err != nil {
		return err
	}

	if forkName == "" {
		forkName = srcName
	}

	// Create the fork
	_, resp, err := client.Repositories.CreateFork(
		ctx, srcOrg, srcName, &github.RepositoryCreateForkOptions{
			Name: forkName,
		},
	)

	// GitHub will return 202 for larger repos that are cloned async
	if err != nil && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("creating repository fork: %w", err)
	}

	return nil
}
