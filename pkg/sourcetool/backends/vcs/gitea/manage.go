package gitea

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"code.gitea.io/sdk/gitea"

	"github.com/slsa-framework/source-tool/pkg/repo"
	"github.com/slsa-framework/source-tool/pkg/repo/options"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

const (
	ActionsOrg     = "actions"
	ActionsRepo    = "slsa-source-provenance"
	workflowPath   = ".gitea/workflows/compute_slsa_source.yaml"

	workflowCommitMessage = "Add SLSA Source Provenance Workflow"

	workflowPRBody = `This pull request adds a new workflow to the repository to generate ` +
		`[SLSA](https://slsa.dev/) Source provenance data on every push.` + "\n\n" +
		`Every time a new commit merges to the specified branch, attestations will ` +
		`be automatically signed and stored in git notes in this repository.` + "\n\n" +
		`Note: This is an automated PR created using a fork of the ` +
		`[SLSA sourcetool](https://github.com/adrianschroeter/source-tool) utility.` + "\n"

	workflowData = `---
name: SLSA Source
on:
  push:
    branches: [ %s ]
    tags: ['**']
permissions: {}

jobs:
  generate-provenance:
    permissions:
      contents: write
      id-token: write
    uses: %s/%s/.github/workflows/compute_slsa_source.yml@%s

`
)

func (b *Backend) checkPushAccess(r *models.Repository) (bool, error) {
	gc, err := b.getGiteaConnection(r, "")
	if err != nil {
		return false, err
	}

	client, err := gc.GetClient()
	if err != nil {
		return false, err
	}

	_, _, err = client.GetRepo(gc.owner, gc.repo)
	if err != nil {
		return false, fmt.Errorf("checking repository access: %w", err)
	}

	return true, nil
}

func (b *Backend) CreateWorkflowPR(r *models.Repository, branches []*models.Branch) (*models.PullRequest, error) {
	if len(branches) == 0 {
		return nil, errors.New("no branches specified")
	}

	user, err := b.getUser()
	if err != nil {
		return nil, err
	}

	quotedBranchesList := []string{}
	for _, br := range branches {
		quotedBranchesList = append(quotedBranchesList, fmt.Sprintf("%q", br.Name))
	}
	workflowYAML := fmt.Sprintf(
		workflowData, strings.Join(quotedBranchesList, ", "),
		ActionsOrg, ActionsRepo, "main",
	)

	hasPush, err := b.checkPushAccess(r)
	if err != nil {
		return nil, fmt.Errorf("checking for repository push access: %w", err)
	}

	if !hasPush {
		if err := b.CheckWorkflowFork(r); err != nil {
			return nil, fmt.Errorf("checking for required repository fork: %w", err)
		}
	}

	prManager := repo.NewPullRequestManager()
	prManager.Options.UseFork = !hasPush

	pr, err := prManager.PullRequestFileList(
		r,
		&options.PullRequestFileListOptions{
			Title: workflowCommitMessage,
			Body:  workflowPRBody,
			CommitOptions: options.CommitOptions{
				Name:  user.GetLogin(),
				Email: user.GetLogin() + "@users.noreply.github.com",
			},
		},
		[]*repo.PullRequestFileEntry{
			{
				Path:   workflowPath,
				Reader: strings.NewReader(workflowYAML),
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("creating workflow pull request: %w", err)
	}

	return pr, nil
}

func (b *Backend) getUser() (*models.Actor, error) {
	gc, err := b.getGiteaConnection(&models.Repository{Path: "dummy/dummy"}, "")
	if err != nil {
		return nil, err
	}

	client, err := gc.GetClient()
	if err != nil {
		return nil, err
	}

	user, _, err := client.GetMyUserInfo()
	if err != nil {
		return nil, fmt.Errorf("getting user info: %w", err)
	}

	return &models.Actor{Login: user.UserName}, nil
}

func (b *Backend) CheckWorkflowFork(r *models.Repository) error {
	prManager := repo.NewPullRequestManager()
	_, err := prManager.CheckFork(r, "")
	return err
}

func (b *Backend) searchPullRequestsByTitle(ctx context.Context, r *models.Repository, query string) (*gitea.PullRequest, error) {
	gc, err := b.getGiteaConnection(r, "")
	if err != nil {
		return nil, err
	}

	client, err := gc.GetClient()
	if err != nil {
		return nil, err
	}

	prs, _, err := client.ListRepoPullRequests(gc.owner, gc.repo, gitea.ListPullRequestsOptions{
		State: "open",
	})
	if err != nil {
		// Repository might not exist or no access - return empty list
		if isGitea404(err) || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		if strings.Contains(pr.Title, query) {
			return pr, nil
		}
	}
	return nil, nil
}

func (b *Backend) FindWorkflowPR(ctx context.Context, r *models.Repository) (*models.PullRequest, error) {
	pr, err := b.searchPullRequestsByTitle(ctx, r, workflowCommitMessage)
	if err != nil {
		return nil, fmt.Errorf("searching for provenance workflow pull request: %w", err)
	}

	if pr == nil {
		return nil, nil
	}

	return &models.PullRequest{
		Title:  pr.Title,
		Body:   pr.Body,
		Number: int(pr.Index),
		Repo:   r,
	}, nil
}

func (b *Backend) CreateRepoRuleset(r *models.Repository, branches []*models.Branch) error {
	if r == nil {
		return errors.New("unable to create repo ruleset, repository not defined")
	}

	if branches == nil {
		return errors.New("unable to create repo ruleset, branch not set")
	}

	if len(branches) > 1 {
		return errors.New("protecting more than one branch at a time is not yet supported")
	}

	gc, err := b.getGiteaConnection(r, branches[0].FullRef())
	if err != nil {
		return err
	}

	client, err := gc.GetClient()
	if err != nil {
		return err
	}

	_, _, err = client.CreateBranchProtection(gc.owner, gc.repo, gitea.CreateBranchProtectionOption{
		BranchName:             branches[0].Name,
		EnablePush:             false,
		BlockOnRejectedReviews: true,
		DismissStaleApprovals:  true,
	})
	if err != nil {
		return fmt.Errorf("enabling branch protection rules: %w", err)
	}

	return nil
}

func (b *Backend) CreateTagRuleset(r *models.Repository) error {
	if r == nil {
		return errors.New("unable to create tag ruleset, repository not defined")
	}

	gc, err := b.getGiteaConnection(r, "")
	if err != nil {
		return err
	}

	client, err := gc.GetClient()
	if err != nil {
		return err
	}

	// Try to create tag protection for all tags
	_, _, err = client.CreateTagProtection(gc.owner, gc.repo, gitea.CreateTagProtectionOption{
		NamePattern: "*",
	})
	if err != nil {
		return fmt.Errorf("enabling tag protection rules: %w", err)
	}

	return nil
}

func (b *Backend) ControlPrecheck(
	r *models.Repository, branches []*models.Branch, config models.ControlConfiguration,
) (ok bool, remediationMessage string, remediateFn models.ControlPreRemediationFn, err error) {
	switch config {
	case models.CONFIG_GEN_PROVENANCE:
		sino, err := b.checkPushAccess(r)
		if err != nil {
			return false, "", nil, fmt.Errorf("checking for push access: %w", err)
		}
		if sino {
			return true, "", nil, nil
		}

		if err := b.CheckWorkflowFork(r); err == nil {
			return true, "", nil, nil
		}
		msg := "No fork found of repository %s\n"
		msg += "and user has no push access.\n\n"
		msg += "Would you like to create a fork in your account?\n"
		return false, fmt.Sprintf(msg, r.Path), nil, nil
	default:
		return true, "", nil, nil
	}
}

func (b *Backend) ConfigureControls(r *models.Repository, branches []*models.Branch, configs []models.ControlConfiguration) error {
	errs := []error{}
	for _, config := range configs {
		switch config {
		case models.CONFIG_BRANCH_RULES:
			if err := b.CreateRepoRuleset(r, branches); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("creating rules in the repository: %w", err))
				}
			}
		case models.CONFIG_GEN_PROVENANCE:
			pr, err := b.FindWorkflowPR(context.Background(), r)
			if err != nil {
				errs = append(errs, fmt.Errorf("checking repository pull request: %w", err))
			}

			if pr != nil {
				continue
			}

			if _, err := b.CreateWorkflowPR(r, branches); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("opening SLSA source workflow pull request: %w", err))
				}
			}
		case models.CONFIG_TAG_RULES:
			if err := b.CreateTagRuleset(r); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("opening SLSA source workflow pull request: %w", err))
				}
			}
		case models.CONFIG_POLICY:
		default:
			errs = append(errs, fmt.Errorf("unknown configuration flag: %q", config))
		}
	}
	return errors.Join(errs...)
}

func (b *Backend) GetLatestActionsTag() (tag, digest string, err error) {
	return "main", "main", nil
}
