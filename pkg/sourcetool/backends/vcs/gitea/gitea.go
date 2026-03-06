
package gitea

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"code.gitea.io/sdk/gitea"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func New() *Backend {
	return &Backend{
		Options: Options{UseFork: true},
	}
}

type Options struct {
	UseFork bool
}

type Backend struct {
	Options Options
}

func (b *Backend) getGiteaConnection(repository *models.Repository, ref string) (*GiteaConnection, error) {
	if repository == nil {
		return nil, fmt.Errorf("unable to build Gitea connection, repository is nil")
	}

	if repository.Path == "" {
		return nil, errors.New("repository path not set")
	}

	owner, name, err := repository.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	return NewGiteaConnectionWithHost(owner, name, ref, repository.Hostname)
}

func getGiteaToken() (string, error) {
	if token := os.Getenv("GITEA_TOKEN"); token != "" {
		return token, nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	tokenFile := filepath.Join(dir, "slsa", "sourcetool.gitea.token")
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func (b *Backend) GetBranchControls(ctx context.Context, r *models.Repository, branch *models.Branch) (*slsa.ControlSetStatus, error) {
	ghc, err := b.getGiteaConnection(branch.Repository, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("getting gitea connection: %w", err)
	}

	commit, err := ghc.GetLatestCommit(ctx, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("fetching latest commit from %q: %w", branch.FullRef(), err)
	}

	return b.GetBranchControlsAtCommit(ctx, r, branch, &models.Commit{SHA: commit})
}

func (b *Backend) GetBranchControlsAtCommit(ctx context.Context, r *models.Repository, branch *models.Branch, commit *models.Commit) (*slsa.ControlSetStatus, error) {
	if commit == nil {
		return nil, errors.New("commit is not set")
	}
	ghc, err := b.getGiteaConnection(branch.Repository, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("getting gitea connection: %w", err)
	}

	activeControls, err := b.getBranchControls(ctx, ghc, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("checking status: %w", err)
	}

	status := slsa.NewControlSetStatus()
	for i, ctrl := range status.Controls {
		if c := activeControls.GetControl(ctrl.Name); c != nil {
			if c.GetSince() != nil {
				t := c.GetSince().AsTime()
				status.Controls[i].Since = &t
			}
			status.Controls[i].State = slsa.StateActive
			status.Controls[i].Message = b.controlImplementationMessage(slsa.ControlName(c.GetName()))
		}
	}

	switchProvCtlToInProgress := false
	var provenanceMessage string
	if c := activeControls.GetControl(slsa.ProvenanceAvailable); c == nil {
		pr, err := b.FindWorkflowPR(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("looking for provenance workflow pull request: %w", err)
		}
		if pr != nil {
			switchProvCtlToInProgress = true
			provenanceMessage = fmt.Sprintf("(PR %s#%d waiting to merge)", pr.Repo.Path, pr.Number)
		}
	}

	for i := range status.Controls {
		if switchProvCtlToInProgress && status.Controls[i].Name == slsa.ProvenanceAvailable {
			status.Controls[i].State = slsa.StateInProgress
			status.Controls[i].Message = provenanceMessage
		}
		action := b.getRecommendedAction(r, branch, status.Controls[i].Name, status.Controls[i].State)
		status.Controls[i].RecommendedAction = action
	}

	return status, nil
}

func (b *Backend) getBranchControls(ctx context.Context, ghc *GiteaConnection, branch string) (*slsa.Controls, error) {
	controls := &slsa.Controls{}

	branchName := branch
	if len(branch) > 11 && branch[:11] == "refs/heads/" {
		branchName = branch[11:]
	}

	client, err := ghc.GetClient()
	if err != nil {
		return nil, err
	}

	rule, _, err := client.GetBranchProtection(ghc.owner, ghc.repo, branchName)
	if err != nil {
		if !isGitea404(err) {
			return nil, fmt.Errorf("getting branch protection: %w", err)
		}
		// No branch protection configured, but continue to check tag protections.
	} else {
		now := timestamppb.Now()

		if rule.EnablePush {
			controls.AddControl(&provenance.Control{
				Name:  slsa.ContinuityEnforced.String(),
				Since: now,
			})
		}

		if rule.EnableApprovalsWhitelist || rule.BlockOnRejectedReviews {
			controls.AddControl(&provenance.Control{
				Name:  slsa.ReviewEnforced.String(),
				Since: now,
			})
		}
	}

	// Check tag protections for TAG_HYGIENE control.
	tagHygieneControl, err := computeTagHygieneControl(client, ghc.owner, ghc.repo, branchName)
	if err != nil {
		return nil, fmt.Errorf("checking tag hygiene: %w", err)
	}
	if tagHygieneControl != nil {
		controls.AddControl(tagHygieneControl)
	}

	return controls, nil
}

// computeTagHygieneControl checks if the Gitea repository has tag protection
// rules that cover the specified branch. A tag protection is considered valid
// if its NamePattern matches the branch name (using glob matching) or if it
// covers all tags (NamePattern "*"). When multiple protections match, the
// oldest one is used for the Since timestamp.
func computeTagHygieneControl(client *gitea.Client, owner, repo, branchName string) (*provenance.Control, error) {
	tagProtections, _, err := client.ListTagProtection(owner, repo, gitea.ListRepoTagProtectionsOptions{})
	if err != nil {
		// If the API is not available (older Gitea versions), treat as no tag hygiene.
		if strings.Contains(strings.ToLower(err.Error()), "404") ||
			strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("listing tag protections: %w", err)
	}

	// Find the oldest tag protection whose pattern matches the branch name.
	var oldest *gitea.TagProtection
	for _, tp := range tagProtections {
		matched, err := path.Match(tp.NamePattern, branchName)
		if err != nil {
			// Invalid pattern, skip it.
			continue
		}
		if matched {
			if oldest == nil || tp.Created.Before(oldest.Created) {
				oldest = tp
			}
		}
	}

	if oldest == nil {
		return nil, nil
	}

	return &provenance.Control{
		Name:  slsa.TagHygiene.String(),
		Since: timestamppb.New(oldest.Created),
	}, nil
}

func isGitea404(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "404") || strings.Contains(errStr, "not found")
}

func (b *Backend) controlImplementationMessage(ctrlName slsa.ControlName) string {
	switch ctrlName {
	case slsa.ProvenanceAvailable:
		return "Signed provenance metadata is being published on every commit"
	case slsa.TagHygiene:
		return "Tag protections are configured in the repository"
	case slsa.ReviewEnforced:
		return "Code review is enforced in the repository"
	case slsa.ContinuityEnforced:
		return "Push and delete protection is enabled on the branch"
	case slsa.PolicyAvailable:
		return "The repository has published a policy"
	default:
		return ""
	}
}

func (b *Backend) GetTagControls(context.Context, *models.Tag) (*slsa.Controls, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (b *Backend) ControlConfigurationDescr(branch *models.Branch, config models.ControlConfiguration) string {
	repo := branch.Repository
	if repo == nil {
		repo = &models.Repository{
			Path: "your repository",
		}
	}

	switch config {
	case models.CONFIG_BRANCH_RULES:
		return fmt.Sprintf(
			"Enable push and delete protection on %s for branch %s",
			repo.Path, branch.Name,
		)
	case models.CONFIG_GEN_PROVENANCE:
		return fmt.Sprintf(
			"Open a pull request on %s to add the provenance generation workflow",
			repo.Path,
		)
	case models.CONFIG_POLICY:
		return fmt.Sprintf(
			"Open a pull request on the SLSA policy repo to check-in %s SLSA source policy",
			repo.Path,
		)
	case models.CONFIG_TAG_RULES:
		return fmt.Sprintf(
			"Enable force push/update/delete protection for all tags in %s",
			repo.Path,
		)
	default:
		return ""
	}
}

func (b *Backend) GetLatestCommit(ctx context.Context, r *models.Repository, branch *models.Branch) (*models.Commit, error) {
	gcx, err := b.getGiteaConnection(r, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("building Gitea connector: %w", err)
	}

	sha, err := gcx.GetLatestCommit(ctx, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("reading latest commit: %w", err)
	}

	return &models.Commit{SHA: sha}, nil
}

func (b *Backend) getRecommendedAction(r *models.Repository, _ *models.Branch, control slsa.ControlName, state slsa.ControlState) *slsa.ControlRecommendedAction {
	switch control {
	case slsa.ProvenanceAvailable:
		switch state {
		case slsa.StateInProgress:
			return &slsa.ControlRecommendedAction{
				Message: "Wait for provenance generator pull request to merge",
			}
		case slsa.StateNotEnabled:
			return &slsa.ControlRecommendedAction{
				Message: "Start generating provenance",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_GEN_PROVENANCE, r.Path),
			}
		default:
			return nil
		}
	case slsa.ContinuityEnforced:
		if state == slsa.StateNotEnabled {
			return &slsa.ControlRecommendedAction{
				Message: "Enable branch push/delete protection",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_BRANCH_RULES, r.Path),
			}
		}
		return nil
	case slsa.TagHygiene:
		if state == slsa.StateNotEnabled {
			return &slsa.ControlRecommendedAction{
				Message: "Enable tag push/update/delete protection",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_TAG_RULES, r.Path),
			}
		}
		return nil
	default:
		return nil
	}
}
