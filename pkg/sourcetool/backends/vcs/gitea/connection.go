package gitea

import (
	"context"
	"fmt"
	"strings"

	"code.gitea.io/sdk/gitea"
	"github.com/hashicorp/go-retryablehttp"
)

const tokenEnvVar = "GITEA_TOKEN"

type GiteaConnection struct {
	client *gitea.Client
	owner  string
	repo   string
	ref    string
	opts   GiteaOptions
	host   string
}

type GiteaOptions struct {
	UseFork bool
}

func NewGiteaConnectionWithHost(owner, repo, ref, host string) (*GiteaConnection, error) {
	return &GiteaConnection{
		client: nil,
		owner:  owner,
		repo:   repo,
		ref:    ref,
		opts:   GiteaOptions{},
		host:   host,
	}, nil
}

func (g *GiteaConnection) GetClient() (*gitea.Client, error) {
	if g.client != nil {
		return g.client, nil
	}

	token, err := getGiteaToken()
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("no Gitea token found - set GITEA_TOKEN environment variable")
	}

	baseURL := fmt.Sprintf("https://%s", g.host)

	client, err := gitea.NewClient(
		baseURL,
		gitea.SetToken(token),
		gitea.SetHTTPClient(retryablehttp.NewClient().StandardClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Gitea client: %w", err)
	}

	g.client = client
	return g.client, nil
}

func (g *GiteaConnection) Client() *gitea.Client {
	client, _ := g.GetClient()
	return client
}

func (g *GiteaConnection) Owner() string {
	return g.owner
}

func (g *GiteaConnection) Repo() string {
	return g.repo
}

func (g *GiteaConnection) GetFullRef() string {
	return g.ref
}

func (g *GiteaConnection) GetRepoUri() string {
	return fmt.Sprintf("https://%s/%s/%s", g.host, g.owner, g.repo)
}

func (g *GiteaConnection) hostFromClient() string {
	return g.host
}

// BranchToFullRef converts a branch name to a full ref (e.g., "main" -> "refs/heads/main")
func (g *GiteaConnection) BranchToFullRef(branch string) string {
	return BranchToFullRef(branch)
}

// TagToFullRef converts a tag name to a full ref (e.g., "v1.0" -> "refs/tags/v1.0")
func (g *GiteaConnection) TagToFullRef(tag string) string {
	return TagToFullRef(tag)
}

func (g *GiteaConnection) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	client, err := g.GetClient()
	if err != nil {
		return "", err
	}

	branchName := targetBranch
	if len(targetBranch) > 11 && targetBranch[:11] == "refs/heads/" {
		branchName = targetBranch[11:]
	}

	branch, _, err := client.GetRepoBranch(g.owner, g.repo, branchName)
	if err != nil {
		return "", fmt.Errorf("could not get info on specified branch %s: %w", targetBranch, err)
	}
	return branch.Commit.ID, nil
}

func (g *GiteaConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	client, err := g.GetClient()
	if err != nil {
		return "", err
	}

	commit, _, err := client.GetSingleCommit(g.owner, g.repo, sha)
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

// BranchToFullRef converts a branch name to a full ref (e.g., "main" -> "refs/heads/main")
func BranchToFullRef(branch string) string {
	return fmt.Sprintf("refs/heads/%s", branch)
}

// TagToFullRef converts a tag name to a full ref (e.g., "v1.0" -> "refs/tags/v1.0")
func TagToFullRef(tag string) string {
	return fmt.Sprintf("refs/tags/%s", tag)
}

// GetNotesForCommit returns the unparsed notes blob for a commit as stored in
// git via the Gitea API. If no notes data can be found at the specified commit
// GetNotesForCommit returns a blank string (and no error).
func (g *GiteaConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// Gitea doesn't have a native API for git notes like GitHub does.
	// We access them via the repository file API.
	// Git notes are stored at refs/notes/commits, with paths like:
	// - refs/notes/commits/<first 2 chars>/<rest of sha>
	// - refs/notes/commits/<full sha>
	if len(commit) < 6 {
		return "", fmt.Errorf("invalid commit string (too short): %s", commit)
	}

	client, err := g.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	// The notes ref
	noteRef := "refs/notes/commits"

	// Try the sharded path first: <first2>/<rest>
	// Ensure commit is at least 2 characters
	if len(commit) >= 2 {
		path := fmt.Sprintf("%s/%s", commit[0:2], commit[2:])
		content, _, err := client.GetFile(g.owner, g.repo, noteRef, path)
		if err != nil {
			// Try the direct path (full commit sha or as much as we have)
			if strings.Contains(strings.ToLower(err.Error()), "404") {
				content, _, err = client.GetFile(g.owner, g.repo, noteRef, commit)
				if err != nil {
					if strings.Contains(strings.ToLower(err.Error()), "404") {
						// No notes for this commit
						return "", nil
					}
					return "", fmt.Errorf("cannot get note contents for commit %s: %w", commit, err)
				}
			} else {
				return "", fmt.Errorf("cannot get note contents for commit %s: %w", commit, err)
			}
		}
		return string(content), nil
	}

	return "", fmt.Errorf("commit string too short: %s", commit)
}
