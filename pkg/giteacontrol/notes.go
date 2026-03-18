// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package giteacontrol

import (
	"context"
	"fmt"
	"strings"
)

// GetNotesForCommit returns the unparsed notes blob for a commit as stored in
// git via the Gitea API. If no notes data can be found at the specified commit
// GetNotesForCommit returns a blank string (and no error).
func (gc *GiteaConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// Gitea doesn't have a native API for git notes like GitHub does.
	// We access them via the repository file API.
	// Git notes are stored at refs/notes/commits, with paths like:
	// - refs/notes/commits/<first 2 chars>/<rest of sha>
	// - refs/notes/commits/<full sha>
	if len(commit) != 40 {
		return "", fmt.Errorf("invalid commit string")
	}

	client, err := gc.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	// The notes ref
	noteRef := "refs/notes/commits"

	// Try the sharded path first: <first2>/<rest>
	path := fmt.Sprintf("%s/%s", commit[0:2], commit[2:])
	content, _, err := client.GetFile(gc.Owner(), gc.Repo(), noteRef, path)
	if err != nil {
		// Try the direct path (full commit sha)
		if strings.Contains(strings.ToLower(err.Error()), "404") {
			content, _, err = client.GetFile(gc.Owner(), gc.Repo(), noteRef, commit)
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
