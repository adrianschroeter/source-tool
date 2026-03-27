// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package giteacontrol

import (
	"context"
	"fmt"
	"strings"

	"code.gitea.io/sdk/gitea"
)

// GetNotesForCommit returns the unparsed notes blob for a commit as stored in
// git via the Gitea API. If no notes data can be found at the specified commit
// GetNotesForCommit returns a blank string (and no error).
func (gc *GiteaConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// Gitea has a dedicated API endpoint for git notes
	if len(commit) != 40 {
		return "", fmt.Errorf("invalid commit string")
	}

	client, err := gc.GetClient()
	if err != nil {
		return "", fmt.Errorf("getting Gitea client: %w", err)
	}

	// Use the dedicated Git Notes API endpoint
	// GET /repos/{owner}/{repo}/git/notes/{sha}
	note, _, err := client.GetRepoNote(gc.Owner(), gc.Repo(), commit, gitea.GetRepoNoteOptions{})
	if err != nil {
		// Check if it's a 404 - note doesn't exist
		if strings.Contains(strings.ToLower(err.Error()), "404") {
			return "", nil
		}
		return "", fmt.Errorf("getting note for commit %s: %w", commit, err)
	}

	if note == nil {
		return "", nil
	}

	// The Note struct has a Message field containing the note content
	return note.Message, nil
}
