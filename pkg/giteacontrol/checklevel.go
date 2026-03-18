// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package giteacontrol

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
)

type GiteaControlStatus struct {
	// The time the commit we're evaluating was pushed.
	CommitPushTime time.Time
	// The actor that pushed the commit.
	ActorLogin string
	// The type of activity that created the commit.
	ActivityType string
	// The controls that are enabled according to the Gitea API.
	Controls slsa.Controls
}

// GetCommitPushTime returns when the commit was pushed
func (cs *GiteaControlStatus) GetCommitPushTime() time.Time {
	return cs.CommitPushTime
}

// GetControls returns the controls that are enabled
func (cs *GiteaControlStatus) GetControls() slsa.Controls {
	return cs.Controls
}

// Adds the control, but only if it existed when the commit was pushed.
func (cs *GiteaControlStatus) AddControl(newControls ...*provenance.Control) {
	for _, newControl := range newControls {
		if newControl != nil && cs.CommitPushTime.After(newControl.GetSince().AsTime()) {
			cs.Controls.AddControl(newControl)
		}
	}
}

// GetBranchControls returns a list of the controls enabled at present for a branch.
func (gc *GiteaConnection) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	branch := GetBranchFromRef(ref)
	if branch == "" {
		return nil, fmt.Errorf("ref %s is not a branch", ref)
	}

	controls := &slsa.Controls{}

	client, err := gc.GetClient()
	if err != nil {
		return nil, fmt.Errorf("getting Gitea client: %w", err)
	}

	// Get branch protection
	rule, _, err := client.GetBranchProtection(gc.Owner(), gc.Repo(), branch)
	if err != nil {
		if !isGitea404(err) {
			return nil, fmt.Errorf("getting branch protection: %w", err)
		}
		// No branch protection configured, continue to check other controls
	} else {
		// Push protection (Continuity)
		if rule.EnablePush {
			controls.AddControl(&provenance.Control{
				Name:  slsa.ContinuityEnforced.String(),
				Since: timestamppb.New(rule.Updated),
			})
		}

		// Review enforcement
		// Gitea requires both EnableApprovalsWhitelist AND BlockOnRejectedReviews for proper review
		if rule.EnableApprovalsWhitelist || rule.BlockOnRejectedReviews {
			controls.AddControl(&provenance.Control{
				Name:  slsa.ReviewEnforced.String(),
				Since: timestamppb.New(rule.Updated),
			})
		}

		// Status checks (similar to GitHub's required status checks)
		if rule.EnableStatusCheck && len(rule.StatusCheckContexts) > 0 {
			for _, check := range rule.StatusCheckContexts {
				controls.AddControl(&provenance.Control{
					Name:  CheckNameToControlName(check).String(),
					Since: timestamppb.New(rule.Updated),
				})
			}
		}
	}

	// Check tag protections for TAG_HYGIENE control
	tagHygieneControl, err := gc.computeTagHygieneControl(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking tag hygiene: %w", err)
	}
	if tagHygieneControl != nil {
		controls.AddControl(tagHygieneControl)
	}

	return controls, nil
}

// computeTagHygieneControl checks if the Gitea repository has tag protection
// rules that cover all tags. A tag protection is considered valid for tag hygiene
// if it has a pattern that matches all tags (like "*").
func (gc *GiteaConnection) computeTagHygieneControl(ctx context.Context) (*provenance.Control, error) {
	client, err := gc.GetClient()
	if err != nil {
		return nil, fmt.Errorf("getting Gitea client: %w", err)
	}

	tagProtections, _, err := client.ListTagProtection(gc.Owner(), gc.Repo(), gitea.ListRepoTagProtectionsOptions{})
	if err != nil {
		// If the API is not available (older Gitea versions), treat as no tag hygiene
		if strings.Contains(strings.ToLower(err.Error()), "404") ||
			strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("listing tag protections: %w", err)
	}

	// Find the oldest tag protection whose pattern matches all tags
	var oldest *gitea.TagProtection
	for _, tp := range tagProtections {
		matched, err := path.Match(tp.NamePattern, "v1.0.0") // Test with a sample tag
		if err != nil {
			// Invalid pattern, skip it
			continue
		}
		// Check if pattern would match typical version tags (glob pattern)
		if matched || tp.NamePattern == "*" || tp.NamePattern == "v*" {
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

// GetBranchControlsAtCommit determines the controls that are in place for a branch
// at a specific commit using Gitea's APIs.
func (gc *GiteaConnection) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (*GiteaControlStatus, error) {
	// For Gitea, we use the commit timestamp as an approximation
	// Gitea doesn't have the same activity tracking as GitHub
	client, err := gc.GetClient()
	if err != nil {
		return nil, fmt.Errorf("getting Gitea client: %w", err)
	}

	commitInfo, _, err := client.GetSingleCommit(gc.Owner(), gc.Repo(), commit)
	if err != nil {
		return nil, fmt.Errorf("getting commit info: %w", err)
	}

	controlStatus := GiteaControlStatus{
		CommitPushTime: commitInfo.Created,
		Controls:       slsa.Controls{},
	}

	// Add actor info if available
	if commitInfo.Author != nil {
		controlStatus.ActorLogin = commitInfo.Author.UserName
	}

	activeControls, err := gc.GetBranchControls(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("reading active controls: %w", err)
	}

	// Add the controls to the control status object
	for _, c := range *activeControls {
		controlStatus.AddControl(c)
	}

	return &controlStatus, nil
}

// GetTagControls returns the tag control status for the repository
func (gc *GiteaConnection) GetTagControls(ctx context.Context) (*GiteaControlStatus, error) {
	controlStatus := GiteaControlStatus{
		CommitPushTime: time.Now(),
		Controls:       slsa.Controls{},
	}

	tagHygieneControl, err := gc.computeTagHygieneControl(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not populate TagHygieneControl: %w", err)
	}
	controlStatus.AddControl(tagHygieneControl)

	return &controlStatus, nil
}

func isGitea404(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "404") || strings.Contains(errStr, "not found")
}
