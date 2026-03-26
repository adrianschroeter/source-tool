// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

type verifyCommitOptions struct {
	commitOptions
	verifierOptions
	outputOptions
	tag string
}

// VerifyCommitResult represents the result of a commit verification
type VerifyCommitResult struct {
	Success        bool     `json:"success"`
	Commit         string   `json:"commit"`
	Ref            string   `json:"ref"`
	RefType        string   `json:"ref_type"` // "branch" or "tag"
	Owner          string   `json:"owner"`
	Repository     string   `json:"repository"`
	VerifiedLevels []string `json:"verified_levels,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// String implements fmt.Stringer for text output
func (v VerifyCommitResult) String() string {
	if !v.Success {
		return fmt.Sprintf("FAILED: %s\n", v.Message)
	}
	return fmt.Sprintf("SUCCESS: commit %s on %s verified with %v\n", v.Commit, v.Ref, v.VerifiedLevels)
}

func (vco *verifyCommitOptions) Validate() error {
	errs := []error{
		vco.commitOptions.Validate(),
		vco.verifierOptions.Validate(),
		vco.outputOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (vco *verifyCommitOptions) AddFlags(cmd *cobra.Command) {
	vco.commitOptions.AddFlags(cmd)
	vco.verifierOptions.AddFlags(cmd)
	vco.outputOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&vco.tag, "tag", "", "The tag within the repository",
	)
}

//nolint:dupl
func addVerifyCommit(cmd *cobra.Command) {
	opts := verifyCommitOptions{}
	verifyCommitCmd := &cobra.Command{
		Use:     "verifycommit",
		GroupID: "verification",
		Short:   "Verifies the specified commit is valid",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}
			return doVerifyCommit(&opts)
		},
	}
	opts.AddFlags(verifyCommitCmd)
	cmd.AddCommand(verifyCommitCmd)
}

func doVerifyCommit(opts *verifyCommitOptions) error {
	// Check if GITEA_TOKEN is set when using Gitea
	if giteaURL != "" {
		if token := os.Getenv("GITEA_TOKEN"); token == "" {
			return fmt.Errorf("GITEA_TOKEN environment variable is not set - this is required when using --gitea_url parameter")
		}
	}

	// Use the unified vcscontrol factory
	factory := vcscontrol.NewFactory()
	hostname := ""
	if giteaURL != "" {
		hostname = giteaURL
	}

	// Determine ref type and name
	var refType string
	var refName string
	var ref string

	switch {
	case opts.branch != "":
		refType = "branch"
		refName = opts.branch
		// Create connection first, then use its methods
		conn, err := factory.CreateConnection(opts.owner, opts.repository, opts.branch, hostname, githubToken)
		if err != nil {
			return fmt.Errorf("creating VCS connection: %w", err)
		}
		ref = conn.BranchToFullRef(opts.branch)
	case opts.tag != "":
		refType = "tag"
		refName = opts.tag
		// Create connection first, then use its methods
		conn, err := factory.CreateConnection(opts.owner, opts.repository, opts.tag, hostname, githubToken)
		if err != nil {
			return fmt.Errorf("creating VCS connection: %w", err)
		}
		ref = conn.TagToFullRef(opts.tag)
	default:
		return fmt.Errorf("must specify either branch or tag")
	}

	// Recreate connection with the correct ref
	conn, err := factory.CreateConnection(opts.owner, opts.repository, ref, hostname, githubToken)
	if err != nil {
		return fmt.Errorf("creating VCS connection: %w", err)
	}

	ctx := context.Background()

	_, vsaPred, err := attest.GetVsa(ctx, conn, getVerifier(&opts.verifierOptions), opts.commit, conn.GetFullRef())
	if err != nil {
		return err
	}

	result := VerifyCommitResult{
		Success:    vsaPred != nil,
		Commit:     opts.commit,
		Ref:        refName,
		RefType:    refType,
		Owner:      opts.owner,
		Repository: opts.repository,
	}

	if vsaPred == nil {
		host := "github.com"
		if giteaURL != "" {
			host = giteaURL
		}
		result.Message = fmt.Sprintf(
			"no VSA matching commit '%s' on %s '%s' found in %s/%s/%s",
			opts.commit, refType, refName, host, opts.owner, opts.repository,
		)
		return opts.writeResult(result)
	}

	result.VerifiedLevels = vsaPred.GetVerifiedLevels()
	return opts.writeResult(result)
}
