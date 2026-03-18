// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

// setGiteaPolicyDefaults sets default policy values when using Gitea
func setGiteaPolicyDefaults(opts *checkLevelOpts) {
	if giteaURL != "" {
		if opts.policyRepo == "" {
			opts.policyRepo = "obs/slsa"
		}
		if opts.policyHostname == "" {
			// Extract hostname from gitea URL (e.g., src.opensuse.org -> opensuse.org)
			hostname := giteaURL
			if strings.HasPrefix(hostname, "https://") {
				hostname = strings.TrimPrefix(hostname, "https://")
			} else if strings.HasPrefix(hostname, "http://") {
				hostname = strings.TrimPrefix(hostname, "http://")
			}
			// Remove port if present
			if idx := strings.Index(hostname, ":"); idx != -1 {
				hostname = hostname[:idx]
			}
			// Extract the main domain (e.g., src.opensuse.org -> opensuse.org)
			parts := strings.Split(hostname, ".")
			if len(parts) >= 2 {
				opts.policyHostname = strings.Join(parts[len(parts)-2:], ".")
			} else {
				opts.policyHostname = hostname
			}
		}
	}
}

type checkLevelOpts struct {
	commitOptions
	outputVsa, outputUnsignedVsa, useLocalPolicy string
	allowMergeCommits                            bool
	policyRepo, policyHostname, policyPathOwner  string
}

func (clo *checkLevelOpts) Validate() error {
	errs := []error{
		clo.commitOptions.Validate(),
	}

	return errors.Join(errs...)
}

func (clo *checkLevelOpts) AddFlags(cmd *cobra.Command) {
	clo.commitOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&clo.outputVsa, "output_vsa", "", "The path to write a signed VSA with the determined level.")
	cmd.PersistentFlags().StringVar(&clo.outputUnsignedVsa, "output_unsigned_vsa", "", "The path to write an unsigned vsa with the determined level.")
	cmd.PersistentFlags().StringVar(&clo.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().BoolVar(&clo.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch.")
	cmd.PersistentFlags().StringVar(&clo.policyRepo, "policy-repo", "", "policy repository (owner/repo format)")
	cmd.PersistentFlags().StringVar(&clo.policyHostname, "policy-hostname", "", "hostname to use in policy path (e.g., opensuse.org)")
	cmd.PersistentFlags().StringVar(&clo.policyPathOwner, "policy-path-owner", "", "owner to use in policy path (e.g., slsa-framework)")
}

func addCheckLevel(parentCmd *cobra.Command) {
	opts := checkLevelOpts{}

	checklevelCmd := &cobra.Command{
		Use:     "checklevel",
		GroupID: "assessment",
		Short:   "Determines the SLSA Source Level of the repo",
		Long: `Determines the SLSA Source Level of the repo.

This is meant to be run within the corresponding GitHub Actions workflow.`,
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

			// Set Gitea policy defaults
			setGiteaPolicyDefaults(&opts)

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			return doCheckLevel(&opts)
		},
	}
	opts.AddFlags(checklevelCmd)
	parentCmd.AddCommand(checklevelCmd)
}

func doCheckLevel(cla *checkLevelOpts) error {
	var repoUri string
	var fullRef string
	var controlStatus vcscontrol.ControlStatus
	var err error

	ctx := context.Background()

	factory := vcscontrol.NewFactory()

	// Determine the hostname to use
	hostname := ""
	if giteaURL != "" {
		hostname = giteaURL
	}

	// Create VCS connection to get the full ref
	conn, connErr := factory.CreateConnection(cla.owner, cla.repository, cla.branch, hostname, githubToken)
	if connErr != nil {
		return fmt.Errorf("creating VCS connection: %w", connErr)
	}
	fullRef = conn.BranchToFullRef(cla.branch)

	// Now create VCS control with the full ref
	vcsCtrl, ctrlErr := factory.CreateVcsControl(cla.owner, cla.repository, fullRef, hostname, githubToken)
	if ctrlErr != nil {
		return fmt.Errorf("creating VCS control: %w", ctrlErr)
	}

	repoUri = conn.GetRepoUri()

	// Get branch controls at commit
	status, statusErr := vcsCtrl.GetBranchControlsAtCommit(ctx, cla.commit, fullRef)
	if statusErr != nil {
		return statusErr
	}
	controlStatus = status

	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = cla.useLocalPolicy
	pe.PolicyRepo = cla.policyRepo
	pe.PolicyHostname = cla.policyHostname
	pe.PolicyPathOwner = cla.policyPathOwner
	pe.GiteaURL = hostname
	verifiedLevels, policyPath, evalErr := pe.EvaluateControl(ctx, cla.GetRepository(), cla.GetBranch(), controlStatus)
	if evalErr != nil {
		return evalErr
	}
	fmt.Print(verifiedLevels)

	unsignedVsa, err := attest.CreateUnsignedSourceVsa(repoUri, fullRef, cla.commit, verifiedLevels, policyPath)
	if err != nil {
		return err
	}
	if cla.outputUnsignedVsa != "" {
		if err := os.WriteFile(cla.outputUnsignedVsa, []byte(unsignedVsa), 0o644); err != nil { //nolint:gosec
			return err
		}
	}

	if cla.outputVsa != "" {
		// This will output in the sigstore bundle format.
		signedVsa, err := attest.Sign(unsignedVsa)
		if err != nil {
			return err
		}
		err = os.WriteFile(cla.outputVsa, []byte(signedVsa), 0o644) //nolint:gosec
		if err != nil {
			return err
		}
	}

	return nil
}
