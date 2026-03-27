// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	sourcetoolmodels "github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

var (
	w  = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
)

// statusOptions
type statusOptions struct {
	commitOptions
	verifierOptions
	policyRepo      string
	policyHostname  string
	policyPathOwner string
}

// Validate checks the options
func (so *statusOptions) Validate() error {
	errs := []error{} //nolint:prealloc
	errs = append(errs, so.commitOptions.Validate())
	errs = append(errs, so.verifierOptions.Validate())

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *statusOptions) AddFlags(cmd *cobra.Command) {
	so.commitOptions.AddFlags(cmd)
	so.verifierOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&so.policyRepo, "policy-repo", "", "policy repository (owner/repo format)",
	)
	cmd.PersistentFlags().StringVar(
		&so.policyHostname, "policy-hostname", "", "hostname to use in policy path (e.g., opensuse.org)",
	)
	cmd.PersistentFlags().StringVar(
		&so.policyPathOwner, "policy-path-owner", "", "owner to use in policy path (e.g., slsa-framework)",
	)
}

// TODO(puerco): Most of the logic in this subcommand (except maybe the output)
// will be moved to a sourcetool object in the future to consolidate it into
// a reusable library.
func addStatus(parentCmd *cobra.Command) {
	opts := &statusOptions{}
	statusCmd := &cobra.Command{
		GroupID: "assessment",
		Short:   "Check the SLSA Source status of a repo/branch",
		Long: `
sourcetool status: Check the SLSA Source status of a repo/branch

The status subcommand reads the current controls enabled for a branch
and reports the SLSA source level that the repository can claim. This
command is intended to help maintainers implementing SLSA controls
understand the next steps to secure their repos and progress in their
SLSA journey. 
`,
		Use:           "status [flags] owner/repo@branch",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: `Check the SLSA tooling status on a repository:
sourcetool status myorg/myrepo

A branch other than the default can be specified by appending it to
the repository slug:

sourcetool status myorg/myrepo@mybranch
`,
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

			// If using Gitea, set default policy repo and hostname
			if giteaURL != "" {
				// Check if GITEA_TOKEN is set
				if token := os.Getenv("GITEA_TOKEN"); token == "" {
					return fmt.Errorf("GITEA_TOKEN environment variable is not set - this is required when using --gitea_url parameter")
				}

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

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create verifier options from verifierOptions
			verifierOpts := attest.DefaultVerifierOptions
			if opts.expectedIssuer != "" {
				verifierOpts.ExpectedIssuer = opts.expectedIssuer
			}
			if opts.expectedSan != "" {
				verifierOpts.ExpectedSan = opts.expectedSan
			}
			if opts.publicKey != "" {
				verifierOpts.PublicKey = opts.publicKey
			}

			// Create a new sourcetool object
			policyRepo := opts.policyRepo
			if policyRepo == "" {
				policyRepo = fmt.Sprintf("%s/%s", policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo)
			}
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithPolicyRepo(policyRepo),
				sourcetool.WithPolicyHostname(opts.policyHostname),
				sourcetool.WithPolicyPathOwner(opts.policyPathOwner),
				sourcetool.WithVerifierOptions(verifierOpts),
			)
			if err != nil {
				return err
			}

			// Get the active repository controls
			// Use the commit-specific method if a commit is provided
			var controls *slsa.ControlSetStatus
			var controlsErr error

			// Get the repository and branch
			repo := opts.GetRepository()
			branch := opts.GetBranch()

			if opts.commit != "" {
				// Use GetBranchControlsAtCommit to check provenance for the specific commit
				commit := &sourcetoolmodels.Commit{SHA: opts.commit}
				controls, controlsErr = srctool.GetBranchControlsAtCommit(cmd.Context(), repo, branch, commit)
			} else {
				controls, controlsErr = srctool.GetBranchControls(cmd.Context(), repo, branch)
			}

			if controlsErr != nil {
				return fmt.Errorf("fetching active controls: %w", controlsErr)
			}

			// Compute the maximum level possible:
			toplevel := policy.ComputeEligibleSlsaLevel(*controls.GetActiveControls())

			title := fmt.Sprintf(
				"\nSLSA Source Status for %s/%s@%s", opts.owner, opts.repository,
				ghcontrol.BranchToFullRef(opts.branch),
			)

			fmt.Println(w(title))
			fmt.Println(strings.Repeat("=", len(title)))

			var policyControlStatus *slsa.ControlStatus
			for _, c := range controls.Controls {
				if c.Name == slsa.PolicyAvailable {
					policyControlStatus = &c
					continue
				}
				fmt.Printf("%-35s  ", c.Name)
				switch c.State {
				case slsa.StateActive:
					fmt.Println("✅")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if c.Message != "" {
						fmt.Print(w2(c.Message))
					}
					fmt.Println()
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				}
			}

			fmt.Println()
			policyNeedsUpdate := false
			if policyControlStatus != nil {
				fmt.Printf("%-35s  ", "Repo policy found:")
				switch policyControlStatus.State {
				case slsa.StateActive:
					fmt.Print("✅")
					// Check if the policy needs updating
					pcy, err := srctool.GetRepositoryPolicy(context.Background(), opts.GetRepository())
					if err == nil {
						pb := pcy.GetBranchPolicy(opts.GetBranch().Name)
						if pb != nil && pb.GetTargetSlsaSourceLevel() != string(toplevel) {
							fmt.Print(w2(fmt.Sprintf(" (needs update to %s)", toplevel)))
							policyNeedsUpdate = true
						}
					}
					fmt.Println()
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if policyControlStatus.Message != "" {
						fmt.Printf(" (%s)", policyControlStatus.Message)
					}
					fmt.Println()
				}
				fmt.Println()
			}

			fmt.Println(w("Current SLSA Source level: " + toplevel))
			fmt.Println("")
			titled := false
			for _, status := range controls.Controls {
				if status.RecommendedAction == nil {
					continue
				}

				// Suggest creating the policy but only when reaching SLSA3+
				if status.Name == slsa.PolicyAvailable && !slsa.IsLevelHigherOrEqualTo(toplevel, slsa.SlsaSourceLevel3) {
					continue
				}

				if !titled {
					fmt.Println(w2("✨ Recommended actions:"))
					titled = true
				}

				fmt.Printf(" - %s\n", status.RecommendedAction.Message)
				if status.RecommendedAction.Command != "" {
					fmt.Printf("   > %s\n", status.RecommendedAction.Command)
				}
				fmt.Println()
			}

			if policyNeedsUpdate {
				if !titled {
					fmt.Println(w2("✨ Recommended actions:"))
				}
				fmt.Println(" - Update the repository source policy")
				fmt.Printf("   > sourcetool policy create --update %s\n", opts.GetRepository().Path)
				fmt.Println()
			}

			return nil
		},
	}
	opts.AddFlags(statusCmd)
	parentCmd.AddCommand(statusCmd)
}
