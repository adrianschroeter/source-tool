// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/repository/github"
	"github.com/carabiner-dev/collector/repository/note"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

type pushOptions struct {
	pushLocation []string
}

// Support repository types to push
var supportedPushRepos = []string{"github", "note"}

// Validate checks the push options
func (po *pushOptions) Validate() error {
	errs := []error{}
	if len(po.pushLocation) == 0 {
		return nil
	}

	// Check the supported schemes
	for _, repouri := range po.pushLocation {
		if slices.Contains(supportedPushRepos, repouri) {
			continue
		}

		s, _, ok := strings.Cut(repouri, ":")
		if ok && slices.Contains(supportedPushRepos, s) {
			continue
		}

		errs = append(errs, fmt.Errorf("unsupported repository type: %q", repouri))
	}

	return errors.Join(errs...)
}

func (po *pushOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(&po.pushLocation, "push", []string{}, fmt.Sprintf("Push signed attestations to storage %v", supportedPushRepos))
}

func (po *pushOptions) GetCollectorAgent(opts commitOptions, token string) (*collector.Agent, error) {
	if len(po.pushLocation) == 0 {
		return nil, nil
	}

	// Create the attestation storage repositories
	agent, err := collector.New()
	if err != nil {
		return nil, err
	}

	for _, uri := range po.pushLocation {
		var repo attestation.Repository
		var err error

		// Translate just "note" or "github" to the full repo spec acting on
		// the sepcified commit
		switch uri {
		case note.TypeMoniker:
			uri = fmt.Sprintf(
				"note:git+https://github.com/%s/%s@%s",
				opts.owner, opts.repository, opts.commit,
			)
		case github.TypeMoniker:
			uri = fmt.Sprintf("github:%s/%s", opts.owner, opts.repository)
		}
		switch {
		case strings.HasPrefix(uri, "github:"):
			repo, err = github.New(
				// Initialize the github repository
				github.WithInit(uri),
				// We pass the token to use in the githu client
				github.WithToken(token),
			)
		case strings.HasPrefix(uri, "note:"):
			repo, err = note.New(
				// Initialize the notes repository
				note.WithInit(uri),
				// Push is enabled as we will append the note to the remote
				note.WithPush(true),
				// Push via http, using the GH access token
				note.WithHttpAuth("x-access-token", token),
			)
		default:
			return nil, fmt.Errorf("repository type not supported")
		}
		if err != nil {
			return nil, fmt.Errorf("creating storage repository: %w", err)
		}
		agent.AddRepository(repo) //nolint:errcheck,gosec // always returns nil
	}

	return agent, nil
}

// setGiteaPolicyDefaultsCheckLevelProv sets default policy values when using Gitea
func setGiteaPolicyDefaultsCheckLevelProv(opts *checkLevelProvOpts) error {
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
	return nil
}

type checkLevelProvOpts struct {
	commitOptions
	verifierOptions
	pushOptions
	prevBundlePath       string
	prevCommit           string
	outputUnsignedBundle string
	outputSignedBundle   string
	useLocalPolicy       string
	allowMergeCommits    bool
	policyRepo           string
	policyHostname       string
	policyPathOwner      string
	useCurrentControls   bool
	privateKey           string
}

func (clp *checkLevelProvOpts) Validate() error {
	return errors.Join([]error{
		clp.commitOptions.Validate(),
		clp.verifierOptions.Validate(),
	}...)
}

func (clp *checkLevelProvOpts) AddFlags(cmd *cobra.Command) {
	clp.commitOptions.AddFlags(cmd)
	clp.pushOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&clp.prevBundlePath, "prev_bundle_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	cmd.PersistentFlags().StringVar(&clp.prevCommit, "prev_commit", "", "The commit to check.")
	cmd.PersistentFlags().StringVar(&clp.outputUnsignedBundle, "output_unsigned_bundle", "", "The path to write a bundle of unsigned attestations.")
	cmd.PersistentFlags().StringVar(&clp.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&clp.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().BoolVar(&clp.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch")
	cmd.PersistentFlags().StringVar(&clp.policyRepo, "policy-repo", "", "policy repository (owner/repo format)")
	cmd.PersistentFlags().StringVar(&clp.policyHostname, "policy-hostname", "", "hostname to use in policy path (e.g., opensuse.org)")
	cmd.PersistentFlags().StringVar(&clp.policyPathOwner, "policy-path-owner", "", "owner to use in policy path (e.g., slsa-framework)")
	cmd.PersistentFlags().BoolVar(&clp.useCurrentControls, "use-current-controls", false, "Use current branch controls instead of push-time controls (allows retroactive claims)")
	cmd.PersistentFlags().StringVar(&clp.privateKey, "private-key", "", "Path to a PEM-encoded private key for signing (instead of sigstore keyless signing)")
}

func addCheckLevelProv(parentCmd *cobra.Command) {
	opts := &checkLevelProvOpts{}

	checklevelprovCmd := &cobra.Command{
		Use:     "checklevelprov",
		GroupID: "assessment",
		Example: `sourcetool checklevelprov owner/repo --push=note`,
		Short:   "Checks the given commit against policy using & creating provenance",
		Long: `Checks the given commit against policy using & creating provenance.

The checklevelprov subcommand computes the SLSA level of a commit by retrieving
the source policy of the repository and the provenance of its parent revision.

Based on the verification, the subcommand generates the commit's provenance
attestation and a verification summary attestation which can optionally be
signed using Sigstore.

The signed attestations can be pushed to a storage repository: either to the
GitHub attestations API (--push=github) or stored and in the commit's git notes
and pushed to its remote (--push=note).
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			// Set Gitea policy defaults
			if err := setGiteaPolicyDefaultsCheckLevelProv(opts); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCheckLevelProv(opts)
		},
	}

	opts.AddFlags(checklevelprovCmd)
	parentCmd.AddCommand(checklevelprovCmd)
}

func doCheckLevelProv(checkLevelProvArgs *checkLevelProvOpts) error {
	t := githubToken
	var err error
	if t == "" {
		t, err = auth.New().ReadToken()
		if err != nil {
			return err
		}
	}

	factory := vcscontrol.NewFactory()
	hostname := ""
	if giteaURL != "" {
		hostname = giteaURL
	}

	// Create VCS connection for use with attestation
	conn, err := factory.CreateConnection(checkLevelProvArgs.owner, checkLevelProvArgs.repository, checkLevelProvArgs.branch, hostname, t)
	if err != nil {
		return fmt.Errorf("creating VCS connection: %w", err)
	}

	// Create VCS control with the full ref for control checking
	vcsCtrl, connErr := factory.CreateVcsControl(checkLevelProvArgs.owner, checkLevelProvArgs.repository, checkLevelProvArgs.branch, hostname, t)
	if connErr != nil {
		return fmt.Errorf("creating VCS control: %w", connErr)
	}

	fullRef := conn.BranchToFullRef(checkLevelProvArgs.branch)
	ctx := context.Background()

	prevCommit := checkLevelProvArgs.prevCommit
	if prevCommit == "" {
		prevCommit, err = conn.GetPriorCommit(ctx, checkLevelProvArgs.commit)
		if err != nil {
			return err
		}
	}

	pa := attest.NewProvenanceAttestor(vcsCtrl, getVerifier(&checkLevelProvArgs.verifierOptions))
	pa = pa.WithOptions(attest.ProvenanceAttestorOptions{
		UseCurrentControls: checkLevelProvArgs.useCurrentControls,
	})
	prov, err := pa.CreateSourceProvenance(ctx, checkLevelProvArgs.prevBundlePath, checkLevelProvArgs.commit, prevCommit, fullRef)
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = checkLevelProvArgs.useLocalPolicy
	pe.PolicyRepo = checkLevelProvArgs.policyRepo
	pe.PolicyHostname = checkLevelProvArgs.policyHostname
	pe.PolicyPathOwner = checkLevelProvArgs.policyPathOwner
	pe.GiteaURL = hostname
	pe.SkipSinceValidation = checkLevelProvArgs.useCurrentControls
	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(ctx, checkLevelProvArgs.GetRepository(), checkLevelProvArgs.GetBranch(), prov)
	if err != nil {
		return err
	}

	// create vsa
	unsignedVsa, err := attest.CreateUnsignedSourceVsa(conn.GetRepoUri(), fullRef, checkLevelProvArgs.commit, verifiedLevels, policyPath)
	if err != nil {
		return err
	}

	unsignedProv, err := protojson.Marshal(prov)
	if err != nil {
		return err
	}

	// Store both the unsigned provenance and vsa
	switch {
	case checkLevelProvArgs.outputUnsignedBundle != "":
		f, err := os.OpenFile(checkLevelProvArgs.outputUnsignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck

		if _, err := f.WriteString(string(unsignedProv) + "\n" + unsignedVsa + "\n"); err != nil {
			return fmt.Errorf("writing signed bundle: %w", err)
		}
	case checkLevelProvArgs.outputSignedBundle != "" || len(checkLevelProvArgs.pushLocation) > 0:
		var f *os.File
		if checkLevelProvArgs.outputSignedBundle != "" {
			f, err = os.OpenFile(checkLevelProvArgs.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
			if err != nil {
				return err
			}
		}
		defer func() {
			if f != nil {
				f.Close() //nolint:errcheck,gosec
			}
		}()

		signedProv, err := signData(string(unsignedProv), checkLevelProvArgs.privateKey)
		if err != nil {
			return err
		}

		signedVsa, err := signData(unsignedVsa, checkLevelProvArgs.privateKey)
		if err != nil {
			return err
		}

		// If a file was specified, write the attestations
		if f != nil {
			if _, err := f.WriteString(signedProv + "\n" + signedVsa + "\n"); err != nil {
				return fmt.Errorf("writing bundle data: %w", err)
			}
		}

		cl, err := checkLevelProvArgs.GetCollectorAgent(checkLevelProvArgs.commitOptions, t)
		if err != nil {
			return fmt.Errorf("creating storage repositories: %w", err)
		}

		// If there are any storage repositories configured, push the attestations
		if cl != nil {
			// Parse the attestations into envelopes
			envProv, err := envelope.Parsers.Parse(strings.NewReader(signedProv))
			if err != nil || len(envProv) == 0 {
				return fmt.Errorf("parsing provenance: %w", err)
			}
			envVsa, err := envelope.Parsers.Parse(strings.NewReader(signedVsa))
			if err != nil || len(envVsa) == 0 {
				return fmt.Errorf("parsing VSA: %w", err)
			}

			// And store them
			err = cl.Store(ctx, []attestation.Envelope{envProv[0], envVsa[0]})
			if err != nil {
				return fmt.Errorf("storing attestations: %w", err)
			}
		}
	default:
		log.Printf("unsigned prov: %s\n", unsignedProv)
		log.Printf("unsigned vsa: %s\n", unsignedVsa)
	}
	fmt.Print(verifiedLevels)
	return nil
}
