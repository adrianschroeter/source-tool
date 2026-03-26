// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

type checkTagOptions struct {
	repoOptions
	verifierOptions
	commit             string
	tagName            string
	actor              string
	outputSignedBundle string
	useLocalPolicy     string
	vsaRetries         uint8
	policyRepo         string
	policyHostname     string
	policyPathOwner    string
	privateKey         string
}

func (cto *checkTagOptions) Validate() error {
	errs := []error{
		cto.repoOptions.Validate(),
		cto.verifierOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (cto *checkTagOptions) AddFlags(cmd *cobra.Command) {
	cto.repoOptions.AddFlags(cmd)
	cto.verifierOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&cto.commit, "commit", "", "The commit to check - required.")
	cmd.PersistentFlags().StringVar(&cto.tagName, "tag_name", "", "The name of the new tag - required.")
	cmd.PersistentFlags().StringVar(&cto.actor, "actor", "", "The username of the actor that pushed the tag.")
	cmd.PersistentFlags().StringVar(&cto.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&cto.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().Uint8Var(&cto.vsaRetries, "retries", 3, "Number of times to retry fetching the commit's VSA")
	cmd.PersistentFlags().StringVar(&cto.policyRepo, "policy-repo", "", "policy repository (owner/repo format)")
	cmd.PersistentFlags().StringVar(&cto.policyHostname, "policy-hostname", "", "hostname to use in policy path (e.g., opensuse.org)")
	cmd.PersistentFlags().StringVar(&cto.policyPathOwner, "policy-path-owner", "", "owner to use in policy path (e.g., slsa-framework)")
	cmd.PersistentFlags().StringVar(&cto.privateKey, "private-key", "", "Path to a PEM-encoded private key for signing (instead of sigstore keyless signing)")
}

// setGiteaPolicyDefaultsCheckTag sets default policy values when using Gitea
func setGiteaPolicyDefaultsCheckTag(opts *checkTagOptions) {
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

func addCheckTag(parentCmd *cobra.Command) {
	opts := &checkTagOptions{}

	checktagCmd := &cobra.Command{
		Use:     "checktag",
		GroupID: "assessment",
		Short:   "Checks to see if the tag operation should be allowed and issues a VSA",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				// Parse owner/repo from args[0] if provided
				pts := strings.Split(strings.TrimPrefix(strings.TrimSuffix(args[0], "/"), "/"), "/")
				if len(pts) == 2 {
					opts.owner = pts[0]
					opts.repository = pts[1]
				}
			}
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}
			setGiteaPolicyDefaultsCheckTag(opts)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCheckTag(opts)
		},
	}

	opts.AddFlags(checktagCmd)
	parentCmd.AddCommand(checktagCmd)
}

func doCheckTag(args *checkTagOptions) error {
	factory := vcscontrol.NewFactory()
	hostname := ""
	if giteaURL != "" {
		hostname = giteaURL
	}

	// Create VCS control to get both connection and provider
	vcsCtrl, err := factory.CreateVcsControl(args.owner, args.repository, args.tagName, hostname, githubToken)
	if err != nil {
		return fmt.Errorf("creating VCS control: %w", err)
	}

	ctx := context.Background()
	verifier := getVerifier(&args.verifierOptions)

	// Create tag provenance.
	pa := attest.NewProvenanceAttestor(vcsCtrl, verifier)
	pa.Options.VsaRetries = args.vsaRetries // Retry fetching the commit's VSA

	prov, err := pa.CreateTagProvenance(ctx, args.commit, vcsCtrl.TagToFullRef(args.tagName), args.actor)
	if err != nil {
		return fmt.Errorf("creating tag provenance metadata: %w", err)
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = args.useLocalPolicy
	pe.PolicyRepo = args.policyRepo
	pe.PolicyHostname = args.policyHostname
	pe.PolicyPathOwner = args.policyPathOwner
	pe.GiteaURL = hostname
	verifiedLevels, policyPath, err := pe.EvaluateTagProv(ctx, args.GetRepository(), prov)
	if err != nil {
		return fmt.Errorf("evaluating the tag provenance metadata: %w", err)
	}

	// create vsa
	unsignedVsa, err := attest.CreateUnsignedSourceVsa(vcsCtrl.GetRepoUri(), vcsCtrl.GetFullRef(), args.commit, verifiedLevels, policyPath)
	if err != nil {
		return err
	}

	unsignedProv, err := protojson.Marshal(prov)
	if err != nil {
		return err
	}

	if args.outputSignedBundle != "" {
		f, err := os.OpenFile(args.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck

		signedProv, err := signData(string(unsignedProv), args.privateKey)
		if err != nil {
			return err
		}

		signedVsa, err := signData(unsignedVsa, args.privateKey)
		if err != nil {
			return err
		}

		if _, err := f.WriteString(signedProv + "\n" + signedVsa + "\n"); err != nil {
			return fmt.Errorf("writing bundledata: %w", err)
		}
	} else {
		log.Printf("unsigned prov: %s\n", unsignedProv)
		log.Printf("unsigned vsa: %s\n", unsignedVsa)
	}
	fmt.Print(verifiedLevels)
	return nil
}
