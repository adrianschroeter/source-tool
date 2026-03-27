// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/auth"
)

var (
	githubToken string
	giteaURL    string
)

func getVerifier(vo *verifierOptions) attest.Verifier {
	options := attest.DefaultVerifierOptions
	if vo.expectedIssuer != "" {
		options.ExpectedIssuer = vo.expectedIssuer
	}
	if vo.expectedSan != "" {
		options.ExpectedSan = vo.expectedSan
	}
	if vo.publicKey != "" {
		options.PublicKey = vo.publicKey
	}
	return attest.NewBndVerifier(options)
}

func buildRootCommand() *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	rootCmd := &cobra.Command{
		Use:   "sourcetool",
		Short: "A tool to manage SLSA Source in code repositories",
		Long: `
SLSA sourcetool: Manage SLSA Source controls and data

The sourcetool utility lets repository administrators configure and manage
the SLSA Source security controls in repositories. sourcetool can generate
attestations and verify them, check the status of repositories, configure
controls and much more.
`,
	}

	rootCmd.PersistentFlags().StringVar(&githubToken, "github_token", "", "the github token to use for auth")
	rootCmd.PersistentFlags().StringVar(&giteaURL, "gitea_url", "", "Gitea instance URL (e.g., https://src.opensuse.org)")

	// Define command groups for better organization
	rootCmd.AddGroup(
		&cobra.Group{
			ID:    "verification",
			Title: "Verification Commands:",
		},
		&cobra.Group{
			ID:    "assessment",
			Title: "Assessment Commands:",
		},
		&cobra.Group{
			ID:    "policy",
			Title: "Policy Commands:",
		},
		&cobra.Group{
			ID:    "configuration",
			Title: "Configuration & Setup Commands:",
		},
	)

	// Verification commands
	addVerifyCommit(rootCmd)
	addAudit(rootCmd)

	// Assessment commands
	addStatus(rootCmd)
	addCheckLevel(rootCmd)
	addCheckLevelProv(rootCmd)
	addCheckTag(rootCmd)
	addProv(rootCmd)

	// Policy commands
	addPolicy(rootCmd)
	addCreatePolicy(rootCmd)

	// Configuration & setup commands
	addSetup(rootCmd)
	addAuth(rootCmd)

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func CheckAuth() (*auth.Authenticator, error) {
	authenticator := auth.New()

	// First try GitHub auth
	user, err := authenticator.WhoAmI()
	if err == nil && user != nil {
		return authenticator, nil
	}

	// If GitHub auth fails, try Gitea auth if GITEA_TOKEN is set
	if os.Getenv("GITEA_TOKEN") != "" || tokenFileExists() {
		// For Gitea, we just need to return an authenticator
		// The Gitea backend will handle its own auth
		return authenticator, nil
	}

	// No auth available
	if user == nil {
		fmt.Println()
		fmt.Println("🚫  " + w("sourcetool is not logged in"))
		fmt.Println()
		fmt.Println("Please log into your GitHub account before using sourcetool. To")
		fmt.Println("log in, run the following command:")
		fmt.Println()
		fmt.Println("  sourcetool auth login")
		fmt.Println()
		return nil, errors.New("source tool is not logged in")
	}
	return authenticator, nil
}

func tokenFileExists() bool {
	dir, err := os.UserConfigDir()
	if err != nil {
		return false
	}
	_, err = os.ReadFile(filepath.Join(dir, "slsa", "sourcetool.gitea.token"))
	return err == nil
}
