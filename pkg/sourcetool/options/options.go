// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"fmt"

	"github.com/slsa-framework/source-tool/pkg/policy"
)

type Options struct {
	// Organization to look for slsa and user forks
	UserForkOrg string
	Enforce     bool
	UseSSH      bool
	UpdateRepo  bool

	CreatePolicyPR bool

	// PolicyRepo is the repository where the policies are stored
	PolicyRepo string

	// PolicyHostname is the hostname to use in the policy path
	// If not set, the repository's hostname will be used
	PolicyHostname string

	// PolicyPathOwner is the owner to use in the policy path
	// If not set, the default (slsa-framework) will be used
	PolicyPathOwner string
}

// DefaultOptions holds the default options the tool initializes with
var Default = Options{
	PolicyRepo:     fmt.Sprintf("%s/%s", policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo),
	UseSSH:         true,
	CreatePolicyPR: true,
}
