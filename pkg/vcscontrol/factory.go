// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package vcscontrol

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/giteacontrol"
)

// Factory provides convenient ways to create VCS connections
type Factory struct{}

// NewFactory creates a new Factory
func NewFactory() *Factory {
	return &Factory{}
}

// DetectVcsType detects the VCS type from a hostname or URL
func (f *Factory) DetectVcsType(hostnameOrURL string) VcsType {
	host := hostnameOrURL

	// If it's a URL, extract the hostname
	if strings.HasPrefix(hostnameOrURL, "http://") || strings.HasPrefix(hostnameOrURL, "https://") {
		u, err := url.Parse(hostnameOrURL)
		if err == nil && u.Host != "" {
			host = u.Host
		}
	}

	// Check if it's GitHub
	if host == "github.com" || host == "" {
		return VcsTypeGitHub
	}

	// Default to Gitea for everything else
	return VcsTypeGitea
}

// CreateConnection creates a connection based on the hostname or URL
func (f *Factory) CreateConnection(owner, repo, ref, hostnameOrURL, token string) (Connection, error) {
	vcsType := f.DetectVcsType(hostnameOrURL)

	switch vcsType {
	case VcsTypeGitHub:
		return NewGitHubConnectionWithToken(owner, repo, ref, token)
	case VcsTypeGitea:
		baseURL := hostnameOrURL
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + hostnameOrURL
		}
		return NewGiteaConnection(owner, repo, ref, baseURL)
	default:
		return nil, fmt.Errorf("unsupported VCS type: %s", vcsType)
	}
}

// CreateControlProvider creates a control provider based on the hostname or URL
func (f *Factory) CreateControlProvider(owner, repo, ref, hostnameOrURL, token string) (Connection, ControlProvider, error) {
	vcsType := f.DetectVcsType(hostnameOrURL)

	switch vcsType {
	case VcsTypeGitHub:
		ghConn := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(token)
		return &gitHubConnection{conn: ghConn}, &gitHubControlProvider{conn: ghConn}, nil
	case VcsTypeGitea:
		baseURL := hostnameOrURL
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + hostnameOrURL
		}
		conn, err := giteacontrol.NewGiteaConnection(owner, repo, ref, baseURL)
		if err != nil {
			return nil, nil, err
		}
		return &giteaConnection{conn: conn}, &giteaControlProvider{conn: conn}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported VCS type: %s", vcsType)
	}
}

// CreateVcsControl creates a unified VcsControl based on hostname or URL
func (f *Factory) CreateVcsControl(owner, repo, ref, hostnameOrURL, token string) (*VcsControl, error) {
	vcsType := f.DetectVcsType(hostnameOrURL)

	switch vcsType {
	case VcsTypeGitHub:
		return NewVcsControlGitHub(owner, repo, ref, token)
	case VcsTypeGitea:
		baseURL := hostnameOrURL
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "https://" + hostnameOrURL
		}
		return NewVcsControlGitea(owner, repo, ref, baseURL)
	default:
		return nil, fmt.Errorf("unsupported VCS type: %s", vcsType)
	}
}

// ExtractHostname extracts the hostname from a URL or returns the input if it's already a hostname
func ExtractHostname(hostnameOrURL string) string {
	if strings.HasPrefix(hostnameOrURL, "http://") || strings.HasPrefix(hostnameOrURL, "https://") {
		u, err := url.Parse(hostnameOrURL)
		if err == nil && u.Host != "" {
			return u.Host
		}
	}
	return hostnameOrURL
}

// ExtractDomain extracts the main domain (e.g., opensuse.org from src.opensuse.org)
func ExtractDomain(hostnameOrURL string) string {
	host := ExtractHostname(hostnameOrURL)
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}
