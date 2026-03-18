// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package giteacontrol

var defaultOptions = Options{
	ApiRetries: 3,
}

type Options struct {
	// accessToken is the token we will use to connect to the Gitea API
	accessToken string

	// ApiRetries controls the number of time we retry calls to the Gitea API
	ApiRetries uint8
}
