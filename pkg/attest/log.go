// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"log"
)

func Debugf(format string, args ...any) {
	log.Printf(fmt.Sprintf(format, args...))
}
