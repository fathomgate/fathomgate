// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package fileacl

import "os"

// extended reports false: only macOS is checked (see the package comment).
func extended(*os.File) (bool, error) { return false, nil }
