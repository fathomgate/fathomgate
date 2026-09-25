// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin

package fileacl

import "os"

// extended reports false: only macOS is checked (see the package comment).
func extended(*os.File) (bool, error) { return false, nil }
