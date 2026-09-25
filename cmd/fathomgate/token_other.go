// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package main

import "errors"

// readTokenFile refuses every token file: on platforms that are neither
// Unix nor Windows fathomgate cannot check that one is owner-only.
// FATHOMGATE_LISTEN_TOKEN still works.
func readTokenFile(string) ([]byte, error) {
	return nil, errors.New("token files cannot be checked for owner-only permissions on this platform; use FATHOMGATE_LISTEN_TOKEN")
}
