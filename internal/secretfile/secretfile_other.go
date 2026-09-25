// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package secretfile

// read refuses every file: on platforms that are neither Unix nor Windows
// fathomgate cannot check that one is owner-only.
func read(_, what string, _ int64) ([]byte, error) {
	return nil, refuse("%s cannot be checked for owner-only permissions on this platform", what)
}
