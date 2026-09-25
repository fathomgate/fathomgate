// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package configfile

import "os"

func open(_, what string, _ bool) (*os.File, error) {
	return nil, refuse("fathomgate cannot check who can change %s on this system", what)
}
