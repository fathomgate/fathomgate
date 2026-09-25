// SPDX-License-Identifier: Apache-2.0

// Package profiles embeds the shipped upstream profiles (profiles/*.yaml) so
// the release binary classifies the shipped upstreams with no files beside
// it (ADR 0027). `fathomgate serve --profiles <dir>` replaces the set; it
// never merges with it.
package profiles

import "embed"

// FS holds every profiles/*.yaml file of the source tree the binary was
// built from, at the top level of the file system.
//
//go:embed *.yaml
var FS embed.FS
