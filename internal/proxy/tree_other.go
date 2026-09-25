// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package proxy

import (
	"os/exec"
	"time"
)

// procTree is empty where there is neither a process group nor a Job Object
// (none of fathomgate's release targets): only the leader is signalled.
type procTree struct{}

func prepareTree(*exec.Cmd) {}

func attachTree(*exec.Cmd) (*procTree, error) { return &procTree{}, nil }

func (*procTree) kill() {}

func (*procTree) terminate() {}

func (*procTree) sweep(time.Duration) {}
