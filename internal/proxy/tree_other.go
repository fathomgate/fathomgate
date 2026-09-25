// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package proxy

import (
	"log/slog"
	"os/exec"
	"time"
)

// procTree is empty where there is neither a process group nor a Job Object
// (none of fathomgate's release targets): only the leader is signalled.
type procTree struct{}

func prepareTree(*exec.Cmd) {}

func attachTree(*exec.Cmd, *slog.Logger) (*procTree, error) {
	if err := injectedFault(); err != nil {
		return nil, err
	}
	return &procTree{}, nil
}

func (*procTree) kill() {}

func (*procTree) terminate() {}

func (*procTree) sweep(time.Duration) {}
