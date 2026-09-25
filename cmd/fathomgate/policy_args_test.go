// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// TestArgumentDecision: policy eval shows the gate's deny for arguments the
// profile does not name (ADR 0033), with a fixed reason that quotes no
// argument name, and the names only in the operator's trace.
func TestArgumentDecision(t *testing.T) {
	if d := argumentDecision(classify.Result{}); d != nil {
		t.Fatalf("clean arguments: %+v", d)
	}
	d := argumentDecision(classify.Result{UnnamedArgs: []string{"config_path"}})
	if d == nil || d.Effect != policy.Deny || d.RuleID != "default:bad_arguments" {
		t.Fatalf("unnamed: %+v", d)
	}
	if strings.Contains(d.Reason, "config_path") {
		t.Errorf("reason quotes the argument: %q", d.Reason)
	}
	if len(d.Trace) != 1 || !d.Trace[0].Matched || !strings.Contains(d.Trace[0].Note, `"config_path"`) {
		t.Errorf("trace: %+v", d.Trace)
	}
	d = argumentDecision(classify.Result{MalformedArgs: []string{"hostname"}})
	if d == nil || !strings.Contains(d.Reason, "not a string") {
		t.Fatalf("malformed: %+v", d)
	}
}
