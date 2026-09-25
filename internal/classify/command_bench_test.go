// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
)

// BenchmarkClassifyCommand is the cost of one command through the
// downgrade checks, short and at maxCommandLen.
func BenchmarkClassifyCommand(b *testing.B) {
	long := "show interfaces" + strings.Repeat(" Ethernet1/1", 90)
	for _, c := range []struct{ name, cmd string }{
		{"short", "show interfaces Ethernet1/1 status"},
		{"1KiB", long[:maxCommandLen]},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.cmd)))
			for b.Loop() {
				_, _ = classifyCommand(c.cmd)
			}
		})
	}
}

// TestCommandWidthIsCommandCap ties the overhead corpus's longest command
// (gatetest.CommandWidth, M1-39) to the classifier's maxCommandLen: the
// worst cases must be commands the classifier reads in full.
func TestCommandWidthIsCommandCap(t *testing.T) {
	if gatetest.CommandWidth != maxCommandLen {
		t.Errorf("gatetest.CommandWidth %d, maxCommandLen %d", gatetest.CommandWidth, maxCommandLen)
	}
}
