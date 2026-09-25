// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"strings"
	"testing"
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
