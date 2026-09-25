// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
)

func TestValidTargetName(t *testing.T) {
	t.Parallel()
	good := []string{
		"core-rtr-01", "lab-sw-01", "CORE-RTR-01", "core_rtr_01", "a",
		"core-rtr-01.dfw1.example.net", "10.0.0.1", "192.168.255.254",
		"2001:db8::1", "::1", "::ffff:10.0.0.1", "fe80::1",
		"x1", "host.a1", "cafe", "0xg", "nullable", "true-sw-01", "null.example", "e5",
		strings.Repeat("a", 63) + ".example",
	}
	bad := []string{
		"", " ", "core-rtr-01 ", " core-rtr-01", "core rtr", "core-rtr-01\t",
		"core-rtr-01\n", "core-rtr-01\r", "core-rtr-01\x00", "core-rtr-01\x7f",
		"lab-x@core-rtr-01", "@core", "user@10.0.0.1",
		"core-rtr-01,lab-sw-01", "core-rtr-01;reboot", "core-rtr-01/32", "core-rtr-01%eth0",
		"core-rtr-01:22", "10.0.0.1:22", "[::1]", "fe80::1%eth0", ":::", "1:2",
		"-oProxyCommand=sh", "core.-x", ".core", "core.", "core..rtr",
		"null", "true", "false", "NaN", "Infinity", "1e5", "1E+5", "2.5e-3", "0.5", `["core-rtr-01"]`, "[]", "{}",
		"0x", "127.1", "2130706433", "0x7f000001", "0x7f.0.0.1", "010.0.0.1", "10.0.0.256", "1.2.3.4.5", "host.123",
		"сore-rtr-01", "core-rtr-01\u200b", "core-rtr-\uff101", "core\u00a0rtr",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "ab",
		"$(reboot)", "`id`", "a|b", "a'b", `a"b`, "a\\b", "a*b", "a?b", "~root",
	}
	for _, s := range good {
		if !validTargetName(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range bad {
		if validTargetName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestTargetsExtraction(t *testing.T) {
	t.Parallel()
	spec := classify.ToolSpec{TargetParams: []string{"host"}, TargetsParams: []string{"hosts"}, GroupParams: []string{"tags"}}
	cases := []struct {
		name    string
		args    map[string]any
		names   []string
		groups  bool
		problem targetProblem
	}{
		{"none", map[string]any{}, nil, false, targetsOK},
		{"single", map[string]any{"host": "r1"}, []string{"r1"}, false, targetsOK},
		{"dedup exact", map[string]any{"host": "r1", "hosts": []any{"r1", "r2", "R1"}}, []string{"r1", "r2", "R1"}, false, targetsOK},
		{"csv", map[string]any{"hosts": "r1,r2"}, []string{"r1", "r2"}, false, targetsOK},
		{"csv untrimmed", map[string]any{"hosts": "r1, r2"}, nil, false, targetBadName},
		{"single with comma", map[string]any{"host": "r1,r2"}, nil, false, targetBadName},
		{"null", map[string]any{"host": nil, "hosts": nil, "tags": nil}, nil, false, targetsOK},
		{"empty list and string", map[string]any{"hosts": []any{}, "tags": ""}, nil, false, targetsOK},
		{"group", map[string]any{"host": "r1", "tags": []any{"core"}}, []string{"r1"}, true, targetsOK},
		{"group object", map[string]any{"tags": map[string]any{}}, nil, true, targetsOK},
		{"host number", map[string]any{"host": 1.0}, nil, false, targetBadName},
		{"host bool", map[string]any{"host": true}, nil, false, targetBadName},
		{"hosts nested", map[string]any{"hosts": []any{[]any{"r1"}}}, nil, false, targetBadName},
	}
	for _, tc := range cases {
		names, groups, problem := targets(spec, tc.args)
		if !reflect.DeepEqual(names, tc.names) || groups != tc.groups || problem != tc.problem {
			t.Errorf("%s: %q %v %v, want %q %v %v", tc.name, names, groups, problem, tc.names, tc.groups, tc.problem)
		}
	}
}

func FuzzValidTargetName(f *testing.F) {
	for _, s := range []string{"core-rtr-01", "10.0.0.1", "::1", "lab-x@core", "127.1", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !validTargetName(s) {
			return
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c <= ' ' || c >= 0x7f || strings.IndexByte("@,;/%[]\"'`$|\\", c) >= 0 {
				t.Fatalf("%q accepted with byte %#x", s, c)
			}
		}
		if s[0] == '-' {
			t.Fatalf("%q accepted with a leading dash", s)
		}
	})
}
