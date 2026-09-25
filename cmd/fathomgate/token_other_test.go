// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package main

import (
	"strings"
	"testing"
)

// writeOwnerOnly skips the test: readTokenFile refuses every token file on
// platforms that are neither Unix nor Windows (token_other.go), so a test
// that needs one cannot run here. FATHOMGATE_LISTEN_TOKEN is the token
// source on these platforms; TestReadTokenFileOther covers both.
func writeOwnerOnly(t *testing.T, _ string, _ []byte) {
	t.Helper()
	t.Skip("token files are refused on this platform; FATHOMGATE_LISTEN_TOKEN is the token source here")
}

// makeShared is never reached: writeOwnerOnly skipped the test first.
func makeShared(t *testing.T, _ string) { t.Helper() }

func TestReadTokenFileOther(t *testing.T) {
	t.Parallel()
	if _, err := readTokenFile("any"); err == nil || !strings.Contains(err.Error(), "use FATHOMGATE_LISTEN_TOKEN") {
		t.Fatalf("error %v, want a refusal naming FATHOMGATE_LISTEN_TOKEN", err)
	}
	if _, err := loadListenTokens([]string{"alice=any"}, noEnv); err == nil {
		t.Fatal("a token file was accepted")
	}
	env := func(k string) (string, bool) { return testListenToken, k == listenTokenEnv }
	got, err := loadListenTokens(nil, env)
	if err != nil || string(got.byName[envPrincipal]) != testListenToken {
		t.Fatalf("FATHOMGATE_LISTEN_TOKEN: %v", err)
	}
}
