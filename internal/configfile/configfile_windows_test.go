// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
}

func sidName(t *testing.T, s string) string {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatal(err)
	}
	return account(sid)
}

// TestWindowsWriteACE: a file or directory that grants Everyone (S-1-1-0)
// write access is refused; read access for Everyone is fine.
func TestWindowsWriteACE(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	p := write(t, dir, "read.yaml", "version: 1\n")
	icacls(t, p, "/grant", "*S-1-1-0:(R)")
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("Everyone read: %v", err)
	}
	everyone := sidName(t, "S-1-1-0")
	for _, right := range []string{"(W)", "(M)", "(F)", "(D)", "(WDAC)"} {
		q := write(t, dir, "w"+strings.Trim(right, "()")+".yaml", "version: 1\n")
		icacls(t, q, "/grant", "*S-1-1-0:"+right)
		if _, err := Read(q, "the policy file", 1<<10); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "can be changed by "+everyone+";") {
			t.Errorf("Everyone %s: %v", right, err)
		}
	}
	sub := ownerOnlyDir(t, t.TempDir())
	icacls(t, sub, "/grant", "*S-1-1-0:(OI)(CI)(M)")
	err := CheckDir(sub, "the profiles directory")
	if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), `"%USERNAME%:(OI)(CI)F"`) {
		t.Errorf("writable directory: %v", err)
	}
}

// TestWindowsRefusalNamesEveryWriterAndFixes: one message names every
// account that can write, by name, gives a runnable icacls command with
// the real path and warns about the directory; running that command makes
// the file pass.
func TestWindowsRefusalNamesEveryWriterAndFixes(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	p := write(t, dir, "policy.yaml", "version: 1\n")
	icacls(t, p, "/grant", "*S-1-1-0:(M)", "*S-1-5-11:(W)")
	_, err := Read(p, "the policy file", 1<<10)
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("not refused: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		sidName(t, "S-1-1-0"), sidName(t, "S-1-5-11"),
		`icacls "` + p + `" /inheritance:r /grant:r "%USERNAME%:F" SYSTEM:F Administrators:F && icacls "` + p + `" /remove:g *S-1-`,
		"can still replace it", "run in Command Prompt", `C:\ProgramData\fathomgate`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	fix := regexp.MustCompile(`icacls "[^"]+" /inheritance:r /grant:r "%USERNAME%:F" SYSTEM:F Administrators:F && icacls "[^"]+" /remove:g( \*S-[0-9-]+)+`).FindString(msg)
	// As typed at a Command Prompt: the raw command line, so cmd expands
	// %USERNAME% and sees the quotes as written.
	run := exec.Command("cmd")
	run.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd /c " + fix}
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", fix, err, out)
	}
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("after the printed fix: %v", err)
	}
}
