// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

func mySID(t *testing.T) string {
	t.Helper()
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return me.User.Sid.String()
}

// commands are the icacls lines a refusal prints, one per line, each
// indented by two spaces with nothing after it.
func commands(msg string) []string {
	var out []string
	for _, l := range strings.Split(msg, "\n") {
		if strings.HasPrefix(l, "  icacls ") {
			out = append(out, strings.TrimPrefix(l, "  "))
		}
	}
	return out
}

// runShell runs line as typed at a Command Prompt (cmd) or a PowerShell
// prompt (powershell), and fails the test if it fails.
func runShell(t *testing.T, shell, line string) {
	t.Helper()
	var c *exec.Cmd
	switch shell {
	case "cmd":
		c = exec.Command("cmd")
		c.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd /c " + line}
	default:
		c = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", line+"; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
	}
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%s: %s: %v\n%s", shell, line, err, out)
	}
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
	if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), `"*`+mySID(t)+`:(OI)(CI)F"`) {
		t.Errorf("writable directory: %v", err)
	}
}

// TestWindowsRefusalNamesEveryWriterAndFixes: explicit entries. One
// message names every account that can write, prints the grant command
// and, on its own line, the /remove:g command for those entries, and warns
// about the directory; the printed lines fix the file whether they are
// typed at a Command Prompt or in PowerShell.
func TestWindowsRefusalNamesEveryWriterAndFixes(t *testing.T) {
	for _, shell := range []string{"cmd", "powershell"} {
		t.Run(shell, func(t *testing.T) {
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
				"run these two commands:\n  icacls \"" + p + `" /inheritance:r /grant:r "*` + mySID(t) + `:F" "*S-1-5-18:F" "*S-1-5-32-544:F"` + "\n",
				"\n  icacls \"" + p + `" /remove:g "*S-1-`,
				"can still replace it", "keep these files", `C:\ProgramData\fathomgate`,
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("message lacks %q:\n%s", want, msg)
				}
			}
			lines := commands(msg)
			if len(lines) != 2 || !strings.Contains(lines[1], `"*S-1-1-0"`) || !strings.Contains(lines[1], `"*S-1-5-11"`) {
				t.Fatalf("commands %q in:\n%s", lines, msg)
			}
			for _, line := range lines {
				runShell(t, shell, line)
			}
			if _, err := Read(p, "the policy file", 1<<10); err != nil {
				t.Fatalf("after the printed fix: %v", err)
			}
		})
	}
}

// TestWindowsInheritedOnlyWriters: write access that the file only
// inherits (from its folder) is removed by /inheritance:r alone, so the
// refusal prints one command and no /remove:g step (security review of
// PR #172, L1: a /remove:g for an inherited or orphaned SID fails).
func TestWindowsInheritedOnlyWriters(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	icacls(t, dir, "/grant", "*S-1-1-0:(OI)(CI)(M)")
	p := write(t, dir, "policy.yaml", "version: 1\n")
	_, err := Read(p, "the policy file", 1<<10)
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("not refused: %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "/remove:g") || !strings.Contains(msg, "; run:\n  icacls \""+p+`" /inheritance:r`) {
		t.Fatalf("inherited-only writers:\n%s", msg)
	}
	lines := commands(msg)
	if len(lines) != 1 {
		t.Fatalf("commands %q in:\n%s", lines, msg)
	}
	runShell(t, "powershell", lines[0])
	if _, err := Read(p, "the policy file", 1<<10); err != nil {
		t.Fatalf("after the printed fix: %v", err)
	}
}

// TestWindowsNoCommandForUnsafePath: a path with a character a shell would
// change gets advice in prose, never a command (L2).
func TestWindowsNoCommandForUnsafePath(t *testing.T) {
	base := ownerOnlyDir(t, t.TempDir())
	for _, name := range []string{"100%done", "wow!"} {
		dir := filepath.Join(base, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := write(t, dir, "policy.yaml", "version: 1\n")
		icacls(t, p, "/grant", "*S-1-1-0:(M)")
		_, err := Read(p, "the policy file", 1<<10)
		if !errors.Is(err, ErrUnsafe) || strings.Contains(err.Error(), `icacls "`) || !strings.Contains(err.Error(), "no command is printed") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, s := range []string{`C:\a%b`, `C:\a!b`, "C:\\a\nb", `C:\a"b`, "C:\\a\x1bb"} {
		if safeForCommand(s) {
			t.Errorf("safeForCommand(%q) = true", s)
		}
	}
	if !safeForCommand(`C:\Users\you\.config\fathomgate\policy.yaml`) {
		t.Error("an ordinary path is not safe")
	}
}
