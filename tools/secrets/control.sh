#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Negative control for the secret scan (M1-42): .gitleaks.toml, tools/secrets/
# scan.py and .gitleaksignore.
#
#   tools/secrets/control.sh GITLEAKS CONFIG IGNORE [PYTHON]
#
# 1. IGNORE is checked line by line: every entry is a full commit fingerprint,
#    <40-hex commit>:<file>:<rule-id>:<line>. A path, rule or commit on its
#    own (which would silence far more than one judged finding) fails.
# 2. A throwaway repository gets redaction-fixture-shaped files under
#    tests/fixtures/ with FAKE and non-FAKE device secrets, an inline
#    `gitleaks:allow`, a finding on main listed in its own ignore file, a PR
#    branch that merges main twice (once with a line added in the merge, once
#    resolving a conflict with a secret), and then:
#    - `gitleaks dir` on the first commit, and scan.py over the full history
#      and over the PR range, must each report exactly the expected findings:
#      every non-FAKE secret (including one that contains FAKE but does not
#      start with it), the FAKE secret in a file the allow-list does not name,
#      the inline-allowed secret (--ignore-gitleaks-allow), both merge
#      secrets, a second PEM block a merge adds to a file main already has a
#      (different) block in, and not the ignored main findings (a line and a
#      PEM block), which the merges repeat in their first-parent diffs;
#    - scan.py with a base that is not a commit must exit 2;
#    - scan.py with a stub gitleaks that scans 0 commits and exits 0 must
#      exit 2.
# A config change that widens the allow-list, drops a network-config rule,
# makes the allow-list global (then `gitleaks dir` skips the fixture file
# whole), or a scan.py change that loses merges, honours inline allows or
# passes a bad range, fails here.
#
# Every value below is made up for this control; none was ever a credential.
set -eu

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
	echo "usage: $0 GITLEAKS CONFIG IGNORE [PYTHON]" >&2
	exit 2
fi
abs() { case $1 in /*) echo "$1" ;; *) echo "$(pwd)/$1" ;; esac; }
gitleaks=$(abs "$1")
config=$(abs "$2")
ignore=$(abs "$3")
python=${4:-python3}
scan=$(cd "$(dirname "$0")" && pwd)/scan.py

failed=0
bad() {
	echo "control: FAIL: $*"
	failed=1
}

# 1. The ignore file's format.
n=0
while IFS= read -r line || [ -n "$line" ]; do
	n=$((n + 1))
	# A file checked out with CRLF line ends must not fail (or pass) on the \r.
	line=$(printf '%s' "$line" | tr -d '\r')
	case $line in '' | '#'*) continue ;; esac
	if ! printf '%s\n' "$line" | grep -Eq '^[0-9a-f]{40}:[^:]+:[a-z0-9-]+:[0-9]+$'; then
		bad "$3 line $n is not <40-hex commit>:<file>:<rule-id>:<line>: $line"
	fi
done < "$ignore"
[ "$failed" -eq 0 ] && echo "control: $3 entries are all full commit fingerprints"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo=$tmp/repo
mkdir -p "$repo/tests/fixtures/configs" "$repo/tests/fixtures/device"
g() { git -C "$repo" -c user.name=control -c user.email=control@invalid -c commit.gpgsign=false "$@"; }

# Allowed: FAKE first, or first after the vendor's fixed encoding marker.
# Found: everything else, and line 11 despite its inline allow.
cat > "$repo/tests/fixtures/configs/control.txt" <<'EOF'
enable secret 9 $9$FAKEcontrolAbCdEf0123456
enable secret 9 $9$controlAbCdEf0123456789
snmp-server community FAKEcontrolRo ro
snmp-server community NOTFAKEcontrol ro
username ops password 7 FAKEcontrolType7
username ops password 7 controlType7Abc
        set password ENC FAKEcontrolAbCdEfGhIjKlMn==
        set psksecret ENC controlAbCdEfGhIjKlMnOpQr==
set shared radius-server secret -AQ==FAKEcontrolAbCd
set shared tacplus-server secret -AQ==controlAbCdEfGh
snmp-server community controlInline ro ! gitleaks:allow
EOF
# Same FAKE value in a file the allow-list does not name: found.
cat > "$repo/tests/fixtures/device/control.md" <<'EOF'
snmp-server community FAKEcontrolRo ro
EOF
printf 'hostname control\n' > "$repo/tests/fixtures/configs/a.txt"
git init -q -b main "$repo"
g add -A
g commit -q -m c1

first=$tmp/first.expected
cat > "$first" <<'EOF'
netdev-crypt-hash tests/fixtures/configs/control.txt 2
netdev-fortios-enc tests/fixtures/configs/control.txt 8
netdev-panos-encrypted tests/fixtures/configs/control.txt 10
netdev-snmp-community tests/fixtures/configs/control.txt 11
netdev-snmp-community tests/fixtures/configs/control.txt 4
netdev-snmp-community tests/fixtures/device/control.md 1
netdev-type0-type7 tests/fixtures/configs/control.txt 6
EOF

compare() { # name expected got
	if sort "$2" | cmp -s - "$3"; then
		echo "control: $1 found exactly the $(wc -l < "$2" | tr -d ' ') expected findings"
	else
		bad "$1 findings differ from the expected set (< expected, > got):"
		sort "$2" | diff - "$3" || true
	fi
}

# 2a. gitleaks dir on the first commit's tree, with the scan's flags.
set +e
(cd "$repo" && "$gitleaks" dir --config "$config" --ignore-gitleaks-allow --no-banner --log-level error \
	--report-format csv --report-path "$tmp/dir.csv" --exit-code 1 .)
rc=$?
set -e
if [ "$rc" -ne 1 ]; then
	bad "gitleaks dir exited $rc, want 1 (findings)"
else
	# Picks RuleID, File and StartLine by header name. Splitting on commas is
	# safe only because no control value, file name or matched text here
	# contains a comma or a quote; do not reuse this on real reports.
	awk -F, 'NR == 1 { for (i = 1; i <= NF; i++) c[$i] = i; next }
		{ print $c["RuleID"], $c["File"], $c["StartLine"] }' "$tmp/dir.csv" | sort > "$tmp/dir.got"
	compare "gitleaks dir" "$first" "$tmp/dir.got"
fi

# Findings on main, judged and listed by fingerprint in the repo's ignore
# file: one line, and one multi-line PEM block. Key bodies are random bytes
# made here, never committed; they are not keys. Each block is 4 lines.
pem() {
	printf '%s\n' '-----BEGIN PRIVATE KEY-----'
	head -c 96 /dev/urandom | base64 | tr -d '\n' | fold -w 64
	printf '\n%s\n' '-----END PRIVATE KEY-----'
}
mkdir -p "$repo/keys"
printf 'snmp-server community ignoredOnMain ro\n' > "$repo/tests/fixtures/configs/ignored.txt"
pem > "$repo/keys/control.pem"
g add -A
g commit -q -m c2
c2=$(git -C "$repo" rev-parse HEAD)
{
	printf '%s:tests/fixtures/configs/ignored.txt:netdev-snmp-community:1\n' "$c2"
	printf '%s:keys/control.pem:private-key:1\n' "$c2"
} > "$tmp/ignore"

# The PR branch starts before c2, then merges main with a line added in the
# merge commit (a clean merge git would not have made on its own).
g checkout -q -b pr HEAD~1
printf 'hostname pr\n' > "$repo/tests/fixtures/configs/b.txt"
g add -A
g commit -q -m p1
g merge -q --no-commit main
printf 'snmp-server community evilCleanMerge ro\n' > "$repo/tests/fixtures/configs/evil.txt"
# A different key appended in the merge to the file main added: its BEGIN
# line equals main's, so only a whole-block comparison tells them apart.
pem >> "$repo/keys/control.pem"
g add -A
g commit -q -m "merge main, plus a line and a key"
# Main and the PR change the same line; the resolution adds a secret.
g checkout -q main
printf 'hostname main-side\n' > "$repo/tests/fixtures/configs/a.txt"
g commit -q -am c3
g checkout -q pr
printf 'hostname pr-side\n' > "$repo/tests/fixtures/configs/a.txt"
g commit -q -am p2
g merge -q main >/dev/null 2>&1 || true
printf 'hostname control\nsnmp-server community evilConflict ro\n' > "$repo/tests/fixtures/configs/a.txt"
g add -A
g commit -q -m "merge main, conflict resolved"

merges=$tmp/merges.expected
cat > "$merges" <<'EOF'
netdev-snmp-community tests/fixtures/configs/a.txt 2
netdev-snmp-community tests/fixtures/configs/evil.txt 1
private-key keys/control.pem 5
EOF
cat "$first" "$merges" > "$tmp/full.expected"

scan_case() { # name want-exit csv [scan.py args...]
	name=$1
	want=$2
	csv=$3
	shift 3
	set +e
	(cd "$repo" && "$python" "$scan" --gitleaks "$gitleaks" --config "$config" --report-csv "$csv" "$@") \
		> "$tmp/scan.log" 2>&1
	rc=$?
	set -e
	if [ "$rc" -ne "$want" ]; then
		bad "$name: scan.py exited $rc, want $want"
		sed 's/^/    /' "$tmp/scan.log"
		return 1
	fi
	echo "control: $name: scan.py exited $rc as expected"
}
csv_got() { # scan.py's own CSV: RuleID,File,StartLine,Commit; no commas in the control values
	tail -n +2 "$1" | awk -F, '{ print $1, $2, $3 }' | sort
}

# 2b. Full history of the PR branch.
if scan_case "full history" 1 "$tmp/full.csv" --ignore "$tmp/ignore" --head pr; then
	csv_got "$tmp/full.csv" > "$tmp/full.got"
	compare "scan.py full history" "$tmp/full.expected" "$tmp/full.got"
fi
# 2c. The PR range, as CI runs it.
if scan_case "PR range" 1 "$tmp/pr.csv" --ignore "$tmp/ignore" --base main --head pr; then
	csv_got "$tmp/pr.csv" > "$tmp/pr.got"
	compare "scan.py PR range" "$merges" "$tmp/pr.got"
fi
# 2d. A base that is not a commit here.
scan_case "unknown base" 2 "$tmp/x.csv" --ignore "$tmp/ignore" \
	--base 0123456789abcdef0123456789abcdef01234567 --head pr || true
# 2e. A gitleaks that scans nothing and says all is well.
stub=$tmp/stub-gitleaks
printf '#!/bin/sh\necho "INF 0 commits scanned." >&2\necho "INF no leaks found" >&2\nexit 0\n' > "$stub"
chmod +x "$stub"
gitleaks_real=$gitleaks
gitleaks=$stub
scan_case "0 commits scanned" 2 "$tmp/x.csv" --ignore "$tmp/ignore" --base main --head pr || true
gitleaks=$gitleaks_real

exit "$failed"
