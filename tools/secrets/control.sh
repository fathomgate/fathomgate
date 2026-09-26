#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Negative control for .gitleaks.toml (M1-42): prove that the FAKE allow-list
# lets FAKE-prefixed fixture secrets through and nothing else.
#
#   tools/secrets/control.sh GITLEAKS CONFIG
#
# It writes a throwaway repository with one redaction-fixture-shaped file under
# tests/fixtures/configs/ holding FAKE and non-FAKE device secrets, plus a FAKE
# secret in a tests/fixtures/ file the allow-list does not name. It scans it
# with `gitleaks git` (what `make secrets-scan` and CI run) and with
# `gitleaks dir` (a working-tree scan), and exits 0 only if each mode reports
# exactly the expected findings: every non-FAKE secret (including one that
# contains FAKE but does not start with it) and the FAKE secret outside the
# named files, and no FAKE secret in the named file. A config change that
# widens the allow-list, drops a network-config rule, or lets `gitleaks dir`
# skip the fixture file whole (a global allow-list with paths does) fails here.
#
# Every value below is made up for this control; none was ever a credential.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 GITLEAKS CONFIG" >&2
	exit 2
fi
gitleaks=$1
config=$2
case $gitleaks in /*) ;; *) gitleaks=$(pwd)/$gitleaks ;; esac
case $config in /*) ;; *) config=$(pwd)/$config ;; esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo=$tmp/repo
mkdir -p "$repo/tests/fixtures/configs" "$repo/tests/fixtures/device"

# Allowed: FAKE first, or first after the vendor's fixed encoding marker.
# Found: everything else.
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
EOF
# Same FAKE value in a file the allow-list does not name: found.
cat > "$repo/tests/fixtures/device/control.md" <<'EOF'
snmp-server community FAKEcontrolRo ro
EOF

expected=$tmp/expected
cat > "$expected" <<'EOF'
netdev-crypt-hash tests/fixtures/configs/control.txt $9$controlAbCdEf0123456789
netdev-fortios-enc tests/fixtures/configs/control.txt controlAbCdEfGhIjKlMnOpQr==
netdev-panos-encrypted tests/fixtures/configs/control.txt -AQ==controlAbCdEfGh
netdev-snmp-community tests/fixtures/configs/control.txt NOTFAKEcontrol
netdev-snmp-community tests/fixtures/device/control.md FAKEcontrolRo
netdev-type0-type7 tests/fixtures/configs/control.txt controlType7Abc
EOF

git init -q "$repo"
git -C "$repo" add -A
git -C "$repo" -c user.name=control -c user.email=control@invalid -c commit.gpgsign=false \
	commit -q -m control

failed=0
for mode in git dir; do
	report=$tmp/$mode.csv
	set +e
	(cd "$repo" && "$gitleaks" "$mode" --config "$config" --no-banner --log-level error \
		--report-format csv --report-path "$report" --exit-code 1 .)
	rc=$?
	set -e
	if [ "$rc" -ne 1 ]; then
		echo "control: gitleaks $mode exited $rc, want 1 (findings)"
		failed=1
		continue
	fi
	# CSV columns: RuleID, Commit, File, SymlinkFile, Secret, ...
	tail -n +2 "$report" | awk -F, '{ print $1, $3, $5 }' | tr -d '"' | sort > "$tmp/$mode.got"
	if sort "$expected" | cmp -s - "$tmp/$mode.got"; then
		echo "control: gitleaks $mode found exactly the $(wc -l < "$expected" | tr -d ' ') expected findings"
	else
		echo "control: gitleaks $mode findings differ from the expected set (< expected, > got):"
		sort "$expected" | diff - "$tmp/$mode.got" || true
		failed=1
	fi
done
exit "$failed"
