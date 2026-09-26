# Redaction fixture corpus

(Other fixtures here: `device/` holds the fake devices tier 2 talks to, and
`meraki/` the Meraki `execute_api` classification fixture of test-matrix
row 18, with its own README.)

`configs/` holds one sanitised running-config excerpt per platform. Each is
run through `internal/redact` by `TestFixtureCorpus` (Go) and by
`make fixtures-check`.

| Fixture | Platform | Format |
| --- | --- | --- |
| `ios-xe.txt` | Cisco IOS-XE | `show running-config` |
| `nxos.txt` | Cisco NX-OS | `show running-config` |
| `eos.txt` | Arista EOS | `show running-config` |
| `junos.txt` | Juniper Junos | curly `show configuration` plus a `display set` tail |
| `panos.txt` | Palo Alto PAN-OS | `show config running format set` |
| `fortios.txt` | Fortinet FortiOS | `show full-configuration` |

## The annotated-secret convention

1. Every secret in a fixture is **fake** and visibly so: it starts with
   `FAKE`, or, for a hash or encrypted value, starts with `FAKE` right after
   the vendor's fixed marker (`$9$FAKE...`, `$1$FAKEsalt$...`, `-AQ==FAKE...`,
   `0xFAKE...`). Nothing in this directory was ever a real credential.
   `TestFixtureCorpus` enforces this (M1-42). Every listed secret must start
   with `FAKE` that way, and every value the redactor replaces must be
   listed, so an unlisted or non-FAKE secret in a shape the redactor knows
   fails `go test`. `TestTranscriptSecretsAreFake` checks the device
   transcripts the same way (no expect file: every redacted value must be a
   FAKE word of the transcript). The `gitleaks` CI job (`.gitleaks.toml`)
   checks five of those shapes again. A value that only contains `FAKE` further in fails
   both.
2. Every secret line carries a trailing comment naming the redaction rule id
   expected to catch it, in the platform's own comment syntax:
   `! cisco-password-type`, `## rule: junos-secret-data`, `# rule: panos-phash`.
   The comment is documentation; the test does not parse it.
3. The sibling `<name>.expect.json` is what the test parses:

   ```json
   { "platform": "eos", "rules": ["eos-secret-sha512", "..."], "secrets": ["FAKE...", "..."] }
   ```

   The test asserts that every listed rule fires at least once, that no rule
   outside the list fires (so a new false positive is noticed), that no
   listed secret string survives, that at least as many secrets were
   replaced as are listed, and that redacting the output again changes
   nothing.
4. Prose in header comments must not contain a redaction keyword followed by
   a token (write "credentials are FAKE", not "every secret is FAKE"), or the
   generic keyword rule will fire on the comment. That is a feature of the
   rule, not a bug of the fixture.

## Adding a case

When a bug report shows a secret format the redactor missed:

1. Add the line to the right fixture with a FAKE value and a rule annotation.
2. Add the FAKE value to `secrets` in the expect file.
3. If a new rule is needed, add it to `internal/redact/rules.go` and to
   `rules` in the expect file.
4. `go test ./internal/redact/` must fail before the rule and pass after.
