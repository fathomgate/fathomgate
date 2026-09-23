# Redaction fixture corpus

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
   `FAKE` or is a hash-shaped string containing `FAKE`. Nothing in this
   directory was ever a real credential.
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
