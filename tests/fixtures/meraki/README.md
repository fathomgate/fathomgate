# Meraki `execute_api` fixture (test-matrix row 18)

The tier 1 fixture for meta-tool classification (board task M1-17). It is
data taken from the official Cisco Meraki MCP server's own code, so the Go
tests can hold `profiles/cisco-meraki-mcp-official.yaml` to what the upstream
exposes without running it.

| File | What it is |
| --- | --- |
| `tools-list.json` | The upstream's `tools/list`: each tool's name, `inputSchema` and annotations, taken through FastMCP's in-memory client from `CiscoMerakiMCP.register_core_capabilities()`. No transport, no API key. |
| `capabilities.tsv` | Every capability id the upstream's `execute_api` can look up: the key set of its capability store, `load_meraki_endpoints()` over the bundled `specs/meraki.json.gz`, which is the non-deprecated GET operations of the spec. Columns: capability id, the spec's category tag (`configure`, `monitor` or `liveTools`), the number of required path or query parameters, the path. |
| `generate.py` | Writes both files. Run it inside the upstream checkout. |

Upstream: <https://github.com/CiscoDevNet/cisco-meraki-mcp-official> at
commit `c1d00eaf8f4455ccb6bf5ffdc0189fe0f40b1a5b` (2026-07-28, "Initial public
release", package version 0.1.0, Apache-2.0). The bundled spec is Meraki
Dashboard API 1.70.0; `specs/meraki.json.gz` has sha256
`23292fc813e6878c346f8bc7ac5248e78295bab2ef247d545a27b85c9f653631`, and the
decompressed JSON
`825276cf08ade49202beb97c446725e48601a599082135e384edb2e6a0de8a64` (as the
upstream's `specs/meraki.json.sha256` records). The capability ids are the
Meraki API's operation ids; nothing here is a credential.

To regenerate for a new upstream version:

```sh
git clone https://github.com/CiscoDevNet/cisco-meraki-mcp-official meraki
cd meraki && git checkout <commit>
uv sync --frozen --no-dev
uv run --frozen --no-dev python <fathomgate>/tests/fixtures/meraki/generate.py <fathomgate>/tests/fixtures/meraki
```

Then update the commit and hashes here and in the profile header, and run
`go test ./internal/classify/`. `TestMerakiCapabilityTable` fails for every
new capability id until the profile's `dashboard` table has a row for it, and
`TestMerakiToolsListFixture` fails for every new argument until the profile
names or refuses it.

Tests that read this fixture: `internal/classify/capability_test.go`
(`TestMerakiCapabilityTable`, `TestMerakiToolsListFixture`, `TestMatrixRow18`).
The fixture proves the classification against the upstream's source. It is
not a run against a live Meraki server, and it does not make row 18
validated against one.
