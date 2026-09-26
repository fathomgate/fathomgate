# SPDX-License-Identifier: FSL-1.1-ALv2
"""Regenerate the Meraki execute_api fixture from the upstream's own code.

Run from a checkout of https://github.com/CiscoDevNet/cisco-meraki-mcp-official
at the commit named in README.md, after `uv sync --frozen --no-dev`:

    uv run --frozen --no-dev python <fathomgate>/tests/fixtures/meraki/generate.py <fathomgate>/tests/fixtures/meraki

It writes two files:

- capabilities.tsv: every capability the upstream's execute_api can look up.
  That is the store's key set: load_meraki_endpoints() over the bundled
  specs/meraki.json.gz, the same call initialize_vector_store() makes, so the
  rows are the non-deprecated GET operations of the spec. Columns:
  capability_id, the spec's category tag (configure, monitor or liveTools),
  the number of required path or query parameters, and the path.
- tools-list.json: the upstream's tools/list, taken through FastMCP's
  in-memory client from CiscoMerakiMCP.register_core_capabilities(), with
  each tool's inputSchema and annotations.

Nothing here reaches the Meraki API or needs a key: tools/list does not wait
for the vector index, and the endpoint list is read from the bundled file.
"""

import asyncio
import json
import sys
from pathlib import Path

from fastmcp import Client

from cisco_meraki_mcp.cisco_meraki_mcp import CiscoMerakiMCP
from cisco_meraki_mcp.index_state import IndexState
from cisco_meraki_mcp.main import bundled_spec_path
from cisco_meraki_mcp.providers.openapi import load_meraki_endpoints

CATEGORIES = ("configure", "monitor", "liveTools")


def category(tags: list[str]) -> str:
    found = [t for t in tags if t in CATEGORIES]
    if len(found) != 1:
        raise SystemExit(f"expected one category tag, got {tags}")
    return found[0]


def capabilities(out: Path) -> None:
    rows = []
    for ep in load_meraki_endpoints(bundled_spec_path()):
        required = sum(1 for p in ep.parameters if p.required)
        rows.append((ep.operation_id, category(ep.tags), str(required), ep.path))
    rows.sort()
    ids = [r[0] for r in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate capability id")
    with (out / "capabilities.tsv").open("w", encoding="utf-8", newline="\n") as f:
        f.write("# capability_id\tcategory\trequired_params\tpath\n")
        for r in rows:
            f.write("\t".join(r) + "\n")


async def tools_list(out: Path) -> None:
    app = CiscoMerakiMCP("cisco-meraki-mcp")
    app.register_core_capabilities(IndexState(), runtime_transport="stdio")
    async with Client(app) as c:
        tools = await c.list_tools()
    doc = {
        "tools": [
            {
                "name": t.name,
                "inputSchema": t.inputSchema,
                "annotations": t.annotations.model_dump(exclude_none=True) if t.annotations else None,
            }
            for t in sorted(tools, key=lambda t: t.name)
        ]
    }
    with (out / "tools-list.json").open("w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def main() -> None:
    out = Path(sys.argv[1])
    capabilities(out)
    asyncio.run(tools_list(out))


if __name__ == "__main__":
    main()
