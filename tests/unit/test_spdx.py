# SPDX-License-Identifier: FSL-1.1-ALv2
"""tools/licences/spdx.py applies the per-path licence rule of ADR 0034."""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

SPDX = pathlib.Path(__file__).resolve().parents[2] / "tools" / "licences" / "spdx.py"


@pytest.fixture(scope="module")
def spdx():
    spec = importlib.util.spec_from_file_location("spdx_check", SPDX)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.tier1
@pytest.mark.parametrize(
    "rel, want",
    [
        ("internal/policy/evaluate.go", "FSL-1.1-ALv2"),
        ("cmd/fathomgate/main.go", "FSL-1.1-ALv2"),
        ("tools/licences/spdx.py", "FSL-1.1-ALv2"),
        ("tools/policy-lint/policy-lint", "FSL-1.1-ALv2"),
        ("policies/examples/helper.py", "Apache-2.0"),
        ("profiles/gen.sh", "Apache-2.0"),
        # A prefix match on the directory, not on the name.
        ("policies/example.py", "FSL-1.1-ALv2"),
        ("profilesx/gen.sh", "FSL-1.1-ALv2"),
        ("tests/profiles/x.py", "FSL-1.1-ALv2"),
    ],
)
def test_licence_for(spdx, rel, want):
    assert spdx.licence_for(rel) == want


@pytest.mark.tier1
def test_exceptions_win(spdx, monkeypatch):
    monkeypatch.setattr(spdx, "EXCEPTIONS", {"internal/x/copied.go": "MIT"})
    assert spdx.licence_for("internal/x/copied.go") == "MIT"


@pytest.mark.tier1
def test_state(spdx):
    fsl = "FSL-1.1-ALv2"
    assert spdx.state(["// SPDX-License-Identifier: FSL-1.1-ALv2", "", "package x"], "go", fsl) == "ok"
    assert spdx.state(["// SPDX-License-Identifier: Apache-2.0", "", "package x"], "go", fsl) == "wrong"
    assert spdx.state(["package x"], "go", fsl) == "missing"
    assert spdx.state([], "go", fsl) == "missing"
    assert spdx.state(["#!/bin/sh", "# SPDX-License-Identifier: FSL-1.1-ALv2"], "sh", fsl) == "ok"
    assert spdx.state(["#!/bin/sh", "# SPDX-License-Identifier: Apache-2.0"], "sh", fsl) == "wrong"
    assert spdx.state(["#!/bin/sh"], "sh", fsl) == "missing"
    # Under an Apache-2.0 path the Apache line is the right one.
    assert spdx.state(["# SPDX-License-Identifier: Apache-2.0"], "py", "Apache-2.0") == "ok"
    assert spdx.state(["# SPDX-License-Identifier: FSL-1.1-ALv2"], "py", "Apache-2.0") == "wrong"


@pytest.mark.tier1
def test_fix_replaces_a_wrong_line(spdx):
    go = "// SPDX-License-Identifier: Apache-2.0\n\npackage x\n"
    assert spdx.fix_header(go, "go", "FSL-1.1-ALv2") == "// SPDX-License-Identifier: FSL-1.1-ALv2\n\npackage x\n"
    sh = "#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\necho hi\n"
    assert spdx.fix_header(sh, "sh", "FSL-1.1-ALv2") == "#!/bin/sh\n# SPDX-License-Identifier: FSL-1.1-ALv2\necho hi\n"


@pytest.mark.tier1
def test_fix_adds_a_missing_line(spdx):
    assert spdx.fix_header("package x\n", "go", "FSL-1.1-ALv2") == "// SPDX-License-Identifier: FSL-1.1-ALv2\n\npackage x\n"
    assert spdx.fix_header("#!/usr/bin/env python3\nprint()\n", "py", "Apache-2.0") == (
        "#!/usr/bin/env python3\n# SPDX-License-Identifier: Apache-2.0\nprint()\n"
    )
    assert spdx.fix_header("print()\n", "py", "FSL-1.1-ALv2") == "# SPDX-License-Identifier: FSL-1.1-ALv2\nprint()\n"
