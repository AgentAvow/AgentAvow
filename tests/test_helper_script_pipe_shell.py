"""A shell helper script the user runs by hand (data/, scripts/, examples/, docs/) that
pipes a remote script to bash is Review (high), not Do not connect, while nothing in
the package runs it. Design review 2026-11-10 (the ultralytics get_imagenet.sh row).

Attack twins: the same line in a postinstall; a helper the package's runtime calls; a
helper named in package.json scripts (install / prepare); a helper another helper runs;
a helper the tree check cannot see.
"""
from __future__ import annotations

import pytest

from src.scanner import npm_scripts, pipe_shell
from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.scan import ScanResult, _calculate_trust_score, apply_artifact_scan

LINE = ("wget -qO- https://raw.githubusercontent.com/soumith/imagenetloader.torch/"
        "master/valprep.sh | bash # move into subdirs\n")
SCRIPT = f"#!/bin/bash\nmkdir val && cd val\n{LINE}"


def _pkg(files: dict[str, str], eco: str = "pypi") -> ScanResult:
    fetched = ArtifactFetchResult(
        ecosystem=eco, name="p", version="1", kind="tarball" if eco == "npm" else "wheel",
        ok=True, files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo=f"{eco}:p", stars=0, description="", framework="")
    apply_artifact_scan(r, eco, fetched)
    r.trust_score = _calculate_trust_score(r)
    return r


def _sev(r: ScanResult, path: str) -> set[str]:
    return {f.severity for f in r.findings
            if f.name == pipe_shell.PIPE_TO_SHELL and f.file_path == path}


@pytest.mark.parametrize("path", [
    "pkg/data/scripts/get_imagenet.sh",
    "pkg/scripts/fetch_weights.sh",
    "examples/setup_env.sh",
    "docs/tools/build.bash",
    "pkg/data/get.ps1",
])
def test_hand_run_helper_is_high(path):
    r = _pkg({path: SCRIPT, "pkg/__init__.py": "VERSION = '1'\n"})
    assert _sev(r, path) == {"high"}
    f = next(f for f in r.findings if f.file_path == path)
    assert f.remediation == npm_scripts.HELPER_SCRIPT_WHY


def test_runtime_subprocess_call_restores_critical():
    # ultralytics/data/utils.py:892, 8.4.209
    path = "ultralytics/data/scripts/get_imagenet.sh"
    runtime = ("import subprocess\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
               "def check(ds):\n    if ds == 'imagenet':\n"
               "        subprocess.run(['bash', str(ROOT / 'data/scripts/get_imagenet.sh')],"
               " check=True)\n")
    r = _pkg({path: SCRIPT, "ultralytics/data/utils.py": runtime})
    assert _sev(r, path) == {"critical"}


def test_runtime_os_system_by_file_name_restores_critical():
    path = "pkg/scripts/fetch.sh"
    runtime = "import os\n\ndef f():\n    os.system('sh ' + HERE + '/fetch.sh')\n"
    r = _pkg({path: SCRIPT, "pkg/run.py": runtime})
    assert _sev(r, path) == {"critical"}


@pytest.mark.parametrize("script", ["install", "postinstall", "preinstall", "prepare",
                                    "test"])
def test_named_in_package_json_scripts_restores_critical(script):
    path = "scripts/fetch.sh"
    pkg = '{"name":"p","scripts":{"' + script + '":"bash scripts/fetch.sh"}}'
    r = _pkg({path: SCRIPT, "package.json": pkg}, eco="npm")
    assert _sev(r, path) == {"critical"}


def test_named_as_bin_restores_critical():
    path = "scripts/fetch.sh"
    pkg = '{"name":"p","bin":{"p":"scripts/fetch.sh"}}'
    r = _pkg({path: SCRIPT, "package.json": pkg}, eco="npm")
    assert _sev(r, path) == {"critical"}


def test_another_helper_running_it_restores_critical():
    path = "scripts/inner.sh"
    r = _pkg({path: SCRIPT, "scripts/outer.sh": "#!/bin/sh\n. ./inner.sh\n"})
    assert _sev(r, path) == {"critical"}


def test_same_line_in_postinstall_stays_critical():
    pkg = '{"name":"p","scripts":{"postinstall":"' + LINE.split(" #")[0] + '"}}'
    r = _pkg({"package.json": pkg}, eco="npm")
    assert "critical" in {f.severity for f in r.findings
                          if f.name == pipe_shell.PIPE_TO_SHELL}


@pytest.mark.parametrize("path", [
    "pkg/data/fetch.py",        # not a shell script: runtime-importable code
    "pkg/lib/fetch.sh",         # not a helper dir
    "fetch.sh",                 # root-level
])
def test_outside_the_helper_shape_stays_critical(path):
    r = _pkg({path: SCRIPT if path.endswith(".sh") else
              f"import os\nos.system({LINE.strip()!r})\n"})
    assert "critical" in _sev(r, path), _sev(r, path)


def test_unseen_file_restores_critical():
    from src.scanner.scan import Finding
    f = Finding(category="dynamic_remote_load", name=pipe_shell.PIPE_TO_SHELL,
                severity="high", file_path="scripts/x.sh", line_number=1, snippet="")
    f.remediation = npm_scripts.HELPER_SCRIPT_WHY
    f._helper_restore = "critical"
    npm_scripts._restore_helper_scripts([f], {})
    assert f.severity == "critical"
