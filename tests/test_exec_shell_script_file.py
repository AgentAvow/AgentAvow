"""A POSIX shell given a script FILE (``["sh", <path>, *args]``) runs that file; no shell
string is evaluated. It reads like any binary run with runtime arguments, while
``sh -c <string>`` and shapes that cannot be told apart keep the shell rule."""
from __future__ import annotations

import pytest

from src.scanner.exec_classify import classify_python_exec
from src.scanner.scan import _scan_content


def _exec(call: str, untrusted_near: bool = False):
    return classify_python_exec(call, "run", untrusted_near=untrusted_near)


@pytest.mark.parametrize("call", [
    'subprocess.run(["sh", str(state / "launcher.sh")] + list(args), capture_output=True)',
    'subprocess.run(["bash", "scripts/setup.sh", name])',
    'subprocess.run(["sh", "-e", os.path.join(d, "run.sh"), x])',
    'subprocess.run(["bash", "--", (root / "ci" / "x.sh").resolve(), *rest])',
])
def test_shell_running_a_script_file_is_a_low_capability(call):
    v = _exec(call)
    assert (v.kind, v.severity) == ("capability", "low")
    assert "script file" in v.label and "no shell string" in v.label


def test_script_file_near_untrusted_input_is_medium():
    v = _exec('subprocess.run(["sh", str(d / "x.sh"), value])', untrusted_near=True)
    assert (v.kind, v.severity) == ("defect", "medium")


@pytest.mark.parametrize("call", [
    'subprocess.run(["sh", "-c", cmd])',
    'subprocess.run(["bash", "-ec", cmd])',
    'subprocess.run(["sh", flag, cmd])',
    'subprocess.run(["sh", "-s", x])',
    'subprocess.run(["sh", d / "-c", cmd])',
    'subprocess.run(["busybox", str(d / "x.sh"), x])',
])
def test_shell_string_shapes_stay_defects(call):
    v = _exec(call)
    assert v.kind == "defect" and v.severity in ("high", "critical")
    assert "script file" not in v.label


def test_scan_reports_script_file_wording():
    src = ('import subprocess\n\ndef run(state, *args):\n'
           '    return subprocess.run(["sh", str(state / "launcher.sh")] + list(args))\n')
    found, _, _ = _scan_content(src, "pkg/tests/test_install.py")
    hits = [f for f in found if f.name == "subprocess.run / Popen (Python)"]
    assert [f.severity for f in hits] == ["low"]
    assert "a shell string is evaluated" not in hits[0].remediation
