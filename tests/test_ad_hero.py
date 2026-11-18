"""The X ad hero shows only when the page URL carries the ad's tag.

web/public/ad-hero.js (before first paint) and isWalletKeyAd in
web/src/rebrand/lib/adLanding.ts (the app) decide whether the homepage opens on the
wallet-key ad hero. Both read the page URL only: a tag stored for the tab (sessionStorage
ag_utm) must not keep the ad hero on the plain homepage after one ad visit. Attribution
still falls back to the stored tags (adTags, setupUrl), so a later install counts.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
AD_HERO_JS = ROOT / "web/public/ad-hero.js"
AD_LANDING_TS = ROOT / "web/src/rebrand/lib/adLanding.ts"
TYPESCRIPT = ROOT / "web/node_modules/typescript"
NODE = shutil.which("node")

needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")

# Runs public/ad-hero.js in a sandbox with a fake location, sessionStorage and <html>,
# then prints whether it marked <html data-ad-hero>.
_HERO_RUNNER = r"""
const vm = require('vm')
const fs = require('fs')
const [file, pathname, search, stored] = process.argv.slice(1)
const attrs = {}
const ctx = {
  location: { pathname, search },
  URLSearchParams,
  JSON,
  sessionStorage: { getItem: (k) => (k === 'ag_utm' ? stored || null : null) },
  document: { documentElement: {
    setAttribute: (k, v) => { attrs[k] = v },
    removeAttribute: (k) => { delete attrs[k] },
  } },
  setTimeout: () => 0,
}
vm.runInNewContext(fs.readFileSync(file, 'utf8'), ctx)
process.stdout.write(JSON.stringify(attrs['data-ad-hero'] || null))
"""

# Transpiles lib/adLanding.ts with the repo's TypeScript and runs it with stubbed
# imports: getUtmParams returns the stored tags, rp leaves paths alone.
_LANDING_RUNNER = r"""
const fs = require('fs')
const [tsPath, file, search, stored] = process.argv.slice(1)
const ts = require(tsPath)
const out = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText
const stubs = {
  '../../lib/analytics': { getUtmParams: () => JSON.parse(stored || '{}') },
  '../basePath': { rp: (p) => p },
}
const mod = { exports: {} }
new Function('require', 'module', 'exports', out)((n) => stubs[n], mod, mod.exports)
const m = mod.exports
process.stdout.write(JSON.stringify({
  hero: m.isWalletKeyAd(search),
  tags: m.adTags(search),
  setup: m.setupUrl(search),
}))
"""


def _hero(pathname: str, search: str, stored: dict | None = None) -> str | None:
    out = subprocess.run(
        [NODE, "-e", _HERO_RUNNER, str(AD_HERO_JS), pathname, search,
         json.dumps(stored) if stored else ""],
        capture_output=True, text=True, check=True, timeout=30,
    )
    return json.loads(out.stdout)


def _landing(search: str, stored: dict | None = None) -> dict:
    out = subprocess.run(
        [NODE, "-e", _LANDING_RUNNER, str(TYPESCRIPT), str(AD_LANDING_TS), search,
         json.dumps(stored) if stored else ""],
        capture_output=True, text=True, check=True, timeout=60,
    )
    return json.loads(out.stdout)


STORED_X5 = {"utm_source": "x", "utm_campaign": "2026-11-test-x", "utm_content": "x5-wallet-home"}


@needs_node
@pytest.mark.parametrize("content", ["x5", "x3-do-not-connect", "x5-wallet-home", "X5"])
def test_ad_hero_js_marks_the_page_when_the_url_has_the_tag(content):
    assert _hero("/", f"?utm_source=x&utm_content={content}") == "wallet"


@needs_node
def test_ad_hero_js_ignores_a_stored_tag():
    # Came from the ad earlier in this tab, now on the plain homepage (the logo).
    assert _hero("/", "", STORED_X5) is None
    assert _hero("/", "?utm_content=", STORED_X5) is None


@needs_node
def test_ad_hero_js_leaves_other_tags_and_pages_alone():
    assert _hero("/", "?utm_content=g1-claude-code") is None
    assert _hero("/", "?utm_content=x55") is None
    assert _hero("/check", "?utm_content=x5") is None


def test_sources_read_the_url_only():
    """Always runs: neither check reads the stored tags."""
    hero_js = AD_HERO_JS.read_text()
    code = re.sub(r"(?m)^\s*//.*$", "", hero_js)
    assert "sessionStorage" not in code
    assert "ag_utm" not in code

    ts = AD_LANDING_TS.read_text()
    m = re.search(r"export function isWalletKeyAd\(search: string\): boolean \{(.*?)\n\}", ts, re.S)
    assert m, "isWalletKeyAd not found"
    body = m.group(1)
    assert "adTags" not in body and "getUtmParams" not in body
    assert "new URLSearchParams(search)" in body
    # Attribution keeps the stored-tag fallback.
    assert "getUtmParams()" in ts
    assert "adTags(search)" in ts.split("export function setupUrl", 1)[1]


needs_ts = pytest.mark.skipif(
    NODE is None or not TYPESCRIPT.exists(),
    reason="needs node and web/node_modules (npm ci in web/)",
)


@needs_ts
def test_is_wallet_key_ad_with_the_tag_in_the_url():
    got = _landing("?utm_source=x&utm_content=x5-wallet-home")
    assert got["hero"] is True
    assert got["tags"]["utm_content"] == "x5-wallet-home"


@needs_ts
def test_is_wallet_key_ad_ignores_a_stored_tag_but_attribution_keeps_it():
    got = _landing("", STORED_X5)
    assert got["hero"] is False
    # adTags and setupUrl still credit the ad.
    assert got["tags"] == STORED_X5
    assert "utm_content=x5-wallet-home" in got["setup"]
    assert "/rebrand/claude-code?" in got["setup"]
