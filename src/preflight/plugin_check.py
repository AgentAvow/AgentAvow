"""Claude plugin-directory checks for a GitHub repo that holds a plugin bundle.

``evaluate_plugin`` is pure: it takes the repo's file list (path + size) and the text of
the few files it needs (``plugin.json``, ``.mcp.json``, ``hooks/hooks.json``, the README
and the scripts hooks run) and returns gates in the same shape as ``gates.py``.
``check_plugin_repo`` fetches those inputs from GitHub.

Rules come from the plugin pre-submission checklist
(claude.com/docs/plugins/pre-submission-checklist) unless a gate says ``basis:
observed``: since about 2026-11-05 the directory also refuses command hooks, local MCP
servers, mods and files outside a short list of types from organizations that aren't
Verified, and raises "Hook can approve tool calls or change their input". None of that
is in Anthropic's docs yet; those gates say so.
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex

from src.preflight.rules import cite

PASS, FAIL, WARN, UNKNOWN, NA = "pass", "fail", "warn", "unknown", "na"
BLOCKER, HOLD, WARNING = "blocker", "hold", "warning"

_DOC = ("claude_plugin_checklist",)
_OBS = ("claude_verified_only_report",)

MAX_FILES = 512
MAX_TEXT_BYTES = 256 * 1024
README_MIN_WORDS = 40
RESERVED_NAMES = frozenset({"claude", "anthropic", "official", "plugin", "mcp", "test"})
SYSTEM_FILES = frozenset({".ds_store", "thumbs.db", "desktop.ini"})
_NAME_RX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_IMAGE_FONT = frozenset({"png", "jpg", "jpeg", "gif", "webp", "svg", "ttf", "otf", "woff",
                         "woff2", "eot"})
# Binaries the documented validator holds for a reviewer ("such as an .ico, .pdf, or
# .zip file or a compiled executable").
_HELD_BINARY = frozenset({"ico", "pdf", "zip", "exe", "dll", "so", "dylib", "bin", "jar",
                          "wasm", "tar", "gz", "tgz", "7z", "rar", "class", "pyc", "node",
                          "mp4", "mov", "mp3", "wav", "o", "a"})
# Observed: the only file types accepted from organizations that aren't Verified.
_OBSERVED_ALLOWED = frozenset({"md", "markdown", "txt", "json", "yaml", "yml", "png", "jpg",
                               "jpeg", "gif", "webp", "ico"})
_TEXT_NAMES = frozenset({"license", "licence", "copying", "notice", "readme", "changelog",
                         "authors", "contributors"})
_PKG_SOURCE_CONFIG = frozenset({".npmrc", ".yarnrc", ".yarnrc.yml", "bunfig.toml", "uv.toml",
                                "pip.conf", "pip.ini", ".pypirc", "pnpm-workspace.yaml"})
_LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "bun.lock", "bun.lockb"})
_COMPONENT_KEYS = ("commands", "agents", "skills", "hooks", "mcpServers", "outputStyles",
                   "lspServers")
_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$")
_VAR = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_INLINE_PROGRAM = re.compile(
    r"(?:^|\s)(?:python3?|node|deno|bun|bash|sh|zsh|ruby|perl|pwsh|powershell)\s+"
    r"(?:-c|-e|--eval|-Command)\b")
_SECRET_HEADER = re.compile(r"authorization|api[-_]?key|token|secret|password", re.I)
_APPROVES = re.compile(
    r"permissionDecision\W{0,4}\s*[:=]\s*\W{0,2}allow|updatedInput|"
    r"[\"']behavior[\"']\s*:\s*[\"']allow|[\"']decision[\"']\s*:\s*[\"']approve", re.I)
_SKILL_MD = re.compile(r"(?:^|/)skills/[^/]+/SKILL\.md$")
_WIN_DEVICE = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.[^/]*)?$", re.I)
_FOLDER_CHARS = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_REPO_ENTRIES = 10_000
MAX_PLUGIN_FILE = 5 * 1024 * 1024


def layout_problems(paths: list[str], folder: str) -> list[str]:
    """What makes the portal answer "Couldn’t validate that repository" or "Repository
    too large to validate", from the file list alone (``.gitattributes`` and archive
    size aren't read)."""
    out = []
    seen: dict[str, str] = {}
    for p in paths:
        for part in p.split("/"):
            if ":" in part or part.endswith((".", " ")) or _WIN_DEVICE.match(part):
                out.append(f"a name Windows can't hold ({p})")
                break
        low = p.lower()
        if low in seen and seen[low] != p:
            out.append(f"names that differ only by case ({seen[low]}, {p})")
        seen.setdefault(low, p)
    if folder and not all(_FOLDER_CHARS.match(x) for x in folder.split("/")):
        out.append("a folder on the plugin path with characters other than letters, digits, "
                   "dots, hyphens and underscores")
    if len(paths) >= MAX_REPO_ENTRIES:
        out.append(f"{len(paths)} files (the limit is under 10,000 files and folders)")
    return out[:3]


def _gate(gate_id, label, status, severity, detail, *, basis="documented",
          sources=_DOC):
    return {"id": gate_id, "label": label, "status": status, "severity": severity,
            "detail": detail, "stores": ["anthropic"], "basis": basis,
            "sources": cite(*sources), "group": "plugin"}


def _ext(path: str) -> str:
    base = posixpath.basename(path)
    return base.rsplit(".", 1)[-1].lower() if "." in base.lstrip(".") else ""


def find_plugin_folders(paths: list[str]) -> list[str]:
    """Folders that hold ``.claude-plugin/plugin.json`` ("" is the repo root)."""
    out = []
    for p in paths:
        if p == ".claude-plugin/plugin.json":
            out.append("")
        elif p.endswith("/.claude-plugin/plugin.json"):
            out.append(p[: -len("/.claude-plugin/plugin.json")])
    return sorted(set(out))


def _in_folder(path: str, folder: str) -> str | None:
    """``path`` relative to ``folder``, or None when it is outside it."""
    if not folder:
        return path
    return path[len(folder) + 1:] if path.startswith(folder + "/") else None


def _readme_words(text: str) -> int:
    no_code = re.sub(r"```.*?```|~~~.*?~~~", " ", text, flags=re.S)
    no_code = re.sub(r"`[^`\n]*`", " ", no_code)
    return len(re.findall(r"[A-Za-z0-9][\w'’-]*", no_code))


def _tokens(cmd) -> list[str]:
    if isinstance(cmd, list):
        return [str(c) for c in cmd]
    try:
        return shlex.split(str(cmd))
    except ValueError:
        return str(cmd).split()


def _launcher_issues(tokens: list[str]) -> tuple[list[str], list[str]]:
    """(unpinned launches, pinned launches) found in one command's tokens."""
    unpinned, pinned = [], []
    i, n = 0, len(tokens)
    while i < n:
        base = posixpath.basename(tokens[i])
        two = f"{base} {tokens[i + 1]}" if i + 1 < n else base
        if two in ("uv run",):
            rest = tokens[i + 2:]
            (pinned if ("--locked" in rest or "--frozen" in rest) else unpinned).append(
                "uv run")
            i += 2
            continue
        if base in ("npx", "bunx", "uvx") or two in ("pnpm dlx", "yarn dlx", "pipx run"):
            j = i + (1 if base in ("npx", "bunx", "uvx") else 2)
            while j < n and tokens[j].startswith("-"):
                # ``uvx --from pkg==1 cmd`` names the package in --from's value
                if tokens[j] in ("--from", "--package", "-p") and j + 1 < n:
                    j += 1
                    break
                j += 1
            pkg = tokens[j] if j < n else ""
            label = f"{two if base not in ('npx', 'bunx', 'uvx') else base} {pkg}".strip()
            (pinned if _pinned(pkg) else unpinned).append(label)
            i = j + 1
            continue
        i += 1
    return unpinned, pinned


def _pinned(pkg: str) -> bool:
    if "==" in pkg:
        return bool(_EXACT_VERSION.match(pkg.split("==", 1)[1]))
    at = pkg.rfind("@")
    if at > 0:  # "@scope/name@1.2.3" or "name@1.2.3" (not a leading scope "@")
        return bool(_EXACT_VERSION.match(pkg[at + 1:]))
    return False


def _bad_vars(text: str) -> list[str]:
    out = []
    for m in _VAR.finditer(text):
        name = m.group(1) or m.group(2) or ""
        if name == "CLAUDE_PLUGIN_ROOT" or name.startswith("user_config."):
            continue
        out.append(name)
    return out


def _command_path_problem(cmd_text: str) -> str | None:
    if "$(" in cmd_text or "`" in cmd_text:
        return "a command substitution"
    if _bad_vars(cmd_text):
        return f"the variable ${_bad_vars(cmd_text)[0]}"
    if any("://" not in t and any(c in t for c in "*?[") for t in _tokens(cmd_text)):
        return "a wildcard"
    if _INLINE_PROGRAM.search(cmd_text):
        return "an inline program"
    return None


def _load_json(text: str | None):
    if text is None:
        return None, False
    try:
        return json.loads(text), True
    except ValueError:
        return None, False


def _mcp_servers(manifest: dict, mcp_text: str | None, read: dict, folder: str):
    """(servers dict, .mcp.json parse ok or None when absent)."""
    servers: dict = {}
    parse_ok = None
    if mcp_text is not None:
        js, parse_ok = _load_json(mcp_text)
        if parse_ok and isinstance(js, dict):
            inner = js.get("mcpServers", js)
            if isinstance(inner, dict):
                servers.update({k: v for k, v in inner.items() if isinstance(v, dict)})
        elif parse_ok:
            parse_ok = False
    decl = manifest.get("mcpServers")
    if isinstance(decl, dict):
        servers.update({k: v for k, v in decl.items() if isinstance(v, dict)})
    elif isinstance(decl, str):
        p = posixpath.normpath(posixpath.join(folder, decl.lstrip("./"))) if folder else \
            posixpath.normpath(decl.lstrip("./"))
        js, ok = _load_json(read.get(p))
        if ok and isinstance(js, dict):
            inner = js.get("mcpServers", js)
            if isinstance(inner, dict):
                servers.update({k: v for k, v in inner.items() if isinstance(v, dict)})
    return servers, parse_ok


def _hook_entries(hooks_obj) -> list[dict]:
    """Every hook dict (``{type, command|url, ...}``) in a ``hooks`` object."""
    out = []
    if not isinstance(hooks_obj, dict):
        return out
    for groups in hooks_obj.values():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") if isinstance(g, dict) else None) or []:
                if isinstance(h, dict):
                    out.append(h)
    return out


def script_paths(command: str, folder: str) -> list[str]:
    """Repo paths of plugin files a hook or server command runs via
    ``${CLAUDE_PLUGIN_ROOT}/...``."""
    out = []
    for m in re.finditer(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\s\"';|&]+)", command or ""):
        rel = posixpath.normpath(m.group(1))
        if rel.startswith(".."):
            continue
        out.append(posixpath.join(folder, rel) if folder else rel)
    return out


def needed_files(paths: list[str], folder: str) -> list[str]:
    """The files ``evaluate_plugin`` reads, before hook scripts are known."""
    want = [posixpath.join(folder, p) if folder else p
            for p in (".claude-plugin/plugin.json", ".mcp.json", "hooks/hooks.json")]
    readmes = [p for p in paths if _in_folder(p, folder) is not None
               and "/" not in _in_folder(p, folder)
               and posixpath.basename(p).lower().startswith("readme")]
    readmes.sort(key=lambda p: (posixpath.basename(p) != "README.md", p))
    return [p for p in want if p in set(paths)] + readmes[:1]


def evaluate_plugin(files: list[dict], read: dict[str, str], folder: str,
                    *, all_folders: list[str] | None = None) -> list[dict]:
    """Gates for the plugin in ``folder``. ``files`` is ``[{path, size}]`` for the whole
    repo; ``read`` maps repo path → text for the files fetched."""
    gates: list[dict] = []
    all_folders = all_folders or [folder]
    rel_files = []
    for f in files:
        rel = _in_folder(str(f.get("path") or ""), folder)
        if rel is not None:
            rel_files.append((rel, int(f.get("size") or 0), str(f.get("path"))))

    def j(rel: str) -> str:
        return posixpath.join(folder, rel) if folder else rel

    if len(all_folders) > 1:
        others = [x or "(repo root)" for x in all_folders if x != folder]
        gates.append(_gate(
            "plugin_one_at_a_time", "One plugin per submission", WARN, WARNING,
            f"This repo holds {len(all_folders)} plugins. Checked "
            f"{folder or '(repo root)'}; validate and submit each folder on its own "
            f"(also here: {', '.join(others[:5])}). Paste a GitHub URL to a folder "
            "(…/tree/main/<folder>) to check another."))

    manifest, ok = _load_json(read.get(j(".claude-plugin/plugin.json")))
    if not ok or not isinstance(manifest, dict):
        gates.append(_gate("plugin_manifest", "plugin.json parses", FAIL, BLOCKER,
                           ".claude-plugin/plugin.json is not valid JSON (or couldn't be "
                           "read). Run `claude plugin validate`."))
        return gates
    gates.append(_gate("plugin_manifest", "plugin.json parses", PASS, BLOCKER,
                       ".claude-plugin/plugin.json is valid JSON."))

    # Name
    name = manifest.get("name")
    name = name if isinstance(name, str) else ""
    if not name.isascii():
        gates.append(_gate("plugin_name", "Plugin name follows the rules", FAIL, BLOCKER,
                           "The name has non-ASCII characters (\"Non-ASCII identifier\")."))
    elif name.lower() in RESERVED_NAMES:
        gates.append(_gate("plugin_name", "Plugin name follows the rules", FAIL, BLOCKER,
                           f"\"{name}\" is a reserved word used as the whole name "
                           "(\"Name is taken\"). Build it around your own product name."))
    elif not _NAME_RX.match(name):
        gates.append(_gate("plugin_name", "Plugin name follows the rules", WARN, WARNING,
                           "Use lowercase letters, digits and hyphens, up to 64 characters, "
                           "starting and ending with a letter or digit."))
    else:
        gates.append(_gate("plugin_name", "Plugin name follows the rules", PASS, BLOCKER,
                           f"\"{name}\" fits the pattern. Uniqueness and brand look-alikes "
                           "are checked only by the portal."))

    missing = [k for k in ("description", "author", "version") if not manifest.get(k)]
    gates.append(_gate("plugin_metadata", "description, author and version set",
                       WARN if missing else PASS, WARNING,
                       f"Missing in plugin.json: {', '.join(missing)}." if missing
                       else "description, author and version are set."))

    # README + license
    readme_path = next((p for p in read if _in_folder(p, folder) is not None
                        and "/" not in (_in_folder(p, folder) or "")
                        and posixpath.basename(p).lower().startswith("readme")), None)
    if readme_path is None:
        gates.append(_gate("plugin_readme", "README of at least 40 words", FAIL, BLOCKER,
                           "No README in the plugin folder (\"README missing\")."))
    else:
        words = _readme_words(read[readme_path])
        gates.append(_gate(
            "plugin_readme", "README of at least 40 words",
            PASS if words >= README_MIN_WORDS else FAIL, BLOCKER,
            f"{posixpath.basename(readme_path)} has {words} words outside code blocks."
            + ("" if words >= README_MIN_WORDS else " (\"README too short\")")))
    has_license_file = any("/" not in r and posixpath.basename(r).lower().startswith(
        ("license", "licence")) for r, _s, _p in rel_files)
    has_license = has_license_file or bool(manifest.get("license"))
    gates.append(_gate("plugin_license", "License present", PASS if has_license else FAIL,
                       BLOCKER, "LICENSE file or `license` in plugin.json found." if has_license
                       else "Add a LICENSE file to the plugin folder or set `license` in "
                            "plugin.json (\"License missing\")."))

    # Repository layout (these stop validation before any report)
    layout = layout_problems([str(f.get("path") or "") for f in files], folder)
    huge = sorted(r for r, s, _p in rel_files if s > MAX_PLUGIN_FILE)
    if huge:
        layout.append(f"files over 5 MiB in the plugin folder: {', '.join(huge[:3])}")
    gates.append(_gate("plugin_repo_layout", "Repository can be validated",
                       FAIL if layout else PASS, BLOCKER,
                       ("Validation stops (\"Couldn’t validate that repository\" / \"Repository "
                        "too large to validate\"): " + "; ".join(layout) + ".") if layout
                       else "File names, plugin path and file count are within the limits. "
                       ".gitattributes and archive size aren't checked here."))
    link_paths = {f.get("path") for f in files if f.get("mode") == "120000"}
    links = sorted(r for r, _s, p in rel_files if p in link_paths)
    if links:
        gates.append(_gate("plugin_symlinks", "Regular files, not symbolic links", WARN,
                           WARNING, f"Symbolic links: {', '.join(links[:3])}. A link the plugin "
                           "loads blocks; commit the file itself."))

    # Folder contents
    sysfiles = sorted(r for r, _s, _p in rel_files
                      if posixpath.basename(r).lower() in SYSTEM_FILES
                      or r.split("/")[0] == "__MACOSX" or "/__MACOSX/" in f"/{r}")
    gates.append(_gate("plugin_system_files", "No .DS_Store / Thumbs.db / __MACOSX",
                       FAIL if sysfiles else PASS, BLOCKER,
                       f"Remove: {', '.join(sysfiles[:5])}." if sysfiles
                       else "No macOS or Windows system files."))

    climbing = []
    for key in _COMPONENT_KEYS:
        v = manifest.get(key)
        for item in (v if isinstance(v, list) else [v]):
            if isinstance(item, str) and ".." in item.replace("\\", "/").split("/"):
                climbing.append(f"{key}: {item}")
    gates.append(_gate("plugin_paths_inside", "Component paths stay inside the plugin",
                       FAIL if climbing else PASS, BLOCKER,
                       f"\"Path climbs out of the plugin\": {'; '.join(climbing[:3])}."
                       if climbing else "No plugin.json path climbs out with `..`."))

    big = sorted(r for r, s, _p in rel_files if s > MAX_TEXT_BYTES
                 and _ext(r) not in _IMAGE_FONT)
    binaries = sorted(r for r, _s, _p in rel_files if _ext(r) in _HELD_BINARY)
    held = []
    if len(rel_files) > MAX_FILES:
        held.append(f"{len(rel_files)} files (over {MAX_FILES})")
    if big:
        held.append(f"files over 256 KiB: {', '.join(big[:3])}")
    if binaries:
        held.append(f"binary files: {', '.join(binaries[:3])}")
    gates.append(_gate("plugin_file_limits", "File count, size and type limits",
                       FAIL if held else PASS, HOLD,
                       ("Held for a reviewer (\"Files or downloads the validator couldn’t "
                        "inspect\"): " + "; ".join(held) + ".") if held
                       else f"{len(rel_files)} files, none over 256 KiB, no held binaries."))

    # MCP servers
    mcp_text = read.get(j(".mcp.json"))
    servers, mcp_ok = _mcp_servers(manifest, mcp_text, read, folder)
    if mcp_ok is False:
        gates.append(_gate("plugin_mcp_json", ".mcp.json parses", FAIL, BLOCKER,
                           "\".mcp.json can’t be parsed\": it isn't valid JSON or isn't an "
                           "object of server entries."))
    elif mcp_ok:
        gates.append(_gate("plugin_mcp_json", ".mcp.json parses", PASS, BLOCKER,
                           ".mcp.json is valid JSON."))

    remote_bad, local, bundles, cred_hold, secret_hdr = [], [], [], [], []
    unpinned, pinned, path_problems = [], [], []
    for sname, s in servers.items():
        url = s.get("url")
        if s.get("command"):
            local.append(sname)
            cmd_tokens = [str(s.get("command"))] + [str(a) for a in s.get("args") or []]
            u, p = _launcher_issues(cmd_tokens)
            unpinned += u
            pinned += p
            problem = _command_path_problem(" ".join(cmd_tokens))
            if problem:
                path_problems.append(f"server {sname}: {problem}")
            if any(t.lower().endswith((".mcpb", ".dxt")) for t in cmd_tokens):
                bundles.append(sname)
        if url is not None:
            u_s = str(url)
            if not (u_s == "" or u_s.startswith(("https://", "wss://"))
                    or re.fullmatch(r"\$\{user_config\.[^}]+\}", u_s)):
                remote_bad.append(sname)
        for blob in (s.get("env"), s.get("headers")):
            if isinstance(blob, dict):
                for k, v in blob.items():
                    if _bad_vars(str(v)):
                        cred_hold.append(f"{sname}.{k}")
        hdrs = s.get("headers") if isinstance(s.get("headers"), dict) else {}
        for k, v in hdrs.items():
            v = str(v)
            if (_SECRET_HEADER.search(k) and "${" not in v and len(v) >= 12
                    and not re.search(r"your|<|example|xxx", v, re.I)):
                secret_hdr.append(f"{sname}.{k}")
        for t in (s.get("args") or []) + ([url] if url else []):
            if _bad_vars(str(t)) and str(t) not in cred_hold:
                cred_hold.append(f"{sname}: {t}"[:80])

    if servers:
        gates.append(_gate("plugin_mcp_https", "Remote MCP URLs are https:// or wss://",
                           FAIL if remote_bad else PASS, BLOCKER,
                           f"\"MCP server URL is not https\": {', '.join(remote_bad)}."
                           if remote_bad else "Every remote server URL is https/wss, a "
                           "${user_config.KEY} reference or empty."))
        gates.append(_gate("plugin_mcp_headers_secret", "No credentials in MCP headers",
                           FAIL if secret_hdr else PASS, BLOCKER,
                           f"\"Secret in MCP headers\": {', '.join(secret_hdr)}. Ask for it "
                           "through userConfig with sensitive: true." if secret_hdr
                           else "No literal credential in MCP server headers."))
    if bundles:
        gates.append(_gate("plugin_mcp_bundle", "No .mcpb / .dxt bundles", FAIL, HOLD,
                           f"\"Bundled MCP server not inspected\": {', '.join(bundles)}. "
                           "Declare each server with command + args or url."))

    # Hooks
    hooks_text = read.get(j("hooks/hooks.json"))
    hooks_js, hooks_ok = _load_json(hooks_text)
    hook_list: list[dict] = []
    modules = False
    if hooks_text is not None:
        valid = hooks_ok and isinstance(hooks_js, dict) and (
            isinstance(hooks_js.get("hooks"), dict) or isinstance(hooks_js.get("modules"),
                                                                     list))
        gates.append(_gate("plugin_hooks_json", "hooks/hooks.json is valid",
                           PASS if valid else FAIL, BLOCKER,
                           "hooks/hooks.json parses with a hooks object or modules array."
                           if valid else "\"hooks.json is invalid\": it must be JSON with a "
                           "top-level hooks object, a modules array, or both."))
        if valid:
            hook_list = _hook_entries(hooks_js.get("hooks"))
            modules = bool(hooks_js.get("modules"))
    if isinstance(manifest.get("hooks"), dict):
        hook_list += _hook_entries(manifest["hooks"])

    cmd_hooks = [h for h in hook_list if h.get("type", "command") == "command"]
    for h in hook_list:
        if h.get("type") == "http":
            u = str(h.get("url") or "")
            if u and not u.startswith("https://"):
                path_problems.append(f"http hook to a non-https URL ({u[:40]})")
            hdrs = h.get("headers") if isinstance(h.get("headers"), dict) else {}
            if any(_bad_vars(str(v)) for v in hdrs.values()):
                cred_hold.append("HTTP hook header (blocks)")
    for h in cmd_hooks:
        cmd = str(h.get("command") or "")
        u, p = _launcher_issues(_tokens(cmd))
        unpinned += u
        pinned += p
        problem = _command_path_problem(cmd)
        if problem:
            path_problems.append(f"hook `{cmd[:50]}`: {problem}")

    launchers = unpinned + pinned
    if launchers or servers or cmd_hooks:
        gates.append(_gate("plugin_launchers_pinned", "Launchers pin an exact version",
                           FAIL if unpinned else PASS, BLOCKER,
                           f"\"Unpinned npx/uvx launcher\": {', '.join(unpinned[:3])}. Pin "
                           "an exact version (pkg@1.2.3, pkg==1.2.3) or run uv with --locked."
                           if unpinned else ("Every launcher pins an exact version."
                                             if launchers else "No package launchers.")))
    if pinned:
        gates.append(_gate("plugin_pinned_package_hold", "Registry packages a reviewer reads",
                           FAIL, HOLD, f"\"Runs a pinned npx or uvx package\": "
                           f"{', '.join(pinned[:3])}. Always held, because its own "
                           "dependencies resolve at install time."))
    src_cfg = sorted(r for r, _s, _p in rel_files
                     if posixpath.basename(r).lower() in _PKG_SOURCE_CONFIG)
    if src_cfg and launchers:
        gates.append(_gate("plugin_package_source", "No custom registry config with a "
                           "launcher", FAIL, BLOCKER,
                           f"{', '.join(src_cfg)} can point installs at another registry; "
                           "with a launcher this blocks."))
    if path_problems or cmd_hooks or any(s.get("command") for s in servers.values()):
        gates.append(_gate("plugin_command_paths", "Commands name files from "
                           "${CLAUDE_PLUGIN_ROOT}", FAIL if path_problems else PASS, BLOCKER,
                           f"\"Command path can’t be followed\": {'; '.join(path_problems[:3])}."
                           if path_problems else "Hook and server commands use only "
                           "${CLAUDE_PLUGIN_ROOT} paths."))
    blocks_cred = any("blocks" in c for c in cred_hold)
    if cred_hold:
        gates.append(_gate("plugin_user_credentials", "No credential read from the user's "
                           "machine", FAIL, BLOCKER if blocks_cred else HOLD,
                           f"\"Uses a credential from the user’s machine\": "
                           f"{', '.join(cred_hold[:3])}. Ask for it through a userConfig entry "
                           "with sensitive: true and use ${user_config.KEY}. README examples "
                           "count too; we don't read them."))
    roots = {r for r, _s, _p in rel_files if "/" not in r}
    if "package.json" in roots and roots & _LOCKFILES:
        gates.append(_gate("plugin_lockfile_install", "Lockfile installs a reviewer reads",
                           FAIL, HOLD, "\"Dependencies install from a lockfile\": package.json "
                           "beside a lockfile in the plugin root is always held."))

    # Observed, undocumented: Verified-only refusals (since ~2026-11-05).
    obs_note = (" Observed since about 2026-11-05 and not in Anthropic's docs yet. Refused "
                "unless your organization is Verified; there is no documented way to apply.")
    if cmd_hooks:
        gates.append(_gate("plugin_verified_command_hooks", "Command hooks (Verified "
                           "organizations only)", FAIL, BLOCKER,
                           f"{len(cmd_hooks)} hook(s) of type command. \"Hooks of type command "
                           "accepted only from Verified organizations\"." + obs_note,
                           basis="observed", sources=_OBS))
    if local:
        gates.append(_gate("plugin_verified_local_mcp", "Local MCP servers (Verified "
                           "organizations only)", FAIL, BLOCKER,
                           f"Local server(s): {', '.join(local[:3])}. \"Local MCP servers "
                           "accepted only from Verified organizations\"." + obs_note,
                           basis="observed", sources=_OBS))
    if modules:
        gates.append(_gate("plugin_verified_mods", "Mods (Verified organizations only)", FAIL,
                           BLOCKER, "hooks.json declares modules. \"Mods accepted only from "
                           "Verified organizations\"." + obs_note,
                           basis="observed", sources=_OBS))

    def _observed_ok(rel: str, repo_path: str) -> bool:
        text = read.get(repo_path)
        if text is not None and text.startswith("#!"):
            return False
        e = _ext(rel)
        if not e:
            return posixpath.basename(rel).lower() in _TEXT_NAMES
        return e in _OBSERVED_ALLOWED

    odd = sorted(r for r, _s, p in rel_files if not _observed_ok(r, p))
    gates.append(_gate(
        "plugin_verified_file_types", "Only Markdown, text, JSON, YAML and images "
        "(Verified organizations only otherwise)", FAIL if odd else PASS,
        BLOCKER, (f"{len(odd)} file(s) outside the accepted types, such as "
                  f"{', '.join(odd[:4])}. \"Files outside the allowed types accepted only "
                  "from Verified organizations\". Files that start with #! count too "
                  "(we read only the files hooks run)." + obs_note) if odd
        else "Every file is Markdown, text, JSON, YAML, PNG, JPEG, GIF, WebP or ICO."
             " (Observed rule, not documented.)",
        basis="observed", sources=_OBS))

    approving = [p for p, t in read.items() if _in_folder(p, folder) is not None
                 and p not in (j(".claude-plugin/plugin.json"), j(".mcp.json"))
                 and _APPROVES.search(t or "")]
    if any(_APPROVES.search(str(h.get("command") or "")) for h in cmd_hooks):
        approving.append("an inline hook command")
    if cmd_hooks or approving:
        gates.append(_gate(
            "plugin_hook_approves", "Hooks only ask or deny", FAIL if approving else PASS,
            HOLD, (f"{', '.join(approving[:3])} can allow a tool call or rewrite its input "
                   "(permissionDecision allow / updatedInput). The directory reports \"Hook "
                   "can approve tool calls or change their input\". Observed, not documented; "
                   "we haven't seen whether it blocks or holds.") if approving
            else "No hook script we read allows a call or rewrites its input. (Observed rule.)",
            basis="observed", sources=_OBS))
    return gates


def _skills_only(paths: list[str]) -> bool:
    return any(_SKILL_MD.search(p) for p in paths)


async def check_plugin_repo(owner: str, repo: str, token: str | None,
                            plugin_path: str | None = None) -> dict:
    """``{found, folder, folders, gates}`` for a repo; ``found`` False when the repo
    holds no plugin. Fail-open: a fetch error gives ``{"found": None, ...}``."""
    from src.scanner.scan import _fetch_file_content, _fetch_repo_tree

    try:
        meta: dict = {}
        blobs, _trunc, ok, ref = await _fetch_repo_tree(owner, repo, token, meta_out=meta)
        if not ok:
            return {"found": None, "folder": None, "folders": [], "gates": []}
        files = [{"path": b.get("path"), "size": b.get("size", 0), "mode": b.get("mode")}
                 for b in list(blobs) + list(meta.get("oversized") or [])]
        paths = [str(f["path"]) for f in files]
        folders = find_plugin_folders(paths)
        if not folders:
            note = []
            if _skills_only(paths):
                note = [_gate("plugin_skills_only", "Skills without plugin.json", WARN,
                              WARNING, "No .claude-plugin/plugin.json, but skills/<name>/"
                              "SKILL.md exists: this passes with a note and is listed for "
                              "Claude Code only.")]
            return {"found": False, "folder": None, "folders": [], "gates": note}
        want = (plugin_path or "").strip("/")
        folder = want if want in folders else folders[0]
        read: dict[str, str] = {}
        for p in needed_files(paths, folder):
            text = await _fetch_file_content(owner, repo, p, token, ref)
            if text is not None:
                read[p] = text
        # Then the scripts hooks and servers run (a few, small).
        cmds: list[str] = []
        hooks_js, _ = _load_json(read.get(posixpath.join(folder, "hooks/hooks.json")
                                          if folder else "hooks/hooks.json"))
        if isinstance(hooks_js, dict):
            cmds += [str(h.get("command") or "") for h in _hook_entries(hooks_js.get("hooks"))]
        sizes = {str(f["path"]): int(f.get("size") or 0) for f in files}
        extra = []
        for c in cmds:
            extra += script_paths(c, folder)
        for p in list(dict.fromkeys(extra))[:10]:
            if p in sizes and sizes[p] <= MAX_TEXT_BYTES:
                text = await _fetch_file_content(owner, repo, p, token, ref)
                if text is not None:
                    read[p] = text
        gates = evaluate_plugin(files, read, folder, all_folders=folders)
        return {"found": True, "folder": folder, "folders": folders, "gates": gates}
    except Exception:  # noqa: BLE001 — the plugin check is additive and best-effort
        import logging
        logging.getLogger(__name__).debug("plugin check failed", exc_info=True)
        return {"found": None, "folder": None, "folders": [], "gates": []}
