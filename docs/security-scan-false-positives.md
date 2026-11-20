# Reducing Security Scan False Positives

AgentGraph's security scanner analyzes your source code for potential vulnerabilities. Sometimes it flags code that is actually safe — these are **false positives**. You have two ways to suppress them.

## Option 1: Inline Suppression (`ag-scan:ignore`)

Add `# ag-scan:ignore` as a comment on any line to suppress all findings on that line.

**Python:**
```python
result = subprocess.run(["scp", "-i", key, file, dest])  # ag-scan:ignore
```

**JavaScript / TypeScript:**
```javascript
const output = execSync('git status')  // ag-scan:ignore
```

**When to use:** For individual lines where you're confident the code is safe. This is the quickest way to suppress a specific finding.

## Option 2: Allowlist File

If your project has many findings of the same type, or you want to suppress findings across multiple files without touching the source code, you can request an allowlist entry.

The allowlist maps **file path patterns** to **finding names**. For example:

| File Path | Finding Name | Effect |
|-----------|-------------|--------|
| `src/deploy.py` | `subprocess.run / Popen (Python)` | Suppresses subprocess findings in that exact file |
| `scripts/*` | `subprocess.run / Popen (Python)` | Suppresses subprocess findings in all files under `scripts/` |
| `src/config.py` | `Unrestricted file read (Python)` | Suppresses file-read findings in config.py |

To request an allowlist entry, contact the AgentGraph team or open an issue.

## What the Scanner Already Handles

The scanner has built-in **context-aware checks** that automatically skip safe patterns — you don't need to suppress these:

| Pattern | Why It's Safe |
|---------|---------------|
| `subprocess.run(["git", "status"])` | First argument is a hardcoded string literal |
| `subprocess.run(cmd, shell=False)` | Explicit `shell=False` prevents shell injection |
| `ast.literal_eval(data)` | Safe eval — only parses Python literals |
| `json.loads(text)` | Not actually `eval()` despite containing "eval" in the call |
| `open("config.json", "r").read()` | Hardcoded file path string |
| `with open(path) as f:` | Context manager ensures proper resource handling |
| `Path("out.txt").write_text(data)` | Pathlib method call on a known path |
| `base = getattr(__builtins__, 'TimeoutError', OSError)` then `type(name, (Base, base), {})` | A builtin exception class looked up by a **literal** exception-class name (`…Error` / `…Exception` / `…Warning` or a builtin exception) and used only in `isinstance` / `issubclass` / `except` / a `type(…)` bases tuple (low). The key AND the default must both be real builtin exception classes that the file never binds (at module level `__builtins__` is a dict, so `getattr` returns the default). A computed key (`'ev'+'al'`, a parameter), an unknown key (`'NoSuchError'`), a default the file binds (`MyError = eval`), any `vars()` / `globals()` / `locals()` / `setattr` / `__dict__` / `sys.modules` / `import builtins`, any binding of `__builtins__` (assignment, a `class __builtins__:`), or a file that does not parse stays critical. So does any use of the name anywhere in the file, checked over bracket-joined logical lines (`(base\n)(…)`), that calls it, passes it to another call (`map(base, …)`), calls it through parentheses, rebinds it or subclasses it with `class X(base)` |
| England / Scotland / Wales flag emoji, with or without a ZWJ before each tag | A subdivision flag whose tag text is `gbeng` / `gbsct` / `gbwls` (either form), or, in the plain form only, the ISO 3166-2 shape (a real alpha-2 country code + 1–3 lowercase alphanumerics) with at most 2 such non-RGI flags on a line and in the whole file. The ZWJ form with any other tag text, a third non-RGI flag on a line or in a file (`se\|nd\|th…` chunks spell text), a flag with a letter or digit right before and after it (inside a token), and any other tag run stay critical; bidi controls keep their finding |
| An EC private key whose secret scalar is below 2^32 (e.g. a `d=4` key for a known-compromised CA) | Anyone can derive it, so it is a placeholder, not a leaked secret (low), but only when the block is exactly that key (re-encoding it gives the same bytes, so no other field carries data) and nothing uses it against a live service: an HTTP / RPC client, a JWT signer or an `Authorization` header in the same file, or in another file that names the key's holder or its file, keeps the critical. Any other key body stays critical |
| `curl … \| bash` inside a `code_example: \|` (or `bad_example`, `examples`, …) block of a YAML rule entry | Example text a rule shows to a person (low), only in an entry of a top-level `rules:` list that has `id`, `severity` and a detection key (`pattern` / `regex` / `detection` …). `safe` / `good` keys, `run: \|` / `command: \|` blocks, entries without that schema and YAML outside a rule set stay critical, and the critical comes back when any file in view, workflow / CI YAML and shell scripts included, names the rules file (`hooks.yaml`) or the bare example key (`code_example`, quoted or not) within 3 lines of an exec sink or `\| sh`, or passes a name bound from such a mention (assignment, `for` / `with` target) to an exec sink. Whatever it calls the field, any code file that loads YAML (or lists a directory and reads what it finds) and can run something (an exec module such as `subprocess`, an exec builtin, an `os` exec call, a shell pipe) reads as a runner, and so does an agent instruction file (`AGENTS.md`, `SKILL.md`, `CLAUDE.md`, `.cursorrules` …) that tells the agent to run a rule, a YAML file or an example. A rules file under a dot-directory (`.claude/`, `.github/` …), in an agent instruction location or with a well-known config name gets no exemption, and if a file that could run it was not read (past the file cap, oversized, or a name the per-file scan skips), the critical stays: recall over precision |
| `placeholder: 'acme.tunnel.example'`, `"e.g. acme.tunnel.example"`, a host-allowlist suffix, a bundled public-suffix list | In JS / TS code only, a tunnel host listed as data is reported low, not critical, but only while it can never be dialled: its holder is never passed on, interpolated or returned; the object around it is never read whole (`Object.values`, spread, `JSON.stringify`, iterated, passed to a call); it is not returned from a function, exported, or set on `this` or a global; it is not handed to a function the package defines itself; no other code shares its line; and nothing in the package reads the file's (or the enclosing function's) source text. Anything else keeps the critical. A value in a JSON, YAML or Python file keeps it too. |

## Finding Names Reference

When using `ag-scan:ignore` or requesting allowlist entries, the finding names match what's shown in the scan results:

**Unsafe Execution:**
- `subprocess.run / Popen (Python)`
- `os.system / os.popen (Python)`
- `eval() call`
- `exec() call (Python)`
- `child_process (Node.js)`
- `execSync / spawn (Node.js)`
- `shell=True (Python)`

**Filesystem Access:**
- `Unrestricted file read (Python)`
- `Unrestricted file write (Python)`
- `fs.readFileSync / writeFileSync (Node.js)`
- `Path traversal risk (../ in string)`
- `rmrf / recursive delete`

**Data Exfiltration:**
- `HTTP POST with sensitive data`
- `Outbound webhook/exfil URL`
- `Base64 encode + send`
- `Environment variable exfil`
- `DNS exfiltration pattern`

**Code Obfuscation:**
- `Hex-encoded string execution`
- `String char-code assembly`
- `Obfuscated eval (Python)`
- `Dynamic import with variable`
- `Reversed/rotated string decode`

## Questions?

If you believe a finding is a false positive and neither suppression method fits your case, [open an issue](https://github.com/agentgraph-co/agentgraph/issues) with the finding details and we'll look into improving the scanner.
