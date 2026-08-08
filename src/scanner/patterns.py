"""Regex patterns for security scanning."""
from __future__ import annotations

import re

# --- Hardcoded secrets ---
# Each tuple: (name, compiled regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical",
    ),
    (
        "AWS Secret Key",
        re.compile(
            r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]([A-Za-z0-9/+=]{40})['"]""",
            re.IGNORECASE,
        ),
        "critical",
    ),
    (
        "OpenAI API Key",
        re.compile(r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}"),
        "critical",
    ),
    (
        "OpenAI Project Key",
        re.compile(r"sk-proj-[a-zA-Z0-9_-]{40,}"),
        "critical",
    ),
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9_-]{40,}"),
        "critical",
    ),
    (
        "Generic API Key assignment",
        re.compile(
            r"""(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[=:]\s*['"]([a-zA-Z0-9_\-/+=]{20,})['"]""",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "Private Key block",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "critical",
    ),
    (
        "GitHub Token",
        re.compile(r"gh[ps]_[a-zA-Z0-9]{36,}"),
        "critical",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bpars]-[a-zA-Z0-9-]+"),
        "high",
    ),
    (
        "Base64 encoded long secret",
        re.compile(
            r"""(?:secret|key|token|password)\s*[=:]\s*['"]([A-Za-z0-9+/]{40,}={0,2})['"]""",
            re.IGNORECASE,
        ),
        "medium",
    ),
]

# --- Unsafe execution patterns ---
UNSAFE_EXEC_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "subprocess.run / Popen (Python)",
        re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\("),
        "high",
    ),
    (
        "os.system / os.popen (Python)",
        re.compile(r"os\.(system|popen)\s*\("),
        "high",
    ),
    (
        "eval() call",
        re.compile(r"\beval\s*\("),
        "high",
    ),
    (
        "exec() call (Python)",
        re.compile(r"\bexec\s*\("),
        "high",
    ),
    (
        "child_process (Node.js)",
        re.compile(r"""(?:require\s*\(\s*['"]child_process['"]\)|from\s+['"]child_process['"])"""),
        "high",
    ),
    (
        "execSync / spawn (Node.js)",
        re.compile(r"\b(?:execSync|spawnSync|exec)\s*\("),
        "high",
    ),
    (
        "shell=True (Python)",
        re.compile(r"shell\s*=\s*True"),
        "critical",
    ),
    (
        "Command.new / system (Ruby)",
        re.compile(r"(?:system|`|%x)\s*[\(\[]"),
        "medium",
    ),
    (
        "os/exec (Go)",
        re.compile(r"""exec\.Command\s*\("""),
        "medium",
    ),
    (
        "std::process::Command (Rust)",
        re.compile(r"Command::new\s*\("),
        "medium",
    ),
]

# --- File system access patterns (without explicit sandboxing) ---
FS_ACCESS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Unrestricted file read (Python)",
        re.compile(r"open\s*\([^)]*\)\s*\.?\s*read"),
        "medium",
    ),
    (
        "Unrestricted file write (Python)",
        re.compile(r"open\s*\([^)]*['\"]w['\"][^)]*\)"),
        "medium",
    ),
    (
        "fs.readFileSync / writeFileSync (Node.js)",
        re.compile(r"fs\.(?:readFileSync|writeFileSync|readFile|writeFile)\s*\("),
        "medium",
    ),
    # NOTE: the old `['"]\.\.[\\/]` "path traversal" rule was removed — it matched
    # every relative ES import (`from "../x"`) and tsconfig path, a pure false positive.
    # Real path-traversal risk comes from a variable concatenated with "..", not a quoted
    # string literal / import statement, so a bare quoted "../" is not flagged here.
    (
        "rmrf / recursive delete",
        re.compile(r"(?:shutil\.rmtree|fs\.rm.*recursive|rimraf)\s*\("),
        "high",
    ),
]

# --- Data exfiltration patterns ---
EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "HTTP POST with sensitive data",
        re.compile(
            r"""(?:requests\.post|httpx\.post|fetch|axios\.post)\s*\([^)]*(?:key|secret|token|password|credential)""",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "Outbound webhook/exfil URL",
        re.compile(
            r"""(?:webhook\.site|requestbin|pipedream|ngrok|burp|interact\.sh)""",
            re.IGNORECASE,
        ),
        "critical",
    ),
    (
        "Base64 encode + send",
        re.compile(r"base64\.b64encode.*(?:post|send|request)", re.IGNORECASE),
        "high",
    ),
    (
        # Exfil = the WHOLE environment sent outbound (env dump), NOT a single
        # var. `os.environ.get('HTTP_PROXY')` / `os.environ['API_KEY']` are normal
        # (proxy config, auth) and are excluded by the negative lookahead — only
        # the bare `os.environ` mapping passed into a send call matches. This kills
        # the false critical on general HTTP-client libs (e.g. requests) whose code
        # reads proxy env + contains the word "request" everywhere.
        "Environment variable exfil",
        re.compile(
            r"""(?:\.post|\.put|\.send|fetch|urlopen|requests\.\w+|httpx\.\w+)"""
            r"""\s*\([^)]{0,200}\bos\.environ\b(?!\s*(?:\.get\b|\.setdefault\b|\[))""",
            re.IGNORECASE,
        ),
        "critical",
    ),
    (
        "DNS exfiltration pattern",
        re.compile(
            r"""(?:socket\.gethostbyname|dns\.resolve).*(?:encode|secret|key)""",
            re.IGNORECASE,
        ),
        "critical",
    ),
]

# --- Dynamic remote payload / rug-pull (external-URL-swap) ---
# category="dynamic_remote_load". Flags a skill/MCP tool that fetches code, config,
# prompts, or tool definitions from an EXTERNAL URL that the owner can SWAP after a
# user has integrated it — the mutable-remote-payload / rug-pull threat class. This
# is distinct from EXFILTRATION (data leaving) — here untrusted content is coming IN
# and being executed/trusted, and the remote is mutable so a clean scan can go rogue.
DYNAMIC_REMOTE_LOAD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # (A) fetch-then-exec on one line — highest confidence
    (
        "Remote fetch piped into eval/exec (Python)",
        re.compile(
            r"""(?:eval|exec)\s*\(\s*(?:requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen)\s*\(""",
        ),
        "critical",
    ),
    (
        "Remote response text fed to exec/eval (Python)",
        re.compile(r"""(?:eval|exec)\s*\(.*\.(?:text|content|body|json\(\))"""),
        "high",
    ),
    (
        "Remote fetch into Function/eval (JS)",
        re.compile(r"""(?:eval|new\s+Function)\s*\(\s*await\s+(?:fetch|axios\.get)\s*\("""),
        "critical",
    ),
    (
        "vm.runInContext on fetched content (Node)",
        re.compile(r"""vm\.(?:runInContext|runInNewContext|compileFunction)\s*\("""),
        "high",
    ),
    # (B) remote code/module load — download then import/run
    (
        "Remote pickle/marshal load from response",
        re.compile(
            r"""(?:pickle|marshal)\.loads?\s*\(\s*(?:requests\.|httpx\.|urlopen|response|resp|r)\b""",
        ),
        "critical",
    ),
    (
        "Runtime pip install from remote URL/git",
        re.compile(
            r"""subprocess\.[a-z_]+\([^)]*pip['"]?\s*,?\s*['"]?install[^)]*(?:https?://|git\+|\.git\b)""",
            re.IGNORECASE,
        ),
        "high",
    ),
    # (C) remote-hosted tool description / prompt / config
    (
        "Tool description/prompt built from remote fetch",
        re.compile(
            r"""(?:description|instructions?|prompt|system_prompt|tools?)\s*=\s*(?:await\s+)?(?:requests\.get|httpx\.get|fetch|axios\.get|urlopen)\s*\(""",
            re.IGNORECASE,
        ),
        "critical",
    ),
    # (D) auto-update-from-URL / self-update loop
    (
        "Auto-update payload from hardcoded endpoint",
        re.compile(
            r"""(?:update|refresh|reload|self_update|check_update)[\w_]*\s*\([^)]*https?://""",
            re.IGNORECASE,
        ),
        "high",
    ),
    # (E) pipe-to-shell (rug-pull via install/launch)
    (
        "curl/wget piped to shell",
        re.compile(
            r"""(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b|python3?\s+<\(\s*(?:curl|wget)""",
        ),
        "critical",
    ),
    # (F) NON-PINNED remote resource feeding load/exec (mutable ref = swappable)
    (
        "Unpinned remote resource (branch/latest/HEAD)",
        re.compile(
            r"""https?://[^\s'"]+/(?:raw/)?(?:main|master|HEAD|latest)/[^\s'"]+\.(?:py|js|ts|sh|json)""",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (
        "Unpinned npx/uvx package (no @version pin)",
        re.compile(r"""\b(?:npx|uvx)\s+(?!.*@)[a-zA-Z@][\w\-/]+"""),
        "medium",
    ),
]

# Co-occurrence pass: a network read + an exec sink in the same file (split across
# lines) is the classic rug-pull loader the per-line scan can't see.
NET_READ_RE = re.compile(
    r"""requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen\s*\(|"""
    r"""fetch\s*\(|axios\.(?:get|post)""",
)
EXEC_SINK_RE = re.compile(
    r"""\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|vm\.run|"""
    r"""(?:pickle|marshal)\.loads?\s*\(|importlib\.""",
)

# --- Toxic-flow / capability composition (#9) — the "lethal trifecta" ---
# category="toxic_flow". Individually-benign capabilities that compose into an attack
# chain. The canonical agent threat (Willison's "lethal trifecta"; Invariant Labs' GitHub
# MCP exploit): a tool that (1) reads PRIVATE DATA, (2) ingests UNTRUSTED CONTENT, and (3)
# can SEND OUTBOUND is a prompt-injection→exfiltration chain even if each part is fine.
# We require all three legs present in one file (= one tool) to keep precision high — a
# pure API wrapper with no untrusted-content ingestion does NOT trigger. NOT discounted
# for MCP servers: the GitHub-MCP trifecta is a real documented attack, not a capability.

# Leg 1a — high-confidence private-data read (env / credential files / keychain)
SENSITIVE_READ_RE = re.compile(
    r"""os\.environ|os\.getenv\s*\(|\bgetenv\s*\(|process\.env\b|"""
    r"""["'][^"'\n]*(?:\.ssh/|\.aws/credentials|\.aws/config|\.netrc|id_rsa|/\.env\b|\.pem\b)|"""
    r"""keyring\.get_password|\bkeychain\b|SecItemCopy|CredentialCache""",
    re.IGNORECASE,
)
# Leg 1b — generic file/listing read (weaker private-data signal → lower severity)
FILE_READ_RE = re.compile(
    r"""open\s*\([^)]*\)\s*\.?\s*read|\.read_text\s*\(|\.read_bytes\s*\(|"""
    r"""fs\.readFile(?:Sync)?\s*\(|\breadFileSync\s*\(|"""
    r"""\bglob\.glob\s*\(|os\.listdir\s*\(|os\.walk\s*\(""",
)
# Leg 2 — untrusted/attacker-influenceable INBOUND input (fetched content or request
# body). Deliberately excludes requests.post/put (those are OUTBOUND, leg 3) so a plain
# API-wrapper POST cannot masquerade as the untrusted-input leg.
UNTRUSTED_INPUT_RE = re.compile(
    r"""requests\.get\b|httpx\.get\b|urllib\.request\.urlopen|urlopen\s*\(|"""
    r"""\bfetch\s*\(|axios\.get\b|"""
    r"""request\.(?:json|body|args|form|data|files|params|values)|req\.(?:body|query|params)|"""
    r"""\bwebhook\b""",
    re.IGNORECASE,
)
# Leg 3 — outbound send (data leaves the tool)
OUTBOUND_SEND_RE = re.compile(
    r"""requests\.(?:post|put|patch)\s*\(|httpx\.(?:post|put|patch)\s*\(|"""
    r"""axios\.(?:post|put)\s*\(|fetch\s*\([^)]*(?:method\s*[:=]\s*['"]POST|['"]POST['"])|"""
    r"""\bsmtplib\b|\bsendmail\b|\.send(?:_message)?\s*\(|"""
    r"""socket\.(?:send|sendto|connect)\s*\(|"""
    r"""(?:slack|discord|telegram)[._]\w*(?:send|post|message|webhook)|"""
    r"""boto3[^\n]*put_object|\.upload_file\s*\(|"""
    r"""dns\.resolver|socket\.gethostbyname""",
    re.IGNORECASE,
)

# --- Insecure deserialization (#7) ---
# category="insecure_deserialization". Deserializing untrusted data with a format that
# can construct arbitrary objects = RCE. Distinct from unsafe_exec (NOT discounted for
# MCP servers — an MCP tool that unpickles untrusted input is a real vuln, not an
# intentional capability). Local counterpart to the remote-pickle rug-pull pattern.
INSECURE_DESERIALIZATION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "pickle.load(s) on untrusted data (Python)",
        re.compile(r"""\b(?:cPickle|_pickle|pickle)\.loads?\s*\("""),
        "high",
    ),
    (
        "marshal.load(s) (Python)",
        re.compile(r"""\bmarshal\.loads?\s*\("""),
        "high",
    ),
    (
        "dill.load(s) (Python)",
        re.compile(r"""\bdill\.loads?\s*\("""),
        "high",
    ),
    (
        "jsonpickle.decode (Python)",
        re.compile(r"""\bjsonpickle\.decode\s*\("""),
        "high",
    ),
    (
        "yaml.load without SafeLoader (Python)",
        re.compile(r"""\byaml\.(?:unsafe_)?load(?:_all)?\s*\((?!.*Safe)""", re.IGNORECASE),
        "high",
    ),
    (
        "numpy.load allow_pickle=True (Python)",
        re.compile(r"""\ballow_pickle\s*=\s*True\b"""),
        "high",
    ),
    (
        "torch.load (pickle-backed) (Python)",
        re.compile(r"""\btorch\.load\s*\("""),
        "medium",
    ),
    (
        "Java/Ruby native deserialization",
        re.compile(r"""\bObjectInputStream\s*\(|\bMarshal\.load\b|\bYAML\.unsafe_load\b"""),
        "high",
    ),
]

# --- Manifest command exec / MCPoison rug-pull (#4) ---
# CVE-2025-54136. An MCP manifest (mcp.json / server.json) whose command/args launch an
# inline interpreter-eval or pipe-to-shell — a mutable config the client re-reads, so a
# swapped command runs on the user's machine. category="dynamic_remote_load" (same
# rug-pull family). Run over the reconstructed "command + args" string, not per-line.
MANIFEST_EXEC_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "MCP manifest command pipes remote fetch to shell",
        re.compile(r"""(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b""", re.IGNORECASE),
        "critical",
    ),
    (
        "MCP manifest shell -c invokes remote fetch",
        re.compile(r"""\b(?:ba)?sh\b[^\n]*-c\b[^\n]*(?:curl|wget|https?://)""", re.IGNORECASE),
        "critical",
    ),
    (
        "MCP manifest runs inline interpreter eval (node -e / python -c)",
        re.compile(
            r"""\b(?:node|deno|bun)\b[^\n]*(?:\s-e\b|--eval\b)|"""
            r"""\bpython3?\b[^\n]*\s-c\b|\bruby\b[^\n]*\s-e\b|\bperl\b[^\n]*\s-e\b""",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "MCP manifest command fetches a remote script",
        re.compile(r"""https?://\S+\.(?:sh|py|js|ts|rb|ps1)\b""", re.IGNORECASE),
        "high",
    ),
    (
        "MCP manifest launches unpinned npx/uvx package",
        re.compile(r"""\b(?:npx|uvx)\s+(?:-y\s+)?(?!.*@)[a-zA-Z@][\w\-/]+"""),
        "medium",
    ),
]

# Dangerous content inside an npm lifecycle install hook (#5).
INSTALL_SCRIPT_DANGER_RE = re.compile(
    r"""(?:curl|wget)\b|\|\s*(?:ba)?sh\b|\bnode\s+(?:-e|--eval)\b|"""
    r"""\bpython3?\s+-c\b|base64\s+(?:-d|--decode|-D)\b|\beval\b|"""
    r"""https?://|\bchmod\s+\+x\b|>\s*/dev/""",
    re.IGNORECASE,
)
# npm lifecycle hooks that auto-run on `npm install` (the supply-chain entry point).
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")

# --- Invisible / smuggled Unicode (hidden-instruction vector) ---
# category="hidden_unicode". Invisible characters in code/config/tool-metadata are a
# prompt-injection smuggling vector: a tool description can carry instructions a human
# reviewer never sees. Tags-block + bidi are essentially always malicious in this context.
INVISIBLE_UNICODE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Unicode Tags block (invisible smuggled instructions)",
        re.compile(r"[\U000e0000-\U000e007f]"),
        "critical",
    ),
    (
        "Bidirectional control character (Trojan Source)",
        re.compile("[\u202a-\u202e\u2066-\u2069]"),
        "high",
    ),
    (
        "Zero-width / invisible character",
        re.compile("[\u200b\u200c\u200d\u2060\u180e]"),
        "medium",
    ),
    (
        "ANSI escape sequence in text (hidden/spoofed content)",
        re.compile(r"\x1b\["),
        "medium",
    ),
]

# --- Prompt injection / tool-description poisoning ---
# category="prompt_injection". Imperative-override or hidden-instruction phrases in tool
# descriptions / manifests / SKILL.md — the #1 agent-tool attack (tool poisoning). The
# scanner now READS metadata instead of only discounting it.
PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Instruction-override phrase",
        re.compile(
            r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?"
            r"|disregard\s+(?:the\s+)?(?:above|previous|prior|earlier|system)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "Hide-from-user directive (tool poisoning)",
        re.compile(
            r"(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show)\s+(?:this\s+)?(?:to\s+)?the\s+user"
            r"|without\s+(?:telling|informing|notifying)\s+the\s+user|hide\s+this\s+from",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "Injected system/role directive",
        re.compile(
            r"<\s*/?\s*(?:system|important|instructions?)\s*>"
            r"|(?:^|[\s\"'])system\s*prompt\s*:"
            r"|you\s+are\s+now\s+(?:a|an|the)?\s"
            r"|your\s+(?:new|real|actual)\s+(?:instructions?|task|role)\s+(?:is|are)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "Exfiltration directive in description",
        re.compile(
            r"send\s+(?:the\s+|all\s+)?(?:secret|api[_\s]?key|token|password|credential|env(?:ironment)?)"
            r"[\w\s,]*?\s+to\s+https?://",
            re.IGNORECASE,
        ),
        "critical",
    ),
    (
        "Mandatory pre-tool action injection",
        re.compile(
            r"before\s+(?:using|calling|running)\s+(?:this|any|the)\s+tool.{0,40}?(?:you\s+must|always|first)",
            re.IGNORECASE,
        ),
        "medium",
    ),
]

# Files that ARE the tool's instruction surface (manifest / skill metadata). Prompt-injection
# and invisible-unicode here are the ATTACK SURFACE, not documentation — scan them + never
# downgrade. (mcp.json/server.json are already scanned via .json; SKILL.md is added here.)
AGENT_METADATA_FILES = frozenset({
    "skill.md", "mcp.json", "server.json", ".mcp.json", "ai-plugin.json", "agents.md",
})

# --- Code obfuscation patterns ---
OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Hex-encoded string execution",
        re.compile(r"""\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}"""),
        "high",
    ),
    (
        "String char-code assembly",
        re.compile(r"""String\.fromCharCode\s*\((?:\s*\d+\s*,\s*){5,}"""),
        "high",
    ),
    (
        "Obfuscated eval (Python)",
        re.compile(r"""getattr\s*\(\s*__builtins__\s*,"""),
        "critical",
    ),
    (
        "Dynamic import with variable",
        re.compile(r"""__import__\s*\(\s*[a-zA-Z_]"""),
        "medium",
    ),
    (
        "Reversed/rotated string decode",
        re.compile(
            r"""(?:reversed|rot13|codecs\.decode)\s*\(.*(?:exec|eval|import)""",
            re.IGNORECASE,
        ),
        "high",
    ),
]

# --- Auth/security positive signals ---
# These REDUCE risk when found.
AUTH_POSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Authentication check", re.compile(
        r"(?:authenticate|verify_token|check_auth|requireAuth|isAuthenticated)",
        re.IGNORECASE,
    )),
    ("Authorization check", re.compile(
        r"(?:authorize|check_permission|has_role|requireRole)",
        re.IGNORECASE,
    )),
    ("Input validation", re.compile(
        r"(?:validate|sanitize|escape|zod\.object|pydantic|BaseModel)",
        re.IGNORECASE,
    )),
    ("Rate limiting", re.compile(r"(?:rate.?limit|throttle|RateLimiter)", re.IGNORECASE)),
    ("CORS configuration", re.compile(r"(?:cors|Access-Control-Allow)", re.IGNORECASE)),
    ("Content-Security-Policy", re.compile(r"Content-Security-Policy", re.IGNORECASE)),
    ("Helmet / security headers", re.compile(r"(?:helmet|security.?headers)", re.IGNORECASE)),
    ("Cryptographic verification", re.compile(
        r"(?:hmac|hashlib\.(?:sha|md5)|cryptography\.|jwt\.(?:encode|decode|verify)|verify_signature)",
        re.IGNORECASE,
    )),
    ("Input sanitization", re.compile(
        r"(?:html\.escape|urllib\.parse\.quote|bleach\.clean|markupsafe|nh3\.clean|DOMPurify)",
        re.IGNORECASE,
    )),
    ("Logging / audit trail", re.compile(
        r"(?:logging\.getLogger|logger\.(?:info|warning|error)|audit_log|structlog)",
        re.IGNORECASE,
    )),
    ("Error handling", re.compile(
        r"(?:try\s*:|except\s+\w|\.catch\s*\(|error\s*boundary|rescue\s+)",
        re.IGNORECASE,
    )),
    ("Type safety", re.compile(
        r"(?:from\s+typing\s+import|TypeVar|Generic\[|pydantic\.BaseModel|@dataclass|interface\s+\w+\s*\{)",
        re.IGNORECASE,
    )),
    ("Dependency pinning", re.compile(
        r"(?:requirements\.txt|poetry\.lock|package-lock\.json|Pipfile\.lock|Cargo\.lock)",
        re.IGNORECASE,
    )),
]

# --- Files to skip (binary, generated, vendor) ---
SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".lock", ".sum",
    ".min.js", ".min.css",
})

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "dist", "build",
    "vendor", ".venv", "venv", "env", ".env",
    "target", "coverage", ".next", ".nuxt",
})

# Source file extensions to scan
SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".rb", ".java", ".kt", ".cs",
    ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".toml", ".json", ".env",
    ".cfg", ".ini", ".conf",
    # Additional languages and formats with executable content
    ".php", ".pl", ".pm", ".lua", ".r", ".scala", ".groovy",
    ".swift", ".m", ".ps1", ".bat", ".cmd", ".vbs",
    ".html", ".htm", ".xml", ".svg",  # can contain inline scripts
    ".ipynb",  # Jupyter notebooks contain executable code
})

# Extensionless files that should always be scanned
EXTENSIONLESS_SCAN_FILES = frozenset({
    "Dockerfile", "Makefile", "Rakefile", "Gemfile",
    "Vagrantfile", "Procfile", "Brewfile",
    "Jenkinsfile", "Snakefile",
})
