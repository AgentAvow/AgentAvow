# Verdict accuracy audit: 36 "Do not connect" tools (2026-11-14)

The static corpus gate (the top ~400 registry packages) is green, so the false positives
that are left sit in the long tail that the catalog and Trust Index actually show. This
audit took the most-adopted tools currently reading **Do not connect**, read every
critical finding that produced the verdict in the package or repo source, and judged
whether the verdict is right.

**Headline:** 33 of the 36 sampled tools still read Do not connect on a live re-check.
Of those 33, **21 are false positives (64%)**, 11 are true positives and 1 is unclear.
The biggest false-positive class by far is **install commands that are shown to a person
and never run**: 9 of the 21 false positives come from it. That class has no narrow fix
(see [Follow-ups](#follow-ups)). The PR that adds this doc also fixes the narrowest class
with the most adoption behind it: **install hooks that only silence their output**,
which made yarn 1.22.22 (12.7M downloads a week, the second most-adopted tool on the
list) read Do not connect.

## Method

1. **Population.** `GET /api/v1/public/scan-catalog?decision=do_not_connect&sort=adoption`
   on agentavow.com, read in pages of 50 (sequential, 3 s apart; no 429s). It reported
   644 tools reading Do not connect out of 59,237 scans.
2. **Sample.** The top 36 by adoption, after merging duplicates (the npm and GitHub
   rows of the same project, e.g. `npm:claude-mem` and `thedotmack/claude-mem`, or
   `pypi:serena-agent` and `oraios/serena`, count once).
3. **Live findings.** For each tool, one sequential request to the public scan endpoint
   (`/api/v1/public/scan/package/{surface}/{name}` for npm / PyPI,
   `/api/v1/public/scan/{owner}/{repo}` otherwise), honouring the 202 `retry_after`.
   No authenticated or admin endpoint was used. The response carries every finding's
   rule, severity, file and line.
4. **Source check.** Every critical finding behind the verdict was read at its file and
   line: the npm tarball or PyPI archive of the scanned version, or the GitHub file at
   `main`, each downloaded into a fresh directory under `/tmp`. Nothing was installed or
   executed. Where `main` had moved past the scanned line, the finding was located by
   its content.
5. **Judgement.** We judged each tool's *verdict*, not each finding. **TP** means at
   least one critical is real under the scanner's documented rules. **FP** means no
   critical holds up. **Unclear** means it depends on a policy call. "TP (by policy)"
   marks cases that follow the documented rule. That rule is critical for an agent
   instruction that pipes an unpinned, non-allowlisted URL to a shell, including the
   project's own host (`src/scanner/pipe_shell.py`).

## Results

| # | Tool (adoption) | Live verdict | Rule(s) behind it | Judgement | Reason |
|---|---|---|---|---|---|
| 1 | pypi:huggingface_hub (63.5M/wk) | Review (catalog: DNC) | curl\|sh, hf CLI installer | stale row | The live scan lowers the official `hf.co/cli/install.sh` installer to high (round-3 allowlist). The catalog row predates that change |
| 2 | npm:yarn 1.22.22 (12.7M/wk) | DNC | npm `preinstall` (remote/shell/eval) | **FP** | `:; (node ./preinstall.js > /dev/null 2>&1 \|\| true)`: `> /dev/null` matched the `>\s*/dev/` danger token. The local script only removes a Corepack symlink. **Fixed in this PR** |
| 3 | pypi:av 19.0.2 (12.4M/wk) | DNC | Obfuscated eval (Python) | **FP** | `av/error.py:199` `getattr(__builtins__, name, OSError)` looks up builtin exception classes from a static table |
| 4 | npm:@earendil-works/pi-coding-agent 1.5.2 (6.2M/wk) | DNC | curl\|sh ×2 | **FP** | `dist/package-manager-cli.js:1065`: an installer hint held in a variable and `console.log`ged. The printed-hint walk gives up because an unrelated bundled worker defines `const console = {}` |
| 5 | npm:@mastra/core 1.83.0 (3.2M/wk) | DNC | Outbound webhook/exfil URL ×2 | **FP** | `dist/test-utils/llm-mock.js:10529` `"ngrok.io",` inside a bundled public-suffix list. The file also holds code, so the domain-list exemption does not apply |
| 6 | pypi:browser-use 1.0.4 (2.1M/wk) | DNC | Whole environment sent outbound | **FP** | `harness_cloud.py:170` `merged = {**os.environ, **env}` is only read by key. Line 202 is a TCP connect probe; the env is never sent |
| 7 | npm:hyperframes 0.9.46 (1.3M/wk) | DNC | remote-fetch prompt, `node -e`, env outbound | **FP** | `fetch("summary", children)` is a local RSS-parser helper that happens to be named `fetch`. The `node -e` template interpolates only a constant PostHog URL. `warmCheckClient.js:99` sends an HMAC `envDigest` over a local socket |
| 8 | pypi:ultralytics 8.4.212 (1.2M/wk) | DNC | curl\|sh | TP | `data/scripts/get_imagenet.sh:45`: `wget -qO- https://raw.githubusercontent.com/soumith/imagenetloader.torch/master/valprep.sh \| bash`. An unpinned third-party script piped to bash in a shipped script |
| 9 | pypi:mitmproxy 12.3.1 (742k/wk) | DNC | Unicode Tags block ×3, Private Key block | **FP** | `utils/emoji.py`: England / Scotland / Wales flags written with a ZWJ between the tag characters, which the well-formed tag-sequence exemption does not match. `certs.py:78`: an all-zero dummy EC key in a cert-chain constant |
| 10 | openclaw/openclaw (394k) | DNC | curl\|sh | **FP** | `node-version.mjs:32`: an error-message line in an exported formatter (`[...].join("\n")`). Repo scans do not follow exported names, so the printed-hint lowering does not apply |
| 11 | npm:@oh-my-pi/pi-coding-agent 18.20.0 (267k/wk) | DNC | curl\|sh, Private Key block | TP | The cited curl\|sh (`update-cli.ts:2085`, a recovery-hint string) is FP. But `src/cli/claude-trace-cli.ts:50` ships a real RSA private key for its local TLS-intercepting debug proxy |
| 12 | thedotmack/claude-mem (101k) | DNC | curl\|sh in agent instructions ×4 | TP (by policy) | `openclaw/SKILL.md:10-32` tells agents to run `curl -fsSL https://install.cmem.ai/openclaw.sh \| bash` |
| 13 | npm:@agent-native/core 0.228.2 (88k/wk) | DNC | Outbound webhook/exfil URL ×5 | **FP** | `vite/client.js:3991`: `allowedHosts: options.allowedHosts ?? userConfig… ?? [".ngrok.io", …]` (the `??` chain is not read as an allowlist, and the bundle has sinks). `provider-api/custom-registry.js:151`: a host-suffix `Set` used for validation |
| 14 | HKUDS/CLI-Anything (59k) | DNC | curl\|sh in data file + SKILL.md | TP | `public_registry.json:312` `install_cmd: "curl -s https://jimeng.jianying.com/cli \| bash"` is executed by `cli_hub/installer.py` (`_run_command`, shell=True) |
| 15 | tashfeenahmed/freellmapi (50k) | DNC | curl\|sh ×3 | **FP** | `cli/src/tools.ts:702/857/929`: strings in a `notes: [...]` array shown to the user ("Install MiMo Code with: curl … \| bash") |
| 16 | pypi:serena-agent 2.1.0 / oraios/serena (40k/wk) | DNC | Remote pickle load from response | TP | `project_server.py:277` `pickle.loads(response.content)` from a 127.0.0.1 project server. The client never authenticates the server, so any local process that holds the port gets code execution. The severity is arguable |
| 17 | npm:@open-mercato/cezar 0.19.0 (32k/wk) | DNC | Outbound webhook/exfil URL ×2 | **FP** | `server-install/platforms/macosx-ngrok.js:99/102`: `cezar.ngrok.app` is the placeholder and example text of a prompt in an ngrok-setup wizard |
| 18 | milind-soni/OpenMausBot (21k) | DNC | curl\|sh ×2 | **FP** | `connector/install.sh:52`, `deploy/install.sh:71`: `command_line()` printfs the re-run command, and every caller is `$(command_line …)` inside a `say` / `fail` message. The shell-shown check keeps the critical whenever a function's output is captured |
| 19 | coder/coder (17k) | DNC | curl\|sh ×2 | **FP** | `cli/root.go:1678/1746` `fmt.Sprintf("download the server version with: 'curl -fsSL …/install.sh \| sh …'")` is upgrade-message text. Go has no printed-hint walk |
| 20 | npm:@openrig/cli 0.7.15 (8.6k/wk) | DNC | curl\|sh | TP | `dist/commands/setup.js:72` `HERDR_INSTALL_COMMAND = "curl -fsSL https://herdr.dev/install.sh \| sh"` is executed by `installCommand()` during `rig setup` |
| 21 | mutonby/openshorts (7.9k) | DNC | Whole environment sent outbound | **FP** | `worker.py` `job_env()` = `dict(os.environ)` minus the worker token, passed as `env=` to the local job subprocess. Never sent over HTTP |
| 22 | builderz-labs/mission-control (6.5k) | DNC | npm `postinstall` (remote/shell/eval) | **FP** | `node -e "try{require('better-sqlite3')}catch(e){… console.error('…Run: pnpm rebuild better-sqlite3'); process.exit(1)}"` is a native-module ABI check that prints a hint |
| 23 | ZJU-REAL/Easel (4.7k) | Safe (catalog: DNC) | none | stale row | The live scan finds no critical or high in its code |
| 24 | firebase/firebase-tools (4.5k) | DNC | curl\|sh ×2 | **FP** | `firebase-vscode/package.json:222` is the maintainer's `pretest:e2e` script in a nested sub-package. `firebase-vscode/src/extension.ts:121` builds a "to install it, run …" message shown in VS Code |
| 25 | Ataraxy-Labs/sem (3.4k) | DNC | curl\|sh ×2 | **FP** | `crates/sem-cli/src/commands/update.rs:240/254` `format!("… or reinstall:\n  curl -fsSL …/install.sh \| sh")` is error text. Rust has no printed-hint walk |
| 26 | miaoxworld/OpenClawInstaller (3.4k) | DNC | curl\|sh | **FP** | `config-menu.sh:5270` `echo "  curl -fsSL ${INSTALLER_RAW_URL}/install.sh \| bash"` under a "to reinstall:" heading. It is printed and never run |
| 27 | mengjian-github/openclaw101 (3.0k) | DNC | curl\|sh ×2 | **FP** | `src/components/StartSetupPage.tsx:50/95` `command: 'curl -fsSL https://openclaw.ai/install.sh \| bash'` is copy on a tutorial web page |
| 28 | qingchencloud/clawpanel (2.9k) | DNC | curl\|sh ×6 + 2 others | TP | `src-tauri/src/commands/extensions.rs:456` runs `bash -c` on a script that pipes `raw.githubusercontent.com/qingchencloud/clawapp/main/install.sh` to bash. Its `mirror-urls.js` / `setup.js` hits are display strings |
| 29 | K-Dense-AI/claude-scientific-writer (2.6k) | DNC | curl\|sh in agent instructions ×3 | unclear | `skills/literature-review/SKILL.md:224`: `curl -fsSL https://parallel.ai/install.sh \| bash`. Critical by policy; it would be Review if parallel.ai is confirmed as an official installer and allowlisted |
| 30 | digitalsamba/claude-code-video-toolkit (2.5k) | Review (catalog: DNC) | none | stale row | The live scan has 4 high and no critical |
| 31 | zzet/gortex (2.1k) | DNC | curl\|sh | TP (by policy) | `cmd/gortex/upgrade.go:102`: `gortex upgrade --run` executes `curl -fsSL https://get.gortex.dev \| sh` via `sh -c`. A self-update from the vendor's own host, which the documented rule keeps critical |
| 32 | openakita/openakita (2.0k) | DNC | curl\|sh in agent instructions ×2 | TP (by policy) | `skills/dingtalk-cli/SKILL.md:22/123` pipes a third-party `…/main/scripts/install.sh` to `sh` |
| 33 | stripe/agent-toolkit (1.9k) | DNC | curl\|sh in agent instructions ×12 | **FP** | Stripe's own skills (`skills/stripe-directory/SKILL.md:58`, `stripe-projects/SKILL.md:41`, plus plugin copies) install Stripe's own CLI with `curl -fsSL https://cli.stripe.com/install.sh \| sh`. This is the official-vendor-installer case the allowlist exists for (it should read Review) |
| 34 | mims-harvard/ToolUniverse (1.8k) | DNC | curl\|sh in agent instructions ×2, obfuscated eval | TP (by policy) | `skills/tooluniverse-connect/SKILL.md:42/45` pipes `https://connect.aiscientist.tools/skills.sh` to `sh`. The obfuscated-eval hit (`python_executor_tool.py:360`, `getattr(__builtins__, name)` building a sandbox allowlist) is FP |
| 35 | pypi:agent-audit 0.20.0 (1.8k/wk) | DNC | curl\|sh in a data file | **FP** | `rules/builtin/agent_architecture_security_v016.yaml:623` is a `# BAD:` example inside a security rule's description |
| 36 | miaoxworld/openclaw-manager (1.6k) | DNC | curl\|sh ×2 | TP | `src-tauri/src/commands/installer.rs:467/471` runs `curl -fsSL https://deb.nodesource.com/setup_22.x \| sudo -E bash -` through `shell::run_bash_output` |

### Rates

| | Count |
|---|---|
| Sampled | 36 |
| Catalog row stale (the live scan no longer reads Do not connect) | 3 (8%) |
| Live Do not connect | 33 |
| True positive | 11 (4 of them by policy) |
| Unclear | 1 |
| **False positive** | **21 of 33 = 64%** (67% if the unclear one is counted) |

Weighted by the catalog's `adoption_count` (weekly downloads for packages, stars or
installs for repos), the 21 false positives sum to about 39.4M and the 11 true
positives to about 1.7M. Most of the FP weight is yarn (12.7M), av (12.4M),
pi-coding-agent (6.2M), mastra (3.2M) and browser-use (2.1M); most of the TP weight is
ultralytics (1.2M).

## False-positive classes, ranked by tools hit

Counts are FP verdicts in the sample. Classes that also misfire inside a TP tool are
noted, but those tools are not counted.

| Rank | Class | FP tools | Tools | Cause |
|---|---|---|---|---|
| 1 | **Install command shown to a person, never run** (`curl … \| sh` rule) | 9 | pi-coding-agent, openclaw, freellmapi, OpenMausBot, coder, firebase-tools, sem, OpenClawInstaller, openclaw101 (+ the cited hits in oh-my-pi and clawpanel) | The printed-hint walk (`printed_hint.py`) covers JS/TS/Python only and gives up conservatively: a package-wide `console` shadow (pi), exported names in a repo scan (openclaw), namespace imports (oh-my-pi). The shell-shown check (`shown_text.py`) keeps the critical when a function's output is captured (OpenMausBot) or on long scripts (OpenClawInstaller). Go and Rust have no walk (coder, sem). Strings in data or UI structures are not covered (freellmapi `notes`, openclaw101 page props) |
| 2 | **Tunnel / collector host named as data, not a destination** (Outbound webhook/exfil URL) | 3 | @mastra/core, @agent-native/core, cezar | A public-suffix list inside a bundle with other code, a `??`-chained `allowedHosts` default and a validation suffix set, and an ngrok wizard's placeholder text. The existing exemptions require a file with no network sink anywhere, which bundles never are |
| 2 | **Whole environment "sent outbound" when it stays local** | 3 | browser-use, openshorts, hyperframes | The env is copied for a key lookup or a child process's `env=`, or only a keyed digest is sent over a local socket. Meanwhile an unrelated network call sits nearby |
| 4 | **Install-hook danger regex on benign shell idioms** (npm lifecycle "runs remote/shell/eval content") | 2 | yarn, mission-control | `> /dev/null` / `2>/dev/null` matched `>\s*/dev/`. Constant banners with a `\n` escape were not recognised as inert. In the full 644-tool population, 15 Do-not-connect verdicts cite only an install hook, and 6 of them are cleared by this PR's fix (below) |
| 5 | `getattr(__builtins__, …)` read as obfuscated eval | 1 | av (+ ToolUniverse's hit) | Exception-class lookup and sandbox allowlist building |
| 5 | Unicode Tags in emoji flags, dummy private key | 1 | mitmproxy | Flag tag sequences with an interleaved ZWJ; an all-zero placeholder key |
| 5 | Official vendor installer missing from `VENDOR_INSTALLERS` | 1 | stripe/agent-toolkit (+ K-Dense, unclear) | `cli.stripe.com/install.sh` is Stripe's own installer in Stripe's own skill |
| 5 | Example text in a security tool's rule data | 1 | agent-audit | A `# BAD:` sample in a YAML rule description |

Minor contributors inside the tools above: an identifier collision (a local helper named
`fetch`, hyperframes), a constant-template `node -e` telemetry flush (hyperframes) and a
maintainer `pretest:e2e` script in a nested `package.json` (firebase-tools).

## Fix shipped with this audit

Class 1 hits the most tools, but it has no narrow fix. Each sub-cause is its own analysis
(new language walks, a scoped console-shadow check, captured-output tracking in shell).
Class 4 is narrow, it carries the most adoption of any class (yarn alone outweighs every
class-1 tool combined), and it can be proven with fixtures:

* `INSTALL_SCRIPT_DANGER_RE` (`src/scanner/patterns.py`): a redirect to `/dev/null`,
  `/dev/stdout` or `/dev/stderr` no longer counts as danger. Any other device still
  does, and so does `>& /dev/tcp/…` now: the old `>\s*/dev/` missed `>&`.
* `_INERT_NODE_SNIPPET_RE` (`src/scanner/scan.py`): a constant
  `console.log/warn/error('…')` banner may contain the simple escapes `\n \t \r \' \\`.
  `\u` / `\x` escapes, `$` and backticks keep the critical
  (`tests/test_r2_lifecycle_dev_datasets.py` already pins `eval`).

Effect: such a hook is the medium "auto-runs on install" signal again. A local scan of
the yarn 1.22.22 tarball goes from Do not connect (45) to Safe (82). Among the 15
install-hook-only Do-not-connect verdicts in the population, the fix clears yarn,
verygoodplugins/mcp-evernote, gokhantos/opencrow, teampolarity/cosmos-mcp,
Intina47/context-sync and thatsrajan/vidlens-mcp.
`tests/test_install_hook_quiet_redirect.py` pins those hooks verbatim and proves recall:
`/dev/tcp`, `/dev/udp`, `/dev/sda`, `/dev/null_evil`, `/dev/null/../tcp/…`, a quiet
redirect next to curl / wget / eval, and non-constant or `\u`-encoded banners all stay
critical.

## Follow-ups

Ranked by expected yield. None is narrow enough to ship blind.

1. **Shown-install-hint coverage (class 1).** Start with the cheapest sub-causes:
   (a) Go `fmt.Sprintf` / `fmt.Errorf` and Rust `format!` / `eprintln!` strings whose
   value only reaches an error or print (2 tools); (b) scope the `console`-shadow guard
   to bindings that are reachable from the hint's file rather than the whole package
   (pi-coding-agent, 6.2M/wk); (c) in shell, treat `$(f …)` captured into an argument of
   a print-only function as shown (OpenMausBot).
   **Status: addressed** by "Scanner: install commands only shown to a person are not
   critical (audit class 1)". 7 of the 9 tools no longer read Do not connect on a local
   static re-scan (openclaw, freellmapi, coder, sem, OpenClawInstaller: Safe;
   OpenMausBot, openclaw101: Review on unrelated high findings). Two remain. pi-coding-agent:
   the vendored SDKs in its CLI bundle pass `console` around as a logger value
   (`this._logger = console`, `filterLogger(console, …)`), and proving that harmless needs
   alias analysis. firebase-tools: its other critical is a maintainer `pretest:e2e`
   script, not a shown hint.
2. **Exfil host as data in bundles (class 2).** Allow the existing domain-list test on a
   contiguous run of 200+ bare-host elements inside a larger file, and read
   `allowedHosts: a ?? b ?? [ … ]` defaults as an allowlist.
3. **Env-to-subprocess (class 2b).** `dict(os.environ)` / `{**os.environ}` that only
   reaches `subprocess.*(env=…)` or `.get(` lookups should not be "sent outbound".
4. **Remaining install-hook cases:** a `node -e` native-module ABI check
   (mission-control), `https://` inside an `echo` message (obsidian-brain), `\"` inside
   a constant banner (namecheap-mcp), `import('./dist/postinstall.js')` (prism-mcp ×2).
5. **Allowlist review:** `cli.stripe.com/install.sh` (Stripe CLI) and, once checked
   against vendor docs, `parallel.ai/install.sh`.
6. **Catalog staleness:** 3 of 36 rows (huggingface_hub, Easel, claude-code-video-toolkit)
   read Do not connect in the catalog while a live scan says Review or Safe. The
   Do-not-connect list should re-derive from the latest scan.
