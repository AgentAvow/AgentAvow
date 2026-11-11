/**
 * Scan-category registry — the single source of truth mapping every backend
 * finding `category` key to its human display (label / icon / description / sub-score
 * family) and to the detection category it rolls up into. New scanner categories MUST
 * be added here so they render with a proper label instead of a raw key.
 *
 * Two levels, mirroring the backend:
 * - SCAN_CATEGORIES is keyed by the RAW finding `category` (what a finding carries, e.g.
 *   `unsafe_exec`, `lethal_trifecta`); families mirror `_calculate_category_scores` in
 *   src/scanner/scan.py.
 * - DETECTION_CATEGORIES is the canonical list of 14 detection categories a person would
 *   name, a TS twin of src/scanner/categories.py. Each raw key rolls up into exactly one
 *   (`detectionCategoryFor`). tests/test_detection_categories_ts_twin.py pins the two.
 */

export type ScoreFamily =
  | 'secret_hygiene'
  | 'code_safety'
  | 'data_handling'
  | 'filesystem_access'
  | 'dependency_health'

export interface CategoryInfo {
  key: string
  label: string
  icon: string
  description: string
  family: ScoreFamily
  /** Detection category id (src/scanner/categories.py) this raw key rolls up into;
   *  `other` for an unknown key, as the backend reports it. */
  detection: DetectionCategoryId | 'other'
}

export type DetectionCategoryId =
  | 'secrets'
  | 'code_execution'
  | 'obfuscation'
  | 'prompt_injection'
  | 'remote_code_load'
  | 'data_exfiltration'
  | 'toxic_flow'
  | 'network_endpoints'
  | 'filesystem_access'
  | 'dependencies'
  | 'install_hooks'
  | 'tool_definition'
  | 'artifact_integrity'
  | 'runtime_robustness'

export interface DetectionCategory {
  id: DetectionCategoryId
  name: string
  description: string
  /** False for a category only the behavioral sandbox can produce. */
  static: boolean
}

// The 14 detection categories, in canonical order (twin of src/scanner/categories.py).
export const DETECTION_CATEGORIES: DetectionCategory[] = [
  { id: 'secrets', name: 'Exposed secrets', static: true,
    description: 'API keys, tokens, passwords or private keys written into the code or config.' },
  { id: 'code_execution', name: 'Unsafe code execution', static: true,
    description: 'Shell or eval execution of input, unsafe deserialization, and git configs that run commands on ordinary git operations.' },
  { id: 'obfuscation', name: 'Obfuscated or hidden code', static: true,
    description: 'Encoded, packed or bytecode-only code, and invisible or bidi Unicode that hides text from a human reviewer.' },
  { id: 'prompt_injection', name: 'Prompt injection', static: true,
    description: 'Instruction-override or hidden-directive text in tool descriptions, metadata, skill prose or tool results, aimed at the model that reads it.' },
  { id: 'remote_code_load', name: 'Remote code loading (rug-pull)', static: true,
    description: 'Code, config or tool definitions fetched from a mutable remote source that can change after you approved the tool.' },
  { id: 'data_exfiltration', name: 'Data exfiltration', static: true,
    description: 'Credentials or local data sent to an outbound endpoint.' },
  { id: 'toxic_flow', name: 'Toxic flows (lethal trifecta)', static: true,
    description: 'Private-data access, untrusted input and an outbound send combined in one tool, the prompt-injection-to-exfiltration chain.' },
  { id: 'network_endpoints', name: 'Network and endpoint safety', static: true,
    description: 'Caller-supplied URLs fetched unchecked (SSRF), plain-HTTP or private-address endpoints, cross-site endpoints, and weak or missing auth schemes.' },
  { id: 'filesystem_access', name: 'Filesystem access', static: true,
    description: 'Unsandboxed reads and writes, path traversal, and recursive deletes.' },
  { id: 'dependencies', name: 'Dependencies and advisories', static: true,
    description: 'Dependencies with known vulnerabilities, published advisories against the package itself, and deprecated or yanked releases.' },
  { id: 'install_hooks', name: 'Install and lifecycle hooks', static: true,
    description: "Scripts that run on install or around a skill's invocation without being called (npm pre/postinstall, skill hook manifests)." },
  { id: 'tool_definition', name: 'Tool and skill definition', static: true,
    description: 'Risky input schemas, annotations that misstate what a tool does, and skill permission grants that differ from what the shipped code does.' },
  { id: 'artifact_integrity', name: 'Artifact integrity', static: true,
    description: 'A published package that differs from its source repo, and agent cards whose signature does not verify.' },
  { id: 'runtime_robustness', name: 'Runtime robustness', static: false,
    description: 'A tool call that crashes the server or a read-only tool that fails on a read, seen only when the behavioral sandbox runs the tool.' },
]

// Every raw backend finding category (src/scanner/categories.py lists them under the
// 14 detection categories). The first twelve are ordered roughly by how agent-native /
// novel the threat is; the rest follow in detection-category order.
export const SCAN_CATEGORIES: Record<string, CategoryInfo> = {
  secret: {
    key: 'secret',
    label: 'Hardcoded Secret',
    icon: '🔑', // 🔑
    description: 'Credentials, API keys, or tokens committed directly in source.',
    family: 'secret_hygiene',
    detection: 'secrets',
  },
  prompt_injection: {
    key: 'prompt_injection',
    label: 'Prompt Injection',
    icon: '💉', // 💉
    description:
      'Instruction-override / hidden-directive text in a tool description or manifest — poisons the agent that reads the tool.',
    family: 'code_safety',
    detection: 'prompt_injection',
  },
  dynamic_remote_load: {
    key: 'dynamic_remote_load',
    label: 'Rug-Pull / Remote Load',
    icon: '🎣', // 🎣
    description:
      'Fetches code, config, or tool definitions from a mutable remote source that can be swapped after you integrate it.',
    family: 'code_safety',
    detection: 'remote_code_load',
  },
  toxic_flow: {
    key: 'toxic_flow',
    label: 'Lethal Trifecta',
    icon: '☠️', // ☠️
    description:
      'Combines private-data access, untrusted-input ingestion, and outbound send — the prompt-injection → exfiltration chain.',
    family: 'data_handling',
    detection: 'toxic_flow',
  },
  hidden_unicode: {
    key: 'hidden_unicode',
    label: 'Hidden Unicode',
    icon: '👻', // 👻
    description:
      'Invisible, bidi, or tag Unicode that can smuggle instructions a human reviewer never sees.',
    family: 'code_safety',
    detection: 'obfuscation',
  },
  insecure_deserialization: {
    key: 'insecure_deserialization',
    label: 'Insecure Deserialization',
    icon: '🧬', // 🧬
    description:
      'Deserializes untrusted data (pickle / marshal / yaml.load) that can execute arbitrary code.',
    family: 'code_safety',
    detection: 'code_execution',
  },
  install_hook: {
    key: 'install_hook',
    label: 'Install Hook',
    icon: '⛓️', // ⛓️
    description:
      'npm pre/post-install lifecycle script that auto-runs on install — a top supply-chain vector.',
    family: 'dependency_health',
    detection: 'install_hooks',
  },
  unsafe_exec: {
    key: 'unsafe_exec',
    label: 'Unsafe Execution',
    icon: '⚠️', // ⚠️
    description: 'Dynamic or shell code execution (subprocess, eval/exec, shell=True).',
    family: 'code_safety',
    detection: 'code_execution',
  },
  exfiltration: {
    key: 'exfiltration',
    label: 'Data Exfiltration',
    icon: '📡', // 📡
    description: 'Sensitive data sent to an outbound or known-exfil endpoint.',
    family: 'data_handling',
    detection: 'data_exfiltration',
  },
  fs_access: {
    key: 'fs_access',
    label: 'Filesystem Access',
    icon: '📁', // 📁
    description: 'Unsandboxed file read/write, path traversal, or recursive delete.',
    family: 'filesystem_access',
    detection: 'filesystem_access',
  },
  obfuscation: {
    key: 'obfuscation',
    label: 'Code Obfuscation',
    icon: '🕵️', // 🕵️
    description: 'Obfuscated or encoded code that hides what it actually does.',
    family: 'code_safety',
    detection: 'obfuscation',
  },
  dependency: {
    key: 'dependency',
    label: 'Vulnerable Dependency',
    icon: '📦', // 📦
    description: 'Depends on a package version with a known CVE.',
    family: 'dependency_health',
    detection: 'dependencies',
  },
  git_autorun: {
    key: 'git_autorun',
    label: 'Git Config Autorun',
    icon: '⚙️',
    description: 'A git config or hook that runs commands on ordinary git operations (clone, checkout, fetch).',
    family: 'code_safety',
    detection: 'code_execution',
  },
  lethal_trifecta: {
    key: 'lethal_trifecta',
    label: 'Lethal Trifecta (server)',
    icon: '☠️',
    description: 'A server whose tools together read private data, take untrusted input and send outbound.',
    family: 'data_handling',
    detection: 'toxic_flow',
  },
  ssrf: {
    key: 'ssrf',
    label: 'Server-Side Request Forgery',
    icon: '🌐',
    description: 'A caller-supplied URL reaches an outbound request without validation.',
    family: 'data_handling',
    detection: 'network_endpoints',
  },
  insecure_transport: {
    key: 'insecure_transport',
    label: 'Insecure Transport',
    icon: '🔓',
    description: 'A plain-HTTP or private-address endpoint.',
    family: 'data_handling',
    detection: 'network_endpoints',
  },
  endpoint_origin: {
    key: 'endpoint_origin',
    label: 'Cross-Site Endpoint',
    icon: '🧭',
    description: 'An endpoint on a different site from the one that publishes the tool.',
    family: 'data_handling',
    detection: 'network_endpoints',
  },
  auth_scheme: {
    key: 'auth_scheme',
    label: 'Weak Auth Scheme',
    icon: '🪪',
    description: 'A weak or missing authentication scheme on an endpoint.',
    family: 'secret_hygiene',
    detection: 'network_endpoints',
  },
  data_handling: {
    key: 'data_handling',
    label: 'Data Handling',
    icon: '🗂️',
    description: 'How the tool treats data it receives or sends.',
    family: 'data_handling',
    detection: 'network_endpoints',
  },
  known_vulnerability: {
    key: 'known_vulnerability',
    label: 'Published Advisory',
    icon: '🚨',
    description: 'A published advisory against the package itself that affects the scanned version.',
    family: 'code_safety',
    detection: 'dependencies',
  },
  maintenance: {
    key: 'maintenance',
    label: 'Deprecated Release',
    icon: '🪦',
    description: 'The maintainer deprecated or yanked this release, or marked the project inactive.',
    family: 'dependency_health',
    detection: 'dependencies',
  },
  skill_hook: {
    key: 'skill_hook',
    label: 'Skill Hook',
    icon: '🪝',
    description: "A skill hook manifest that runs scripts around the skill's invocation without being called.",
    family: 'dependency_health',
    detection: 'install_hooks',
  },
  schema_risk: {
    key: 'schema_risk',
    label: 'Risky Input Schema',
    icon: '📐',
    description: 'A tool input schema that invites dangerous arguments (raw commands, paths, URLs).',
    family: 'code_safety',
    detection: 'tool_definition',
  },
  annotation_lie: {
    key: 'annotation_lie',
    label: 'Misstated Annotation',
    icon: '🎭',
    description: 'A tool annotation that misstates what the tool does (for example read-only on a tool that writes).',
    family: 'code_safety',
    detection: 'tool_definition',
  },
  skill_capability: {
    key: 'skill_capability',
    label: 'Skill Permission Mismatch',
    icon: '📝',
    description: "A skill's declared permissions differ from what its shipped code does.",
    family: 'code_safety',
    detection: 'tool_definition',
  },
  artifact_drift: {
    key: 'artifact_drift',
    label: 'Artifact Drift',
    icon: '🧩',
    description: 'The published package differs from its source repo (injected or modified files).',
    family: 'code_safety',
    detection: 'artifact_integrity',
  },
  card_signature: {
    key: 'card_signature',
    label: 'Agent Card Signature',
    icon: '✍️',
    description: 'An A2A Agent Card whose signature does not verify.',
    family: 'code_safety',
    detection: 'artifact_integrity',
  },
  robustness: {
    key: 'robustness',
    label: 'Runtime Robustness',
    icon: '💥',
    description: 'A tool call crashed the server, or a read-only tool failed on a read (behavioral sandbox).',
    family: 'code_safety',
    detection: 'runtime_robustness',
  },
}

/** Look up a category, with a graceful fallback for any unknown/new key. */
export function getCategoryInfo(key: string): CategoryInfo {
  return (
    SCAN_CATEGORIES[key] ?? {
      key,
      label: key
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase()),
      icon: '🔍', // 🔍
      description: 'Security finding.',
      family: 'code_safety',
      detection: 'other',
    }
  )
}

/** The detection category a raw finding `category` rolls up into, or undefined for an
 *  unknown key (the backend reports those as `other`). */
export function detectionCategoryFor(key: string): DetectionCategory | undefined {
  const id = SCAN_CATEGORIES[key]?.detection
  return id ? DETECTION_CATEGORIES.find((c) => c.id === id) : undefined
}

// The five sub-score axes the scanner reports (category_scores), with display labels.
export const SUBSCORE_LABELS: Record<ScoreFamily, string> = {
  secret_hygiene: 'Secret Hygiene',
  code_safety: 'Code Safety',
  data_handling: 'Data Handling',
  filesystem_access: 'Filesystem Access',
  dependency_health: 'Dependency Health',
}

export const SUBSCORE_ORDER: ScoreFamily[] = [
  'secret_hygiene',
  'code_safety',
  'data_handling',
  'filesystem_access',
  'dependency_health',
]
