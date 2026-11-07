"""A raw wallet signing key sent over the network.

``gadgethumans-mcp`` (Knostic, 2026-09-08) read ``WALLET_PRIVATE_KEY`` and put it in an
``X-402-Wallet`` request header. The env-secret flow rule (``skill_key_flow``) only runs
on skills, and it can't simply run on packages: a package sending its own ``FOO_API_KEY``
to foo.com is normal capability. A signing key is different. It signs on this machine;
what leaves is a signature or an address. No host is its "own vendor", so that excuse
does not apply here, and a key name that names the vendor buys nothing.

So this rule is narrow on purpose:

* SOURCE: an env var with a wallet signing-key NAME (``is_signing_key_name``). The name
  only ever raises a finding. A bland name (``X402_AUTH``) is a known gap, not a relaxation.
* SINK: the raw value, or a string built from it, reaching a network call
  (``skill_key_flow``'s flow: aliases, ``headers["X"] = key``, helpers).
* Not a send: the key handed to a known wallet library (``privateKeyToAccount(key)``,
  ``new Wallet(key)``). The call must resolve to an import of that library and must not
  be defined or reassigned in the file. ``wallet.privateKey`` read back off such an
  object is the key again. Also not a send: testing that the key is set (``!!key``,
  ``key ? a : b``).

Severity: a hardcoded public host (or a hardcoded default behind ``env || default``) is
critical; an endpoint only the user configures, or a local one, is high.

Pure text analysis; never executes code. Category is ``exfiltration``, never ``secret``
(``verdict.SECRET_CATEGORY`` would cap it at Review).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.scanner.credential_flow import _arg_span, _redefine_re
from src.scanner.skill_key_flow import (
    _URL_RE,
    DECODED,
    _dest_hosts,
    _flow,
    _func_called,
    _mentions,
    _taint,
    _visible_names,
    is_local_host,
    strip_comments,
)

# Chains and signers: a word here plus a private-key suffix names a wallet key.
_WALLET_WORDS = frozenset({
    "WALLET", "ETH", "ETHEREUM", "EVM", "SOL", "SOLANA", "BTC", "BITCOIN", "BASE",
    "POLYGON", "ARBITRUM", "OPTIMISM", "AVAX", "BSC", "TRON", "SUI", "APTOS", "SIGNER",
    "PAYER", "X402", "CRYPTO", "ONCHAIN", "TREASURY",
})
_ALWAYS = frozenset({"PRIVATE_KEY", "PRIVATEKEY", "PRIVKEY", "PRIV_KEY", "MNEMONIC",
                     "SEED_PHRASE", "MNEMONIC_PHRASE", "RECOVERY_PHRASE"})
_PHRASE_SUFFIXES = ("_MNEMONIC", "_SEED_PHRASE", "_MNEMONIC_PHRASE", "_RECOVERY_PHRASE")
_KEY_SUFFIXES = ("_PRIVATE_KEY", "_PRIVATEKEY", "_PRIVKEY", "_PRIV_KEY", "_SECRET_KEY",
                 "_PK", "_SEED")


def is_signing_key_name(name: str) -> bool:
    """True for an env var named as a wallet signing key. ``STRIPE_PRIVATE_KEY`` and
    ``IMAGEKIT_PRIVATE_KEY`` are API credentials their vendor expects, so a private-key
    suffix counts only beside a wallet word."""
    if name in _ALWAYS or name.endswith(_PHRASE_SUFFIXES):
        return True
    words = set(name.split("_"))
    if name.endswith(_KEY_SUFFIXES) and words & _WALLET_WORDS:
        return True
    return "WALLET" in words and name.endswith("_KEY") and "API" not in words


_HINT_RE = re.compile(r"PRIVATE_?KEY|PRIV_?KEY|MNEMONIC|SEED|RECOVERY_PHRASE|_PK\b|WALLET")
_ENV_READ_RE = re.compile(
    r"(?:\benviron(?:\.get)?\s*[\[(]\s*[\"']|\bgetenv\s*\(\s*[\"']"
    r"|\bprocess\.env(?:\.|\[\s*[\"'`])|\bimport\.meta\.env\.)([A-Z][A-Z0-9_]*)\b")
_DESTRUCTURE_RE = re.compile(r"\{([^{}]*)\}\s*=\s*process\.env\b")

# Wallet libraries whose constructors take a key and keep it local.
_JS_LIBS = (r"(?:viem(?:/[\w/.-]+)?|ethers|web3|@solana/web3\.js|@solana/kit|tweetnacl"
            r"|@noble/[\w/.-]+|@scure/[\w/.-]+|@x402/[\w/.-]+|x402(?:-[\w-]+)?"
            r"|@coinbase/[\w/.-]+|@mysten/[\w/.-]+|@aptos-labs/[\w/.-]+)")
_PY_LIBS = r"(?:eth_account|web3|solders|solana|nacl|ed25519|x402|bip_utils)"
_JS_IMPORT_RE = re.compile(
    r"\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\s*\(\s*['\"]" + _JS_LIBS
    + r"['\"]\s*\)"
    r"|\bimport\s+(?:\*\s+as\s+([\w$]+)|(\{[^}]*\})|([\w$]+)(?:\s*,\s*(\{[^}]*\}))?)\s+from\s+"
    r"['\"]" + _JS_LIBS + r"['\"]")
_PY_FROM_RE = re.compile(
    r"^[ \t]*from[ \t]+" + _PY_LIBS + r"(?:\.[\w.]+)?[ \t]+import[ \t]+\(?([^\n)]+)", re.M)
_PY_IMPORT_RE = re.compile(
    r"^[ \t]*import[ \t]+(" + _PY_LIBS + r")(?:\.[\w.]+)?(?:[ \t]+as[ \t]+(\w+))?", re.M)

# The last name of a call that turns a key into a local signer.
_SIGNER_CTOR_RE = re.compile(
    r"(?:(?:\bnew\s+)?(?<![\w$])((?:[\w$]+\s*\.\s*)*)"
    r"(privateKeyToAccount|mnemonicToAccount|hdKeyToAccount|Wallet|HDNodeWallet|Keypair"
    r"|SigningKey|fromPhrase|fromMnemonic|fromSecretKey|fromSeed|fromSecretKeyBytes"
    r"|from_key|from_mnemonic|from_bytes|from_seed|from_base58_string|from_json"
    r"|from_secret_key|keyPair|createSigner|createKeyPairSignerFromBytes)\s*\()")
_ASSIGNED_RE = re.compile(r"(?:^|[\s;(])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)"
                          r"\s*(?::[^=\n]{1,60})?=\s*(?:await\s+)?(?:new\s+)?$")
# Reading the key back off a signer object: the object is the key again.
_KEY_READBACK = (r"\s*\.\s*(?:privateKey|secretKey|mnemonic|phrase|extendedKey|signingKey"
                 r"|key|secret|to_bytes|to_base58_string|to_json|_private_key)\b")
_READBACK_NAME = "AGENTAVOW_SIGNING_KEY"


def _blank(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


def _lib_names(code: str, python: bool) -> set[str]:
    out: set[str] = set()
    if python:
        for m in _PY_FROM_RE.finditer(code):
            for part in m.group(1).split(","):
                bits = part.split()
                if bits:
                    out.add(bits[-1])
        for m in _PY_IMPORT_RE.finditer(code):
            out.add(m.group(2) or m.group(1))
        return out
    for m in _JS_IMPORT_RE.finditer(code):
        for g in m.groups():
            for part in (g or "").strip("{} ").split(","):
                bits = part.replace(":", " as ").split()
                if bits:
                    out.add(bits[-1])
    return out


def _mask_signers(code: str, python: bool) -> str:
    """``code`` with the arguments of resolved wallet-library signer calls blanked, so a
    key handed to one goes no further; ``obj.privateKey`` on the result then reads as
    the key. A signer defined or reassigned in this file is not the library's."""
    libs = _lib_names(code, python)
    if not libs:
        return code
    no_imports = code
    for rx in ((_PY_FROM_RE, _PY_IMPORT_RE) if python else (_JS_IMPORT_RE,)):
        no_imports = rx.sub(lambda m: _blank(m.group(0)), no_imports)
    out = list(code)
    objs: set[str] = set()
    for m in _SIGNER_CTOR_RE.finditer(code):
        chain = [c.strip() for c in m.group(1).split(".") if c.strip()]
        root = chain[0] if chain else m.group(2)
        if root not in libs or any(_redefine_re(p).search(no_imports)
                                   for p in [*chain, m.group(2)]):
            continue
        a = m.end() - 1
        b = _arg_span(code, a)
        out[a + 1:b - 1] = _blank(code[a + 1:b - 1])
        am = _ASSIGNED_RE.search(code[max(0, m.start() - 120):m.start()])
        if am:
            objs.add(am.group(1))
    masked = "".join(out)
    for nm in objs:
        masked = re.sub(r"(?<![\w$.])" + re.escape(nm) + _KEY_READBACK, _READBACK_NAME, masked)
    return masked


def _mask_presence(code: str, names: set[str]) -> str:
    """``code`` with key-is-set tests blanked: ``!!key``, ``Boolean(key)``, ``key ? a :
    b``, ``if (key)``, ``key.length``, ``typeof key``. They say a key exists, not what
    it is."""
    for nm in sorted(names, key=len, reverse=True):
        n = re.escape(nm)
        code = re.sub(
            r"!{1,2}\s*" + n + r"(?![\w$])"
            r"|\bBoolean\(\s*" + n + r"\s*\)|\bbool\(\s*" + n + r"\s*\)"
            r"|\btypeof\s+" + n + r"(?![\w$])"
            r"|(?<![\w$.])" + n + r"(?=\s*(?:\?(?![.?])|\.length\b))"
            r"|\bif\s*\(\s*" + n + r"\s*\)"
            r"|\bif\s+(?:not\s+)?" + n + r"\s*:",
            lambda m: _blank(m.group(0)), code)
    return code


_ENV_DEFAULT_RE = re.compile(
    r"(?:process\.env(?:\.\w+|\[[^\]]+\])|import\.meta\.env\.\w+|environ(?:\.get)?\s*[\[(][^)\]]+"
    r"[\])]|getenv\s*\([^)]*\))\s*(?:\|\||\?\?|\bor\b)\s*([^\n;,)]+)"
    r"|(?:environ\.get|getenv)\s*\(\s*[\"'][^\"']+[\"']\s*,\s*([^)\n]+)\)")


def _default_hosts(flow) -> list[str]:
    """Public hosts a file falls back to behind an env override (``process.env.URL ||
    "https://x"``, ``os.getenv("URL", DEFAULT)``). "Configure it if you like" with a
    hardcoded default is the hardcoded host."""
    out: list[str] = []
    for m in _ENV_DEFAULT_RE.finditer(flow.joined):
        rhs = m.group(1) or m.group(2) or ""
        out.extend(_URL_RE.findall(rhs))
        for v, hosts in flow.url_vars.items():
            if re.search(r"(?<![\w$.])" + re.escape(v) + r"(?![\w$])", rhs):
                out.extend(hosts)
    return [h for h in out if not is_local_host(h)]


@dataclass
class SigningKeySend:
    env_name: str
    line: str           # the call's first line, to locate it in the source
    hosts: list[str]    # public destinations; empty = configured or local only
    severity: str       # critical | high


def signing_key_sends(text: str, path: str) -> list[SigningKeySend]:
    """One entry per wallet signing key whose raw value reaches a network call."""
    if not text or not _HINT_RE.search(text):
        return []
    code = strip_comments(text, path)
    names = {n for n in _ENV_READ_RE.findall(code) if is_signing_key_name(n)}
    seeds = set(names)
    for m in _DESTRUCTURE_RE.finditer(code):
        for part in m.group(1).split(","):
            bits = [b.strip().split("=")[0].strip() for b in part.split(":")]
            if bits and is_signing_key_name(bits[0]):
                names.add(bits[0])
                seeds.update(b for b in bits if b)
    if not names:
        return []
    python = path.lower().endswith(".py")
    code = _mask_signers(code, python)
    if _READBACK_NAME in code:
        seeds.add(_READBACK_NAME)
    # Aliases first, so a presence test on one (`const k = KEY; if (k)`) is blanked too.
    flow0 = _flow(_mask_presence(code, seeds), path)
    aliases, _f0 = _taint(flow0, {s: {None} for s in seeds})
    flow = _flow(_mask_presence(code, set(aliases)), path)
    defaults = _default_hosts(flow)
    tainted, funcs = _taint(flow, {s: {None} for s in seeds})
    out: list[SigningKeySend] = []
    for chunk, line in flow.calls:
        vis = _visible_names(flow, tainted, line)
        if not ((vis and _mentions(chunk, vis)) or (funcs and _func_called(chunk, funcs))):
            continue
        hosts = _dest_hosts(flow, chunk, line)
        public = [h for h in hosts if h != "?" and h != DECODED and not is_local_host(h)]
        unresolved = "?" in hosts
        if unresolved and defaults:
            public += defaults
        crit = bool(public) or DECODED in hosts
        out.append(SigningKeySend(
            env_name=sorted(names)[0], line=chunk.split("\n", 1)[0].strip()[:80],
            hosts=sorted(set(public)), severity="critical" if crit else "high"))
    return out
