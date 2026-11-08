// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each case: JSON.parse the served definition text, see that RFC 8785 cannot
// canonicalize it (a lone surrogate or a non-finite number), rebuild the issuer's
// fallback preimage (LABEL + "\n" + Python json.dumps text, WTF-8 encoded) and check
// its bytes and SHA-256 against the values the issuer produced. Nothing is fetched.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./tool-manifest-digest-v1-noncanonical-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));

const PROFILE = 'agentavow.mcp-tool-definition.v1';
const LABEL = PROFILE + '.noncanonical';
const FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'];

const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// True when RFC 8785 refuses the value and the issuer falls back.
function needsFallback(v) {
  if (typeof v === 'number') return !Number.isFinite(v);
  if (typeof v === 'string') return LONE.test(v);
  if (v === null || typeof v !== 'object') return false;
  if (Array.isArray(v)) return v.some(needsFallback);
  return Object.keys(v).some(k => LONE.test(k) || needsFallback(v[k]));
}

// Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False).
const ESC = { '"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f' };
function pyStr(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    out += ESC[ch] ?? (c < 0x20 ? '\\u' + c.toString(16).padStart(4, '0') : ch);
  }
  return out + '"';
}
// json.loads gives an int for an integer literal and a float otherwise; a JSON.parse
// number keeps no such mark. An integer value below 2^53 prints as an int, anything
// else as Python's repr of the double. A literal the other way round (1.0, 1e2, a huge
// integer) prints differently, so the digest does not match and the gate fails closed.
function pyNum(x) {
  if (Number.isNaN(x)) return 'NaN';
  if (x === Infinity) return 'Infinity';
  if (x === -Infinity) return '-Infinity';
  if (Number.isInteger(x) && Math.abs(x) < 2 ** 53) return String(x === 0 ? 0 : x);
  const sign = x < 0 ? '-' : '';
  const [mant, exp] = Math.abs(x).toExponential().split('e');
  const digits = mant.replace('.', '');
  const decpt = Number(exp) + 1;
  if (decpt <= -4 || decpt > 16) {
    const e = decpt - 1;
    return sign + digits[0] + (digits.length > 1 ? '.' + digits.slice(1) : '') +
      'e' + (e < 0 ? '-' : '+') + String(Math.abs(e)).padStart(2, '0');
  }
  if (decpt <= 0) return sign + '0.' + '0'.repeat(-decpt) + digits;
  if (decpt < digits.length) return sign + digits.slice(0, decpt) + '.' + digits.slice(decpt);
  return sign + digits + '0'.repeat(decpt - digits.length) + '.0';
}
const byCodePoint = (a, b) => {
  const x = Array.from(a), y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
};
function pyDumps(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') return pyNum(v);
  if (typeof v === 'string') return pyStr(v);
  if (Array.isArray(v)) return '[' + v.map(pyDumps).join(',') + ']';
  return '{' + Object.keys(v).sort(byCodePoint).map(k => pyStr(k) + ':' + pyDumps(v[k])).join(',') + '}';
}
// UTF-8, with a lone surrogate written as its own three bytes (Python surrogatepass).
function wtf8(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Buffer.from(out);
}
function fallbackPreimage(tool) {
  const body = {};
  for (const f of FIELDS) if (tool[f] !== undefined && tool[f] !== null) body[f] = tool[f];
  return wtf8(LABEL + '\n' + pyDumps(body));
}

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
  if (!ok) failures++;
};

check(set.profile === PROFILE && set.portable === false, `profile is ${PROFILE}, not portable`);
const byName = {};
for (const c of set.cases) {
  const tool = JSON.parse(c.definition_json);
  check(needsFallback(tool), `${c.name}: RFC 8785 cannot canonicalize it`);
  const pre = fallbackPreimage(tool);
  const digest = 'sha256:' + createHash('sha256').update(pre).digest('hex');
  byName[c.name] = digest;
  check(pre.toString('hex') === c.preimage_hex, `${c.name}: preimage bytes`);
  check(digest === c.digest, `${c.name}: digest ${c.digest.slice(0, 19)}…`);
}
for (const [a, b] of set.different_digest) {
  check(byName[a] !== byName[b], `different digest: ${a} / ${b}`);
}
console.log(failures ? `${failures} failure(s)` : `all ${set.cases.length} cases ok`);
process.exit(failures ? 1 : 0);
