#!/usr/bin/env node
// agentavow-trust CLI — `npx agentavow-trust scan <owner/repo>` and `verify`.
//
// A zero-install way to get a signed safety score from the terminal:
//   npx agentavow-trust scan modelcontextprotocol/servers
//   npx agentavow-trust scan npm:chalk
//   npx agentavow-trust badge you/your-repo      # prints the README badge line
//
// scan/badge hit the free public API; the returned score carries a signed (Ed25519)
// attestation you can verify offline — the point of the product.
import process from 'node:process';

const API = process.env.AGENTAVOW_API || 'https://agentavow.com/api/v1';
const SITE = 'https://agentavow.com';

function scanPath(target) {
  // owner/repo -> /public/scan/owner/repo ; surface:name -> /public/scan/package/surface/name
  const m = target.match(/^([a-z]+):(.+)$/i);
  if (m && ['npm', 'pypi', 'crates', 'docker', 'hf'].includes(m[1].toLowerCase())) {
    return `/public/scan/package/${m[1].toLowerCase()}/${encodeURIComponent(m[2])}`;
  }
  return `/public/scan/${target}`;
}

function badgeLine(target) {
  return `[![AgentAvow Trust](${SITE}/api/v1/public/scan/${target}/badge)](${SITE}/check/${target})`;
}

async function scan(target) {
  const res = await fetch(API + scanPath(target), { headers: { accept: 'application/json' } });
  if (!res.ok) {
    console.error(`scan failed (HTTP ${res.status}) for ${target}`);
    process.exit(1);
  }
  const d = await res.json();
  const f = d.findings || {};
  console.log(`\n  ${target}`);
  console.log(`  ${d.trust_score}/100  ${d.grade || ''}  ${d.trust_tier || ''}${d.certified?.eligible ? '  ✓ Certified' : ''}`);
  console.log(`  findings: ${f.critical || 0} critical · ${f.high || 0} high · ${f.total || 0} total`);
  console.log(`  report:  ${SITE}/check/${target}`);
  console.log(`  signed:  ${d.jws ? 'yes — verify offline against ' + SITE + '/.well-known/jwks.json' : 'n/a'}`);
  console.log(`\n  badge:   ${badgeLine(target)}\n`);
}

const [cmd, target] = process.argv.slice(2);
if (!cmd || !['scan', 'badge', 'verify'].includes(cmd) || (cmd !== 'help' && !target)) {
  console.log('usage: npx agentavow-trust <scan|badge> <owner/repo | surface:name>');
  process.exit(cmd ? 1 : 0);
} else if (cmd === 'badge') {
  console.log(badgeLine(target));
} else {
  scan(target).catch((e) => { console.error(String(e)); process.exit(1); });
}
