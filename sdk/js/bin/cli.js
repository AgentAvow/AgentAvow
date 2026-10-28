#!/usr/bin/env node
// agentavow-trust CLI — `npx agentavow-trust scan <owner/repo>` and `badge`.
//
// A zero-install way to ask "is this tool safe to connect?" from the terminal:
//   npx agentavow-trust scan modelcontextprotocol/servers
//   npx agentavow-trust scan npm:chalk
//   npx agentavow-trust badge you/your-repo      # prints the README badge line
//
// scan/badge hit the free public API; the returned score carries a signed (Ed25519)
// attestation you can verify offline — the point of the product (see the `./verify`
// export, or https://agentavow.com/docs/verify-attestations).
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

const PHRASES = {
  safe: 'Safe to connect',
  review: 'Review before you connect',
  do_not_connect: 'Do not connect',
};

function isPackage(target) {
  const m = target.match(/^([a-z]+):(.+)$/i);
  return Boolean(m && ['npm', 'pypi', 'crates', 'docker', 'hf'].includes(m[1].toLowerCase()));
}

function reportUrl(target) {
  const m = target.match(/^([a-z]+):(.+)$/i);
  if (isPackage(target)) {
    return `${SITE}/check/pkg/${m[1].toLowerCase()}/${m[2]}`;
  }
  return `${SITE}/check/${target}`;
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
  const answer = PHRASES[d.decision] || '';
  console.log(`\n  ${target}`);
  if (answer) {
    console.log(`  ${answer}${d.certified_mark === true && d.decision === 'safe' ? ' · Certified' : ''}${d.decision_reason ? ' — ' + d.decision_reason : ''}`);
  }
  console.log(`  trust score: ${d.trust_score}/100${d.trust_tier ? '  (tier: ' + d.trust_tier + ')' : ''}`);
  console.log(`  findings: ${f.critical || 0} critical · ${f.high || 0} high · ${f.total || 0} total`);
  console.log(`  report:  ${reportUrl(target)}  (adoption score and full findings)`);
  console.log(`  signed:  ${d.jws ? 'yes — verify offline against ' + (d.jwks_url || 'https://agentgraph.co/.well-known/jwks.json') : 'n/a'}`);
  // The README badge is served for GitHub repos only.
  console.log(isPackage(target) ? '' : `\n  badge:   ${badgeLine(target)}\n`);
}

const [cmd, target] = process.argv.slice(2);
if (!cmd || !['scan', 'badge'].includes(cmd) || !target) {
  console.log('usage: npx agentavow-trust <scan|badge> <owner/repo | surface:name>');
  process.exit(cmd ? 1 : 0);
} else if (cmd === 'badge') {
  console.log(badgeLine(target));
} else {
  scan(target).catch((e) => { console.error(String(e)); process.exit(1); });
}
