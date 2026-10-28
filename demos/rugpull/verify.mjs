#!/usr/bin/env node
// Anyone can check the signed result offline: no network, no AgentAvow account.
//
//   node verify.mjs            verify .state/result.json against .state/jwks.json, then
//                              compare the signed send_email digest with what the
//                              server serves now (recomputed from tools.mjs)
//   node verify.mjs --tamper   rewrite the signed score first: the signature fails
//
// The same check runs inside the gate on every call; this script just does it in the open.

import fs from 'node:fs';
import { b64urlDecode, b64urlEncode, verifyJws } from 'agentavow-trust/jws';
import { toolDigest } from 'agentavow-trust/gate';
import { DEMO_KID, statePath } from './config.mjs';
import { VERSIONS } from './tools.mjs';

const tamper = process.argv.includes('--tamper');
const result = JSON.parse(fs.readFileSync(statePath('result.json'), 'utf8'));
const jwks = JSON.parse(fs.readFileSync(statePath('jwks.json'), 'utf8'));
let jws = result.jws;
if (tamper) {
  // Raise the signed trust score by 20 and keep the original signature.
  const [h, p, s] = jws.split('.');
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  payload.scan.trustScore += 20;
  jws = `${h}.${b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)))}.${s}`;
  console.log(`  tampered: signed trust score rewritten to ${payload.scan.trustScore}/100, signature kept`);
}

const v = await verifyJws(jws, jwks, { expectKid: DEMO_KID });
if (!v.valid) {
  console.log(`  signature: INVALID (${v.reason})${tamper ? ': any edit to the signed result is caught' : ''}`);
  process.exit(tamper ? 0 : 1);
}
const scan = v.payload?.scan ?? {};
const signed = (scan.toolDigests ?? {})['tool:send_email'];
console.log(`  signature: valid (EdDSA, kid ${v.kid}, checked against the local JWKS file, no network)`);
console.log(`  signed trust score: ${scan.trustScore ?? result.trust_score}/100`);
const later = process.env.RUGPULL_LATER ?? 'v2';
const served = toolDigest(VERSIONS[later]);
console.log(`  send_email signed  ${signed}`);
console.log(`  send_email now     ${served}  (${later})`);
console.log(signed === served
  ? '  match: the served definition is the one that was scanned'
  : '  MISMATCH: the definition changed after the scan, so the signed result no longer covers it');
