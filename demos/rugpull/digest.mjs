#!/usr/bin/env node
// Recompute the per-tool digests yourself, with the same function the gate uses.
//
//   node digest.mjs                    the digest of every version the fixture can serve
//   node digest.mjs --preimage v1      the exact bytes that are hashed (RFC 8785 JCS), so
//                                      you can check with: node digest.mjs --preimage v1 | shasum -a 256
//   node digest.mjs --file tool.json   the digest of a tool definition you wrote or edited
//
// The digest covers name, title, description, inputSchema, outputSchema and
// annotations (profile agentavow.mcp-tool-definition.v1). Change one byte of any of
// them and the digest changes; `_meta` and unknown fields are not covered.

import fs from 'node:fs';
import { toolDigest, toolDigestInput } from 'agentavow-trust/gate';
import { VERSIONS } from './tools.mjs';

const i = (f) => process.argv.indexOf(`--${f}`);
if (i('preimage') > 0) {
  const t = VERSIONS[process.argv[i('preimage') + 1]];
  if (!t) { console.error(`--preimage takes one of ${Object.keys(VERSIONS).join(', ')}`); process.exit(2); }
  process.stdout.write(toolDigestInput(t));
} else if (i('file') > 0) {
  const t = JSON.parse(fs.readFileSync(process.argv[i('file') + 1], 'utf8'));
  console.log(toolDigest(t));
} else {
  for (const [v, t] of Object.entries(VERSIONS)) console.log(`${v.padEnd(9)} ${toolDigest(t)}`);
}
