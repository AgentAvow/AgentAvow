// Writes the artifact digest into the component manifest and prints the pin values.
// Same procedure as federation-port scripts/seal.ts. Usage: node scripts/seal.ts <component-dir>
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { artifactDigest, digestJson } from '../src/digest.ts'

const dir = process.argv[2]
if (!dir) { console.error('usage: node scripts/seal.ts <component-dir>'); process.exit(2) }
const p = join(dir, 'manifest.json')
const m = JSON.parse(readFileSync(p, 'utf8'))
m.artifact.digest = artifactDigest(dir, m.artifact.files)
writeFileSync(p, JSON.stringify(m, null, 2) + '\n')
console.log(JSON.stringify({ id: m.id, version: m.artifact.version, artifact_digest: m.artifact.digest, manifest_digest: digestJson(m) }))
