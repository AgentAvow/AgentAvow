import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { instantNanoseconds } from './time.mjs';

const fixture = JSON.parse(readFileSync(new URL('./tool-manifest-digest-v1-vectors.json', import.meta.url), 'utf8'));
const [, payload] = fixture.attestation.jws.split('.');
const signed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
const issued = instantNanoseconds(signed.issuedAt);
const expiry = instantNanoseconds(signed.expiresAt);
const exactCases = [
  ['Mayur-boundary-fresh', '2026-10-02T21:28:34.085Z', true],
  ['last-nanosecond-before-expiry', '2026-10-02T21:28:34.085196999Z', true],
  ['exact-expiry-offset', '2026-10-02T21:28:34.085197+00:00', false],
  ['exact-expiry-Z', '2026-10-02T21:28:34.085197Z', false],
  ['first-nanosecond-after-expiry', '2026-10-02T21:28:34.085197001Z', false],
  ['last-nanosecond-before-issuance', '2026-10-01T21:28:34.085196999Z', false],
  ['exact-issuance-offset', '2026-10-01T21:28:34.085197+00:00', true],
  ['exact-issuance-Z', '2026-10-01T21:28:34.085197Z', true],
  ['first-nanosecond-after-issuance', '2026-10-01T21:28:34.085197001Z', true],
  ['equivalent-nanosecond-expiry', '2026-10-02T21:28:34.085197000Z', false],
];
for (const [name, value, expected] of exactCases) {
  test(name, () => {
    const instant = instantNanoseconds(value);
    assert.equal(instant >= issued && instant < expiry, expected);
  });
}

test('historical millisecond truncation disagrees in both admission directions', () => {
  assert.equal(Date.parse(exactCases[0][1]) < Date.parse(signed.expiresAt), false);
  assert.equal(Date.parse(exactCases[5][1]) >= Date.parse(signed.issuedAt), true);
});

const equivalentPairs = [
  ['2026-10-02T21:28:34.085197Z', '2026-10-02T23:28:34.085197+02:00'],
  ['2026-10-02T21:28:34.085197Z', '2026-10-02T19:28:34.085197-02:00'],
  ['2026-10-02T21:28:34Z', '2026-10-02T21:28:34.000000000+00:00'],
  ['2026-10-02T21:28:34.1Z', '2026-10-02T21:28:34.100000000Z'],
  ['1970-01-01T00:00:00Z', '1970-01-01T01:00:00+01:00'],
  ['1969-12-31T23:59:59.999999999Z', '1970-01-01T00:59:59.999999999+01:00'],
  ['2026-10-02T00:00:00Z', '2026-10-01T22:00:00-02:00'],
  ['0042-01-01T00:00:00Z', '0041-12-31T23:00:00-01:00'],
];
for (const [a, b] of equivalentPairs) {
  test(`equivalent instants: ${a} and ${b}`, () => assert.equal(instantNanoseconds(a), instantNanoseconds(b)));
}
test('epoch and midnight retain adjacent nanoseconds', () => {
  assert.equal(instantNanoseconds('1970-01-01T00:00:00Z'), 0n);
  assert.equal(instantNanoseconds('1969-12-31T23:59:59.999999999Z'), -1n);
  assert.equal(instantNanoseconds('2026-10-02T00:00:00Z') - instantNanoseconds('2026-10-01T23:59:59.999999999Z'), 1n);
});
test('Gregorian leap day is accepted in year 2000', () => {
  assert.equal(instantNanoseconds('2000-03-01T00:00:00Z') - instantNanoseconds('2000-02-29T00:00:00Z'), 86_400_000_000_000n);
});

const unsupported = [null, 0, {}, '', '2026-10-02T21:28:34.0851970001Z',
  '2026-10-02T21:28:34,085197Z', '2026-10-02T21:28:34Z\n', '2026-10-02T21:28:34Z\r',
  ' 2026-10-02T21:28:34Z', '2026-10-02T21:28:34Z ', '2026-10-02 21:28:34Z',
  '2026-10-02t21:28:34z', '2026-10-02T21:28:34', '2026-10-02T21:28:34-00:00',
  '2026-10-02T21:28:34+24:00', '2026-10-02T21:28:34+00:60', '2026-02-30T21:28:34Z',
  '1900-02-29T00:00:00Z', '2026-00-02T21:28:34Z', '2026-13-02T21:28:34Z',
  '2026-10-00T21:28:34Z', '2026-10-32T21:28:34Z', '2026-10-02T24:28:34Z',
  '2026-10-02T21:60:34Z', '2026-10-02T21:28:60Z'];
for (const value of unsupported) {
  test(`unsupported timestamp refuses: ${JSON.stringify(value)}`, () => assert.throws(() => instantNanoseconds(value)));
}

test('native verifier checks all axes using unchanged signed bytes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentavow-exact-time-'));
  try {
    const original = fixture.vectors.find(v => v.name === 'tool-match');
    const candidate = { ...fixture, vectors: [...fixture.vectors, ...exactCases.map(([name, value, expected]) => ({
      ...original, name, gate: { ...original.gate, evaluation_time: value },
      expect: { ...original.expect, fresh: expected, rely: expected },
    }))] };
    const path = join(directory, 'exact-time-vectors.json');
    writeFileSync(path, JSON.stringify(candidate));
    const result = spawnSync(process.execPath, [new URL('./verify.mjs', import.meta.url).pathname, path], { encoding: 'utf8' });
    assert.equal(candidate.attestation.jws, fixture.attestation.jws);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, '');
    assert.match(result.stdout, /all checks passed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('valid local signed nanosecond windows keep issuance inclusive and expiry exclusive', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentavow-local-nanosecond-'));
  try {
    // This ephemeral fixture key is no issuer credential. Original signed bytes stay unchanged.
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const kid = 'local-nanosecond-regression';
    const [originalHeader, originalPayload] = fixture.attestation.jws.split('.');
    const header = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(originalHeader, 'base64url')), kid })).toString('base64url');
    const issuedAt = '2026-10-01T21:28:34.085000900Z';
    const expiresAt = '2026-10-01T21:28:34.085001100Z';
    const windowBytes = encoded => {
      let body = Buffer.from(encoded, 'base64url').toString('utf8');
      for (const [field, value] of [['issuedAt', issuedAt], ['expiresAt', expiresAt]]) {
        const before = JSON.stringify(field) + ':' + JSON.stringify(signed[field]);
        assert.equal(body.split(before).length, 2);
        body = body.replace(before, JSON.stringify(field) + ':' + JSON.stringify(value));
      }
      return body;
    };
    const body = windowBytes(originalPayload);
    const encoded = Buffer.from(body).toString('base64url');
    const input = `${header}.${encoded}`;
    const jws = input + '.' + sign(null, Buffer.from(input, 'ascii'), privateKey).toString('base64url');
    const original = fixture.vectors.find(v => v.name === 'tool-match');
    const times = [['before-issuance', '2026-10-01T21:28:34.085000899Z', false],
      ['exact-issuance', '2026-10-01T21:28:34.085000900Z', true],
      ['before-expiry', '2026-10-01T21:28:34.085001099Z', true],
      ['exact-expiry', '2026-10-01T21:28:34.085001100Z', false]];
    // Retain the verifier's six required controls with the local window. The
    // tampered payload remains canonical but retains a deliberately wrong signature.
    const controls = fixture.vectors.map(vector => {
      let controlJws = vector.jws;
      if (controlJws !== 'reference') {
        const [, controlPayload, invalidSignature] = controlJws.split('.');
        controlJws = header + '.' + Buffer.from(windowBytes(controlPayload)).toString('base64url') + '.' + invalidSignature;
      }
      return { ...vector, jws: controlJws,
        gate: { ...vector.gate, evaluation_time: vector.name === 'past-expiry' ? expiresAt : issuedAt } };
    });
    const candidate = { ...fixture, author_set: 'local precision regression; ephemeral fixture key',
      issuer: { ...fixture.issuer, jwk: { ...publicKey.export({ format: 'jwk' }), kid } },
      attestation: { ...fixture.attestation, jws }, vectors: [...controls, ...times.map(([name, value, fresh]) => ({ ...original,
        name: 'local-' + name, gate: { ...original.gate, evaluation_time: value },
        expect: { ...original.expect, fresh, rely: fresh } }))] };
    const path = join(directory, 'local-nanosecond-vectors.json');
    writeFileSync(path, JSON.stringify(candidate));
    if (process.env.AGENTAVOW_TIME_TEST_RECEIPT)
      writeFileSync(process.env.AGENTAVOW_TIME_TEST_RECEIPT, JSON.stringify(candidate), { flag: 'wx', mode: 0o600 });
    const result = spawnSync(process.execPath, [new URL('./verify.mjs', import.meta.url).pathname, path], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, '');
    assert.match(result.stdout, /all checks passed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('unsupported gate and signed-window forms fail at the verifier input boundary', () => {
  const directory = mkdtempSync(join(tmpdir(), 'agentavow-invalid-time-'));
  try {
    for (const value of [unsupported[4], unsupported[5], unsupported[13]]) {
      const candidate = { ...fixture, vectors: fixture.vectors.map(v => ({ ...v, gate: { ...v.gate, evaluation_time: value } })) };
      const path = join(directory, 'unsupported-time-vectors.json');
      writeFileSync(path, JSON.stringify(candidate));
      const result = spawnSync(process.execPath, [new URL('./verify.mjs', import.meta.url).pathname, path], { encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /timestamp/);
    }
    for (const field of ['issuedAt', 'expiresAt']) {
      const [header, payload, signature] = fixture.attestation.jws.split('.');
      const changed = { ...JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')), [field]: unsupported[4] };
      // Keep the old signature: this is invalid input, not a newly signed grade.
      const jws = [header, Buffer.from(JSON.stringify(changed)).toString('base64url'), signature].join('.');
      const candidate = { ...fixture, attestation: { ...fixture.attestation, jws }, vectors: [fixture.vectors[0]] };
      const path = join(directory, 'unsupported-signed-window.json');
      writeFileSync(path, JSON.stringify(candidate));
      const result = spawnSync(process.execPath, [new URL('./verify.mjs', import.meta.url).pathname, path], { encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /timestamp/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
