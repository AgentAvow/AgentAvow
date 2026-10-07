// Async API client for the AgentGraph Trust Score v2 surface.
//
// Peer of the Python agentgraph_sdk.client.AgentGraphClient (Trust Score v2
// methods). Uses the global `fetch` (Node 18+). API base is `<baseUrl>/api/v1`;
// the JWKS lives outside that prefix at `<baseUrl>/.well-known/jwks.json`.

import { verifyEnvelope } from './verify.js';

/** Base error for AgentGraph API failures. */
export class AgentGraphError extends Error {
  /**
   * @param {string} message
   * @param {number|null} [statusCode]
   */
  constructor(message, statusCode = null) {
    super(message);
    this.name = 'AgentGraphError';
    this.statusCode = statusCode;
  }
}

/**
 * Async client for the AgentAvow API (Trust Score v2 surface).
 *
 * @example
 * const client = new TrustClient('https://agentavow.com');
 * const env = await client.getAggregate('did:web:agentgraph.co:agents:<id>');
 * const result = await client.verifyEnvelope(env);
 * if (result.valid) console.log('verified:', result.kid);
 */
export class TrustClient {
  /**
   * @param {string} baseUrl
   * @param {{apiKey?: string, token?: string, timeout?: number}} [opts]
   */
  constructor(baseUrl, { apiKey, token, timeout = 30000 } = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this._apiPrefix = `${this.baseUrl}/api/v1`;
    this._apiKey = apiKey ?? null;
    this._token = token ?? null;
    this._timeout = timeout;
  }

  _headers() {
    const headers = {};
    if (this._apiKey) {
      headers['X-API-Key'] = this._apiKey;
    } else if (this._token) {
      headers['Authorization'] = `Bearer ${this._token}`;
    }
    return headers;
  }

  /**
   * Low-level request against the API prefix (`<baseUrl>/api/v1`).
   * @param {string} method
   * @param {string} path
   * @param {{json?: object, params?: object}} [opts]
   */
  async _request(method, path, { json, params } = {}) {
    let url = `${this._apiPrefix}${path}`;
    if (params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== null && v !== undefined) qs.append(k, String(v));
      }
      const s = qs.toString();
      if (s) url += `?${s}`;
    }
    return this._fetch(method, url, json);
  }

  async _fetch(method, url, json) {
    const headers = this._headers();
    const init = { method, headers };
    if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(json);
    }

    let controller;
    let timer;
    if (this._timeout && typeof AbortController !== 'undefined') {
      controller = new AbortController();
      init.signal = controller.signal;
      timer = setTimeout(() => controller.abort(), this._timeout);
    }

    let resp;
    try {
      resp = await fetch(url, init);
    } catch (err) {
      throw new AgentGraphError(`request failed: ${err.message}`, null);
    } finally {
      if (timer) clearTimeout(timer);
    }
    return this._parseResponse(resp);
  }

  async _parseResponse(resp) {
    if (resp.status === 204) return null;
    const text = await resp.text();
    if (resp.status >= 400) {
      let detail = text;
      try {
        detail = JSON.parse(text).detail ?? text;
      } catch {
        // keep raw text
      }
      throw new AgentGraphError(String(detail) || `HTTP ${resp.status}`, resp.status);
    }
    if (!text) return null;
    return JSON.parse(text);
  }

  // ------------------------------------------------------------------
  // Trust Score v2 — signed aggregate envelopes
  // ------------------------------------------------------------------

  /**
   * Fetch the signed v2 trust-score envelope for a subject DID.
   * The envelope carries the score, a per-source methodology breakdown, and an
   * Ed25519 proof. Use `verify()` to check it client-side.
   * @param {string} subjectDid
   */
  async getAggregate(subjectDid) {
    return this._request('GET', `/aggregate/${subjectDid}`);
  }

  /**
   * Fetch just the methodology breakdown (contributions) for a subject.
   * @param {string} subjectDid
   */
  async getContributions(subjectDid) {
    return this._request('GET', `/aggregate/${subjectDid}/contributions`);
  }

  /**
   * Scan a GitHub repo and return its grade + findings + signed v2 envelope.
   * The `trust_envelope` field (when present) is verifiable via verifyEnvelope().
   * @param {string} owner
   * @param {string} repo
   */
  async checkRepo(owner, repo) {
    return this._request('GET', `/public/scan/${owner}/${repo}`);
  }

  /**
   * Fetch the issuer JWKS (RFC 7517) used to verify signed envelopes.
   * Served at `<baseUrl>/.well-known/jwks.json` (outside the API prefix).
   */
  async getJwks() {
    return this._fetch('GET', `${this.baseUrl}/.well-known/jwks.json`);
  }

  /**
   * Verify a signed envelope client-side against the issuer's JWKS.
   * Fetches the JWKS, then checks the Ed25519 signature + freshness WITHOUT
   * trusting this server's verdict — the whole point of the signed envelope.
   * @param {object} envelope
   * @param {{now?: Date}} [opts]
   * @returns {Promise<import('./verify.js').VerificationResult>}
   */
  async verifyEnvelope(envelope, { now } = {}) {
    const jwks = await this.getJwks();
    return verifyEnvelope(envelope, jwks, { now });
  }

  /**
   * Fetch a subject's envelope and verify it client-side in one call.
   * @param {string} subjectDid
   * @param {{now?: Date}} [opts]
   * @returns {Promise<import('./verify.js').VerificationResult>}
   */
  async verify(subjectDid, { now } = {}) {
    const envelope = await this.getAggregate(subjectDid);
    return this.verifyEnvelope(envelope, { now });
  }
}

export default TrustClient;
