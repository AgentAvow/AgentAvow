/*!
 * AgentAvow embeddable widget — the live dual-mark card + offline verify.
 *
 *   <script src="https://agentavow.com/widget.js" data-tool="npm/chalk"></script>
 *
 * Renders the always-current scores card (the hosted card.svg) as a link to the
 * full report, and adds a "Verify offline" control that recomputes the Ed25519
 * (JWS/EdDSA) signature IN THE VISITOR'S BROWSER against the public JWKS — so the
 * trust check runs on the reader's machine, not on a claim we make. No framework,
 * no build step, no external calls beyond AgentAvow's own CORS-open endpoints.
 *
 * Attributes on the <script> (or a target <div data-agentavow-tool="...">):
 *   data-tool   required — coordinate: "npm/chalk", "pypi/requests", "owner/repo"
 *   data-theme  "dark" (default) | "light"
 *   data-verify "true" (default) | "false"  — hide the verify control
 */
(function () {
  'use strict';

  // Capture our own <script> now — document.currentScript is null once we defer to
  // DOMContentLoaded, so the inline data-tool render path needs the reference here.
  var THIS_SCRIPT = document.currentScript;
  var ORIGIN = (function () {
    try { return new URL(THIS_SCRIPT.src).origin; }
    catch (e) { return 'https://agentavow.com'; }
  })();

  function coordToPath(tool) {
    // "npm:chalk" and "npm/chalk" both mean npm/chalk; pass through owner/repo.
    return String(tool || '').trim().replace(/^https?:\/\/[^/]+\//, '').replace(':', '/');
  }

  function b64urlToBytes(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  // Recompute the JWS signature offline: verify header.payload with the JWKS key.
  async function verifyJws(verdict) {
    if (!verdict || !verdict.jws) throw new Error('no-attestation');
    if (!(window.crypto && window.crypto.subtle)) throw new Error('no-webcrypto');
    var parts = verdict.jws.split('.');
    if (parts.length !== 3) throw new Error('malformed');
    var header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    // Fetch the JWKS from OUR origin (where widget.js loaded from). It's served there
    // with CORS *, so this is same-origin on agentavow.com (CSP-safe) and a plain
    // cross-origin GET on any third-party embed — no dependency on the embedding
    // page's connect-src allowing the canonical agentgraph.co host.
    var jwksUrl = ORIGIN + '/.well-known/jwks.json';
    var jwks;
    try { jwks = await (await fetch(jwksUrl)).json(); }
    catch (e) { jwks = await (await fetch(verdict.jwks_url || jwksUrl)).json(); }
    var keys = (jwks && jwks.keys) || [];
    var jwk = keys.filter(function (k) { return k.kid === header.kid; })[0] || keys[0];
    if (!jwk) throw new Error('no-key');
    var key = await crypto.subtle.importKey(
      'jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify(
      { name: 'Ed25519' }, key, b64urlToBytes(parts[2]),
      new TextEncoder().encode(parts[0] + '.' + parts[1]));
  }

  function el(tag, css, text) {
    var n = document.createElement(tag);
    if (css) n.style.cssText = css;
    if (text != null) n.textContent = text;
    return n;
  }

  function mount(host, tool, theme, wantVerify) {
    var path = coordToPath(tool);
    if (!path) return;
    var cardUrl = ORIGIN + '/api/v1/public/scan/' + path + '/card.svg?theme=' + theme;
    var reportUrl = ORIGIN + '/check/' + path;
    var verdictUrl = ORIGIN + '/api/v1/public/scan/' + path + '/verdict.json';

    var wrap = el('div', 'display:inline-block;width:100%;max-width:360px;' +
      'font-family:system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.4');

    var link = el('a', 'display:block;text-decoration:none');
    link.href = reportUrl; link.target = '_blank'; link.rel = 'noopener';
    link.setAttribute('aria-label', 'AgentAvow scores for ' + path + ' — open full report');
    var img = el('img', 'width:100%;height:auto;display:block;border-radius:14px');
    img.src = cardUrl; img.alt = 'AgentAvow trust & adoption scores for ' + path; img.loading = 'lazy';
    link.appendChild(img);
    wrap.appendChild(link);

    if (wantVerify) {
      var teal = '#2dd4bf';
      var row = el('div', 'margin-top:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap');
      var btn = el('button', 'font:600 11.5px ui-monospace,SFMono-Regular,Menlo,monospace;' +
        'color:' + teal + ';background:transparent;border:1px solid rgba(45,212,191,.45);' +
        'border-radius:8px;padding:5px 11px;cursor:pointer;letter-spacing:.02em', '🔒 Verify offline');
      var out = el('span', 'font:500 11.5px ui-monospace,SFMono-Regular,Menlo,monospace;color:#93a1c0');
      btn.type = 'button';
      btn.addEventListener('click', function () {
        btn.disabled = true; btn.style.opacity = '.6';
        out.style.color = '#93a1c0'; out.textContent = 'recomputing signature…';
        fetch(verdictUrl).then(function (r) { return r.json(); }).then(function (v) {
          return verifyJws(v);
        }).then(function (ok) {
          out.style.color = ok ? '#22c55e' : '#ef4444';
          out.textContent = ok ? '✓ signature verified — recomputed in your browser'
                               : '✗ signature does not match — tampered';
        }).catch(function (e) {
          out.style.color = '#f59e0b';
          out.textContent = e && e.message === 'no-webcrypto'
            ? 'verify unsupported in this browser'
            : e && e.message === 'no-attestation'
              ? 'not scanned yet'
              : 'could not verify';
        }).then(function () { btn.disabled = false; btn.style.opacity = '1'; });
      });
      row.appendChild(btn); row.appendChild(out);
      wrap.appendChild(row);
    }

    host.replaceWith ? host.replaceWith(wrap) : (host.parentNode && host.parentNode.replaceChild(wrap, host));
    return wrap;
  }

  // Scan for target divs and mount any not yet rendered. Safe to call repeatedly —
  // exposed as window.AgentAvow.render(root) so single-page apps can re-mount after
  // navigation or after inserting a new [data-agentavow-tool] element.
  function render(root) {
    var scope = root || document;
    var targets = scope.querySelectorAll('[data-agentavow-tool]');
    for (var i = 0; i < targets.length; i++) {
      var t = targets[i];
      if (t.getAttribute('data-agentavow-mounted')) continue;
      t.setAttribute('data-agentavow-mounted', '1');
      var placeholder = el('div');
      t.appendChild(placeholder);
      mount(placeholder, t.getAttribute('data-agentavow-tool'),
        t.getAttribute('data-theme') || 'dark',
        t.getAttribute('data-verify') !== 'false');
    }
  }

  function boot() {
    render(document);
    // inline <script data-tool> — render in place, right after the tag
    var s = THIS_SCRIPT;
    if (s && s.getAttribute('data-tool') && !s.getAttribute('data-agentavow-mounted')) {
      s.setAttribute('data-agentavow-mounted', '1');
      var anchor = el('span');
      s.parentNode.insertBefore(anchor, s.nextSibling);
      mount(anchor, s.getAttribute('data-tool'),
        s.getAttribute('data-theme') || 'dark',
        s.getAttribute('data-verify') !== 'false');
    }
  }

  window.AgentAvow = window.AgentAvow || {};
  window.AgentAvow.render = render;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
