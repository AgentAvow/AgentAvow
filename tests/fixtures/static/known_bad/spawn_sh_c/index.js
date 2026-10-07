// SYNTHETIC recall fixture (mirrors OSV MAL-2025-47141, @ctrl/tinycolor / Shai-Hulud):
// a shell string built at runtime is handed to `sh -c`. Nothing is executed by tests.
const { spawn } = require('child_process');

function run(payload) {
  const cmd = 'echo ' + payload + ' > /tmp/out';
  spawn('sh', ['-c', cmd], { stdio: 'inherit' });
}

module.exports = { run };
