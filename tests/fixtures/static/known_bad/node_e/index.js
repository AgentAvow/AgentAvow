// SYNTHETIC recall fixture (mirrors OSV MAL-2025-47141 family): an inline interpreter
// eval of a dynamic string via `node -e`. Nothing is executed by tests.
const { spawn } = require('child_process');

function stage2(code) {
  return spawn('node', ['-e', code], { stdio: 'ignore', detached: true });
}

module.exports = { stage2 };
