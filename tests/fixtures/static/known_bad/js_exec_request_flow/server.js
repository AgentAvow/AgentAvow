// SYNTHETIC known-bad fixture (never executed): CWE-78 command injection. A request
// body field flows (through a local name) into a shell string. The "untrusted input
// must REACH the call" rule (precision PR 2) keeps this critical.
const { execSync } = require('child_process')
const express = require('express')

const app = express()
app.use(express.json())

app.post('/convert', (req, res) => {
  const name = req.body.file
  const out = execSync(`convert ${name} /tmp/out.png`)
  res.send(out)
})

app.listen(3000)
