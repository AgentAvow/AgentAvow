# Contributing to AgentAvow

Thank you for looking. This repository is source-available, not open source as a whole, so
what you can contribute depends on the folder. The short version: the open standards
material and the Claude Code plugin take outside contributions; the product does not.

## What takes contributions

| Folder | Licence | Contributions |
|---|---|---|
| `docs/standards/tool-manifest-digest-vectors-v0/` | Apache-2.0 | Welcome: new vectors, verifier fixes, reproductions |
| `docs/standards/tool-manifest-digest-vectors-v1/` | Apache-2.0 | Welcome: new vectors, verifier fixes, reproductions |
| `docs/standards/attribution-record-v0/` | Apache-2.0 | Welcome: record format, fixtures, verifier fixes |
| `plugins/agentavow-trust/` | MIT | Welcome: bug fixes and hook improvements |
| Everything else (`src/`, `web/`, `sdk/`, `scripts/`, …) | All rights reserved (see `LICENSE`) | Not accepted. Please open an issue instead |

Files under `docs/standards/attribution-record-v0/pins/` are byte copies of other projects'
artifacts under their own licences. Fix those upstream, not here.

## Terms

A contribution to a folder that carries its own `LICENSE` file is accepted under that
licence (inbound equals outbound). There is no separate contributor agreement.

Sign off each commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s
```

which adds `Signed-off-by: Your Name <you@example.com>`. A pull request to a proprietary
folder will be closed with thanks; the idea is still welcome as an issue.

## Credit

Contributors to a folder are named in that folder's README. If you would rather not be
named, say so in the pull request.

## How a standards contribution is checked

Every vector folder has a zero-dependency verifier. Before opening a pull request:

```
cd docs/standards/tool-manifest-digest-vectors-v1
node generate.mjs   # regenerates the vector file from source.json; must be byte-identical
node verify.mjs     # must print "all checks passed"
```

A new negative vector should fail exactly one named axis, and the README should say what the
case establishes and what it does not. Reproductions by people who did not write the vectors
are the most useful contribution of all: report the commit you ran, your runtime, the verifier
output verbatim, and whether you used `verify.mjs` or your own implementation.

Pull requests from forks need a maintainer to approve their CI run before checks start; that
is a GitHub default, not a judgement on the change.

## Security

Please report vulnerabilities privately, not in a public issue: email admin@agentavow.com.
