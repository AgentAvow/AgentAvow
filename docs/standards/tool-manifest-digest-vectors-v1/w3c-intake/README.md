# Intake record for the tool-manifest-digest v1 vectors

`RECORD.json` is an intake record for the [v1 vector set](../) under the intake
criteria v2.1 of the W3C Agent Conformance and Benchmarking Community Group
([public-agent-conformance, October 2026](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/)).
Its shape is the one the intake reader `agent_evidence_vectors.w3cintake` reads at
probityai/agent-evidence-vectors commit `7e501506c35ddfe5da64bb5885d668f505f7d6d3`,
the commit the criteria's CHECK lines pin. Every file here except `intake.py` and
this README is written by `intake.py`; none is edited by hand.

The record establishes byte agreement between `verify.mjs` and the expected values
in the pinned vector file, on those pinned inputs. It says nothing about
AgentAvow's grades, trust scores or answers.

## What the record claims about

The admitted population is the 76 checks `node verify.mjs` makes over
`tool-manifest-digest-v1-vectors.json`, named by the check identities the v0.1
reports in [../w3c-v01](../w3c-v01/) already use (`definition-digest/<key>`,
`key-encoding/NN`, `case/<vector>/<axis>`, `property/*` and three counts). The ids
are declared in `MANIFEST.json` from the vector file before the checker runs.

Why checks and not the seven cases: `verify.mjs` prints one `ok` or `FAIL` line per
check and nothing per case, so a per-check member carries one printed line as
printed. A per-case member would fold seven printed lines into one verdict.

Every check reads the same input file, so every member pins that file. A byte
change there is refused for all 76 members; the pin cannot say which item inside
the file moved.

The intake reader reads one native format, `corpus-result-json-v1`. `verify.mjs`
prints text, so `intake.py` re-encodes its stdout one printed line per member into
`native/verify-mjs.cases.json`, keeps the stdout bytes in
`native/verify-mjs.stdout`, and refuses to write anything unless the re-encoding
renders back to the stdout byte for byte. The intake reader checks the carried
lines against the re-encoding. It does not read the stdout file:
`runs/controls.txt` shows an edit to it admitted by the intake reader and refused
by `intake.py check`.

## Commands

The readers are pinned by commit. `intake.py` checks the intake reader's module
by its sha256 and records a sha256 listing of the files each outside reader's
glue imports.

    git clone https://github.com/probityai/agent-evidence-vectors aev
    git -C aev checkout 7e501506c35ddfe5da64bb5885d668f505f7d6d3
    git clone https://github.com/probityai/agent-evidence-vectors probity
    git -C probity checkout d759fb4db68a7fefcc91c2d3ad2a585471d6a53a
    git clone https://github.com/rufat325/heldfast heldfast
    git -C heldfast checkout ca5a872264b486907ed5479247e5150c5122d33d
    python3.14 -m venv .venv && .venv/bin/pip install cryptography==50.0.2 rfc8785==0.1.4

C1, from the repository root:

    PYTHONPATH=aev/packaging PYTHONHASHSEED=0 python3 -m agent_evidence_vectors.w3cintake \
      docs/standards/tool-manifest-digest-vectors-v1/w3c-intake/RECORD.json --root .

C2, the anchor's own check (also `python3 intake.py anchor-check`):

    git cat-file -e af5648c29360673a39d962b759c1430eb7116daa^{commit}
    git show af5648c29360673a39d962b759c1430eb7116daa:docs/standards/tool-manifest-digest-vectors-v1/w3c-intake/DIGESTS.txt \
      | grep -Fx -- "$(python3 -c "import json;r=json.load(open('docs/standards/tool-manifest-digest-vectors-v1/w3c-intake/RECORD.json'));print(r['anchor']['sha256']+'  '+r['anchor']['manifest'])")"

The full verification rebuilds every generated file from fresh runs of all three
readers and refuses on any differing byte, naming each differing JSON field:

    python3 intake.py check --intake-reader aev --probity probity --heldfast heldfast \
      --python .venv/bin/python

It compares whole files, not chosen fields. `runs/sweep.txt` applies 5597
single-field edits to `RECORD.json` (every leaf changed, every key and list element
deleted, a key inserted into every object): `check` refuses all of them; the
intake reader with the root refuses 2587. The rest are fields the intake reader
does not read, mostly evidence detail and inserted keys.

## Results on this tree

- C1 with `--root .`: exit 0, admitted; the first line lists W3C-I-002, 003, 008,
  019, 023, 024, 025, 026, 028 and 033 as run (`runs/c1.txt`).
- C2 against `af5648c29360673a39d962b759c1430eb7116daa`: exit 0.
- `node verify.mjs`: 76 checks, 76 `ok`, `all checks passed`, exit 0. The recount
  from the per-check lines agrees with the printed line and the exit code. The
  printed line states no total, so the total of 76 is a recount only.
- Three processes (one with `TZ=Pacific/Kiritimati LANG=C LC_ALL=C`) gave
  byte-identical stdout, sha256 `d5c6adef...dd9161`, on Node 22.22.0, macOS arm64.
- The three controls of ../w3c-v01, run as injected faults, each fail exactly
  their target check.
- Probity's map_reader at `d759fb4`: 67 of 67 checks agree. heldfast's
  profiles.py at `ca5a872`: 16 of 16. Both run through AgentAvow's glue in
  ../compat by the vector author, with the answers visible.

## Consumption (swap and re-pin)

Each of the 28 other files of the package was replaced by fixed bytes, every pin
over it was moved (its sha256 wherever another file writes it, transitively, and
the corpus digest in the manifest and the anchor list), and each reader was run
again.

- `node verify.mjs`: no observed effect for any of the 28. That includes
  `source.json`, `generate.mjs`, `time-contract.md`, `nanosecond-window-vectors.json`,
  `test-time.mjs`, the README and LICENSE, the compat glue and pins, and every file
  of ../w3c-v01. In the record's vocabulary each is `unconsumed`; read with
  2026Oct/0127, that is no observed effect for that mutation, checker and context,
  and does not alone establish that the file is never read. The source agrees:
  `verify.mjs` opens only the vector file (or the path given as its argument) and
  imports `time.mjs`. `source.json` and `generate.mjs` are the derivation of the
  vector file (`node generate.mjs`); `nanosecond-window-vectors.json` is read by
  `node --test test-time.mjs` and by `node verify.mjs nanosecond-window-vectors.json`,
  neither of which is this record's checker.
- Probity's glue: changed only when `compat/probity_compat.py` itself is swapped.
  heldfast's glue: changed only when `compat/heldfast_compat.py` is swapped.
- With its pin left in place, each swap is refused by the intake reader under
  W3C-I-002.

Fields inside the vector file, one at a time (`member-field-mutations` in the
record):

| field | verify.mjs | Probity (answers) | heldfast (answers) |
|---|---|---|---|
| `/issuer/jwk/x`, the verification key | changed | no observed effect | no observed effect |
| `/issuer/id` | no observed effect | no observed effect | no observed effect |
| `/issuer/jwks_url` | no observed effect | no observed effect | no observed effect |
| `/attestation/toolDigests/tool:ask_wiki_question` (unsigned copy) | changed | no observed effect | changed |
| `/attestation/payload_sha256` | no observed effect | changed | no observed effect |
| `/claim_ceiling` (prose) | no observed effect | no observed effect | no observed effect |
| `/vectors/0/note` (prose) | no observed effect | no observed effect | no observed effect |
| Probity's own `selection.json` key | not read | changed | not read |

`verify.mjs` verifies under the key carried in the vector file, so the key is
inside the pins and travels with what it verifies. Probity's reader verifies
under the key in its own `selection.json`, which the record pins by sha256. heldfast
compares against the unsigned digest map; `verify.mjs`'s
`unsigned-map-equals-signed` check is what ties that map to the signed payload.
Both outside readers' complete outputs echo the input file's sha256, so any byte
change to the vector file changes them; the "answers" column leaves that echo out.

## Anchor

`DIGESTS.txt` binds the corpus digest (member file and the 28 artifacts) to
`MANIFEST.json`. It was committed in `af5648c29360673a39d962b759c1430eb7116daa`,
which the record names. The anchor is a git commit: it binds content, and names no
signer. A consistent rewrite of the tree that moves every pin, the record and the
`DIGESTS.txt` line included, is admitted by C1 (which locates the line on disk)
and refused by C2 (which reads the line at the named commit); see
`runs/controls.txt`. Who published that commit rests on this repository and on the
list message that cites it. The commit must stay reachable: this record needs a
merge that keeps branch commits, or regeneration after a squash.

## Runs by other operators

On 2026-10-14 Nicolas Rocchia, who wrote none of the vectors, the readers or the
glue, ran `w3c-v01/emit.py` from `fbbbd4a` with `--runner-wrote none` (2026Oct/0101):
76/76, 67/67 and 16/16. The vector file, `verify.mjs`, `time.mjs` and the glue are
byte-identical at `fbbbd4a` and here. For `verify.mjs` that run is a reproduction
in O8's sense. For the two outside readers it is a run by someone who wrote neither
the reader nor the vectors, with the answers visible and through AgentAvow's glue.
It produced v0.1 reports; it predates this record and did not produce its native
output.

## Files

- `intake.py`: writes and checks everything below.
- `MANIFEST.json`, `DIGESTS.txt`: the closed manifest and the anchor list
  (committed first; that commit is the anchor).
- `RECORD.json`: the intake record.
- `native/verify-mjs.stdout`, `native/verify-mjs.cases.json`: the checker's stdout
  and its re-encoding.
- `runs/c1.txt`: C1 on the record, and the intake reader judging its own corpus.
- `runs/controls.txt`: mutations of the record and of the tree, with the grounds
  the intake reader gives and, for the anchor, C2.
- `runs/sweep.txt`: the single-field edit sweep.

`tests/standards/test_w3c_intake_record.py` checks the committed pins, the
manifest and anchor list, and a fresh native run against these files, offline.

Licensed under Apache-2.0 with the rest of this directory; see [`../LICENSE`](../LICENSE).
