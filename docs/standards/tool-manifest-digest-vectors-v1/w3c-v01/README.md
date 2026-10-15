# v0.1 records for the tool-manifest-digest v1 vectors

This directory turns runs of the [v1 vector set](../) into reports in the v0.1
reporting format of the W3C Agent Conformance and Benchmarking Community Group
([public-agent-conformance 2026Sep/0087](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0087.html)).
There is one report per implementation, one producer per report, one per-check
record per check that implementation makes, and a control built to fail, run
under the same checker revision and configuration (section 5.4).

The records establish byte agreement between each implementation's output and
the expected values in the pinned vector file, on those pinned inputs. They say
nothing about AgentAvow's safety grades, trust scores or answers.

## Command

    python3.14 -m venv .venv
    .venv/bin/pip install cryptography==50.0.2 rfc8785==0.1.4
    .venv/bin/python emit.py --runner "Kenne Ives (AgentAvow)" --runner-wrote vectors,native --out records

`emit.py` clones the two pinned repositories into `--work` (default: a directory
under the system temp directory) the first time it runs; that is the only
network access. `--probity DIR` and `--heldfast DIR` use existing checkouts
instead; each must be at its pinned commit with no local changes. The two
package pins are the ones in Probity's requirements file at its pinned commit.

The committed records were written with Node v22.22.0, Python 3.14.3 (for both
the emitter and the readers), cryptography 50.0.2 and rfc8785 0.1.4, on macOS
arm64. The emitter itself needs Python 3.9 or newer and the standard library;
Probity's reader needs Python 3.13 or newer (pass that interpreter as
`--python` if it is not the one running `emit.py`); `verify.mjs` needs Node 18
or newer.

sha256 of `records/SHA256SUMS`:
`0d47327bbaf5b172b8c3e30151df18920bd05ff0b9af21c08ec1153fa010eb3c`

The records posted on 14 October were emitted at `fbbbd4a`, where this digest was
`c720c68a4dfe0f196ef132c8428649df11152d541403b342db37aad939acd82e`. The only change
since is the run label for other runners (see "Run it yourself"); every check
result is the same. Because `emit.py` is pinned in each configuration, the
configuration digests and therefore `SHA256SUMS` changed with it.

## What runs

| report | implementation | written by | relationship to the vectors | checks | controls |
|---|---|---|---|---|---|
| `native-verify-mjs` | `../verify.mjs` with `../time.mjs` | AgentAvow | same implementation as the vector producer | 76 | 3 |
| `probity-map-reader` | `map_reader.py` in `probityai/agent-evidence-vectors` at `d759fb4` ([`compat/probity-pin.json`](../compat/probity-pin.json)) | Probity | implementation written from the specification | 67 | 3 |
| `heldfast-profiles` | `src/heldfast/profiles.py` in `rufat325/heldfast` at `ca5a872` ([`compat/heldfast-pin.json`](../compat/heldfast-pin.json)) | heldfast | implementation written from the specification | 16 | 2 |

Every check in all three reports is `pass`. The committed runs were made by
the vector author, so each run label in `records/run.json` reads "run by the
vector author". None of them is an independent record.

Check identities are shared where the question is the same:
`definition-digest/<key>` (the digest recomputed from each served definition
against the signed one), `definition-count`, `key-encoding/NN` (index into the
file's thirteen name-to-key pairs) and `case/<vector>/<axis>` (each expected
axis of the seven cases, `rely` included). The native verifier also reports
`unsigned-map-equals-signed`, `key-encoding-count` and its eight
`property/*` checks; Probity's reader also reports `payload-digest`. A check
passes when the implementation's output equals the value the vector file
states for it.

The Python readers run through glue that only calls their functions and writes
the answers as JSON: [`compat/probity_compat.py`](../compat/probity_compat.py)
and [`compat/heldfast_compat.py`](../compat/heldfast_compat.py). Neither
reimplements any encoding, hashing or verification. Probity's own driver,
`run_agentavow.py`, refuses this vector file because its bytes differ from the
one Probity locked at producer commit `36426cf` (the `boundary-fresh` case was
added after), so the glue runs the same sequence on the current file.

## Controls (section 5.4)

Each control is the vector file with one stated change, written to
`records/controls/`, and run through the same checker and configuration as the
report it speaks for:

- `control-key-encoding-01`: the expected key for `a=b` is written as
  `tool:a=b` instead of `tool:a%3Db`. Built to fail `key-encoding/01`.
- `control-definition-ask_wiki_question`: one sentence appended to the served
  description of `ask_wiki_question`. Built to fail
  `definition-digest/tool:ask_wiki_question`.
- `control-case-tool-drift`: the `tool-drift` case expects
  `tool_digest_binds` true. Built to fail `case/tool-drift/tool_digest_binds`.
  Not run against heldfast, which makes no case checks.

The emitter writes nothing unless each control flips exactly its target check
to `fail` and leaves every other check of that implementation unchanged.
`records/controls.json` holds one record per control and implementation in the
shape proposed in section 5.5 (not normative in v0.1), with the observed result.
Each report's roll-up names its controls as `negative-capable` of kind
`control-failed`, with the report's own `fixed` binding, and each target check
carries `other-verdict` and `discrimination` as `demonstrated`, referencing an
evidence object that carries both observations (the pinned file passes, the
control fails). The evidence-completeness claim is `not-satisfied`, because
the other checks have no such pair.

## Validation with the reference reader

The reports were validated with `agent_evidence_vectors.w3creport` from
[`probityai/agent-evidence-vectors` release v0.18.1](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.18.1)
(commit `33d545104ff2f8c124cff465c96c013eeb809156`):

    git clone https://github.com/probityai/agent-evidence-vectors aev
    git -C aev checkout v0.18.1
    .venv/bin/python validate.py --reader aev --records records

Output:

    reference reader agent_evidence_vectors.w3creport at v0.18.1 (33d545104ff2)
    heldfast-profiles.json: checks 16, shape errors [], rejections [], check-set root recomputes
    native-verify-mjs.json: checks 76, shape errors [], rejections [], check-set root recomputes
    probity-map-reader.json: checks 67, shape errors [], rejections [], check-set root recomputes
    result: every report conforms

`validate.py` only calls the reader's `shape_errors`, `rejections` and
`check_set_root`. The check set is digested as `jcs-sha256` (RFC 8785, integers
within plus or minus 2^53-1, no floats) under tree shape `flat`, and each
binding declares `"digest-encoding": "jcs-sha256"`. The reader's corpus marks
that encoding rule as proposed (`W3C-R-030` to `W3C-R-032`), since v0.1 does
not say which bytes a digest over a JSON value is taken over.

## Determinism and the runner string

Two runs with the same arguments in the same environment gave byte-identical
output (same `SHA256SUMS`). `--runner`, `--runner-wrote` and the environment
(Node, Python and package versions, operating system) are written to
`records/run.json` and nowhere else; no clock is read. A run with a different
`--runner` string changes exactly two files: `run.json` and `SHA256SUMS`. A
different environment changes the same two files, unless an implementation
answers differently, which would change its report. Running the emitter
itself under Python 3.9.6 instead of 3.14.3 (readers unchanged) changed only
`run.json` and `SHA256SUMS`.

`--runner-wrote` is the runner's own statement of what they authored
(`vectors`, `native`, `probity`, `heldfast`, or `none`). It sets the run label
for each implementation in `run.json`; it is declared, not checked.

## Limits

- Byte agreement on pinned inputs only: one pinned attestation for one server,
  its three served definitions, thirteen name-to-key pairs and seven cases.
  Nothing here is about AgentAvow's grades, about runtime behavior, or about
  any other server or tool. Each report carries the claim ceiling its reader
  states, in `claim-ceiling`.
- The expected answers are in the vector file and were visible to every
  implementation's author and to every runner. Agreement shows the outputs
  match; it does not show the outputs were reached without seeing them.
- `verify.mjs` is the vector producer's own implementation. Probity's reader
  and heldfast were written from the published rules by other parties. All
  three runs here were made by the vector author.
- Probity's reader verifies the signature under the key in its own
  `selection.json`, not the key in the vector file, and its `rely` also
  requires an `issuer_binds` axis of its own; on all seven cases its `rely`
  equals the expected value.
- heldfast's claim covers the three served-definition digests and the thirteen
  key pairs only, and it is asked nothing else. Like its own test, it compares
  against the unsigned `attestation.toolDigests` map in the file; the native
  verifier's `unsigned-map-equals-signed` check is what ties that map to the
  signed payload.
- The control inputs and the check mapping are AgentAvow's. A control shows
  that each target check can return `fail` under the pinned checker and
  configuration; it is not a second-order check of every rule.
- The checks on the pinned checkouts (commit and clean tracked files) are
  snapshots, not barriers against a hostile file system or interpreter.

## Not emitted

- APS-side consumer (`agent-passport-system` 7.2.0,
  `examples/interop/agentavow` at `fd47f34`): no v1 run of it has been
  reported. Its reported run is of the v0 vectors, and the [v1 README](../README.md#separate-implementations)
  lists it as awaiting a v1 report. There is no v1 result to record, so no
  record is emitted. This is also in `records/not-emitted.json`.

## Run it yourself

A run of the native verifier by anyone other than AgentAvow is a reproduction:
it is the vector producer's own code. For the Probity and heldfast readers, a
run by someone who wrote neither the vectors nor that reader is the nearest
thing to an independent record this set has, with two limits: the expected
answers are visible, and the readers run through our glue. The first such run
was posted on 14 October (Nicolás Rocchia, from `fbbbd4a`, `--runner-wrote
none`). Before this fix, `run.json` labelled all three of those runs "an
independent run"; the native label now says reproduction. If you are in that
position, run the command above with your own `--runner` and
`--runner-wrote none`, and post your `SHA256SUMS` digest with your Node and
Python versions. If your environment matches, every file except `run.json`
and `SHA256SUMS` should be byte-identical to `records/`; if a report differs,
that difference is the finding. Nothing here needs permission from AgentAvow.

## Files

- `emit.py`: the emitter (standard library only).
- `validate.py`: runs the reference reader over `records/reports/`.
- `records/reports/*.json`: one v0.1 report per implementation.
- `records/configs/*.json`: the configuration each report names in
  `fixed.constraint-set`, by path and sha256 (checker, input digests, driver
  file digests, controls, check mapping).
- `records/controls/*.json`: the three control inputs.
- `records/controls.json`: one section 5.5 shaped record per control and
  implementation, with the observed result.
- `records/not-emitted.json`: implementations with no record, and why.
- `records/run.json`: runner, run labels and environment.
- `records/SHA256SUMS`: one line per file above, sorted by path.

The tests in `tests/standards/test_w3c_v01_records.py` check the committed
records against `SHA256SUMS`, recompute each check-set root and roll-up, and
fail if the vectors, the verifier, the drivers or the emitter change without a
fresh emission.

Licensed under Apache-2.0 with the rest of this directory; see [`../LICENSE`](../LICENSE).
