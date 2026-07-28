#!/usr/bin/env python3
"""Mutation / negative test for the AlgoVoi JCS conformance corpus + runner.

For EVERY hex64 (digest-shaped) field in every vector file, substitute a
deterministically fabricated-but-well-formed value (sha256("MUTATED:"+original))
and re-run the ACTUAL conformance runner (docs/conformance/algovoi-jcs-v1/run_conformance.py)
over the mutated corpus. Record whether the runner now REJECTS (>=1 new failure -> the
mutation was caught) or still ACCEPTS (0 failures -> the digest is not actually enforced =
an ESCAPE / blind spot).

This mutates the STORED digest and asks the real verifier: did you notice?

    ./.venv/bin/python scripts/dev/mutation_test_vectors.py
"""
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VEC_DIR = os.path.join(REPO, "docs/conformance/algovoi-jcs-v1/vectors")
RUNNER = os.path.join(REPO, "docs/conformance/algovoi-jcs-v1/run_conformance.py")
PY = sys.executable


def is_hex64(s):
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


def fabricate(orig):
    return hashlib.sha256(("MUTATED:" + orig).encode()).hexdigest()


def enumerate_fields(obj, path="$"):
    """Yield (json_path, key_name, value) for every hex64 leaf, in traversal order.

    json_path is descriptive only (may be ambiguous when key names contain dots);
    mutation is performed by ordinal position via set_by_ordinal, not by this path.
    """
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if is_hex64(v):
                out.append((p, k, v))
            else:
                out.extend(enumerate_fields(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(enumerate_fields(v, f"{path}[{i}]"))
    return out


def set_by_ordinal(obj, ordinal, newval):
    """Mutate the ordinal-th hex64 leaf in the SAME traversal order enumerate_fields uses."""
    counter = [0]

    def walk(node):
        if isinstance(node, dict):
            for k in list(node.keys()):
                v = node[k]
                if is_hex64(v):
                    if counter[0] == ordinal:
                        node[k] = newval
                        counter[0] += 1
                        return True
                    counter[0] += 1
                else:
                    if walk(v):
                        return True
        elif isinstance(node, list):
            for i in range(len(node)):
                v = node[i]
                if is_hex64(v):
                    if counter[0] == ordinal:
                        node[i] = newval
                        counter[0] += 1
                        return True
                    counter[0] += 1
                else:
                    if walk(v):
                        return True
        return False

    return walk(obj)


BINDING = os.path.join(REPO, "docs/conformance/algovoi-jcs-v1/verify_binding.py")


def run_runner(vec_dir):
    env = dict(os.environ, VECTORS_DIR=vec_dir)
    r = subprocess.run([PY, RUNNER], capture_output=True, text=True, env=env)
    # Parse the TOTAL line for failure count.
    fails = None
    for line in r.stdout.splitlines():
        m = re.search(r"\((\d+) failures\)", line)
        if m:
            fails = int(m.group(1))
    return r.returncode, fails, r.stdout


def run_binding(vec_dir):
    """Our recompute-binding verifier: nonzero exit == rejected the corpus."""
    env = dict(os.environ, VECTORS_DIR=vec_dir)
    r = subprocess.run([PY, BINDING], capture_output=True, text=True, env=env)
    return r.returncode != 0


def main():
    work = tempfile.mkdtemp(prefix="mut_corpus_")
    for f in glob.glob(os.path.join(VEC_DIR, "*.json")):
        shutil.copy(f, work)

    rc, base_fails, _ = run_runner(work)
    print(f"BASELINE: exit={rc} failures={base_fails}")
    if base_fails != 0:
        print("!! baseline is not clean; aborting")
        return 2

    # Build the field inventory: (basename, ordinal_within_file, json_path, key, orig)
    files = sorted(glob.glob(os.path.join(VEC_DIR, "*.json")))
    inventory = []
    for f in files:
        b = os.path.basename(f)
        if "package" in b:
            continue
        data = json.load(open(f))
        for j, (p, k, v) in enumerate(enumerate_fields(data)):
            inventory.append((b, j, p, k, v))

    total = len(inventory)
    print(f"TOTAL hex64 (digest-shaped) fields to mutate: {total}\n")

    caught = []
    escaped = []
    caught_combined = []
    escaped_combined = []
    orig_cache = {b: open(os.path.join(work, b)).read() for b in {i[0] for i in inventory}}

    for n, (b, j, p, k, orig) in enumerate(inventory, 1):
        target = os.path.join(work, b)
        data = json.loads(orig_cache[b])
        assert set_by_ordinal(data, j, fabricate(orig)), f"failed to locate ordinal {j} in {b}"
        with open(target, "w") as fh:
            json.dump(data, fh)
        rc, fails, _ = run_runner(work)
        jcs_caught = bool(fails and fails > 0)
        bind_caught = run_binding(work) if not jcs_caught else False
        # restore
        with open(target, "w") as fh:
            fh.write(orig_cache[b])
        rec = (b, p, k, orig, fails)
        (caught if jcs_caught else escaped).append(rec)
        if jcs_caught or bind_caught:
            caught_combined.append(rec)
        else:
            escaped_combined.append(rec)

    print("=" * 78)
    print("MUTATION TEST RESULT")
    print("=" * 78)
    print(f"  digest-shaped fields mutated : {total}")
    print(f"  CAUGHT (runner rejected)     : {len(caught)}")
    print(f"  ESCAPED (runner still PASSED): {len(escaped)}")
    print()

    # Break escapes down by key name.
    from collections import Counter
    esc_by_key = Counter(k for _, _, k, _, _ in escaped)
    print("ESCAPES by field key name:")
    for k, c in esc_by_key.most_common():
        print(f"  {c:3d}  {k}")
    print()
    print("Full escape list (file :: json_path :: key):")
    for b, p, k, orig, fails in escaped:
        print(f"  ESCAPE  {b}  {p}  [{k}]")

    print()
    print(f"HEADLINE (JCS runner only):      {len(caught)}/{total} mutated digest-shaped fields rejected.")
    print(f"HEADLINE (JCS + binding verifier): {len(caught_combined)}/{total} rejected "
          f"({len(escaped_combined)} still escape).")
    # What the binding verifier newly closed:
    newly = [r for r in caught_combined if r in escaped]
    print(f"  binding verifier newly caught: {len(newly)} fields "
          f"(previously escaped the JCS runner).")
    from collections import Counter
    for k, c in Counter(k for _, _, k, _, _ in newly).most_common():
        print(f"    +{c:3d}  {k}")

    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
