"""Fail when the OpenAPI document breaks a client compared with the base branch.

    python scripts/openapi/breaking.py --base-ref origin/main
    python scripts/openapi/breaking.py --base old.json --head new.json

A break is anything a client written against the base document could trip over:

- an operation (method + path) removed;
- a parameter removed, a new required parameter, or an optional one made required;
- a request body newly required, a request media type removed, a request property
  removed, a new required request property, or a request type narrowed;
- a documented response status or media type removed, a response property removed or
  no longer always present, or a response type changed or widened;
- an enum value removed from a request field.

Adding operations, optional parameters, optional request properties, response
properties and response statuses is fine. Each break prints as one line. A break the
owner has approved is listed, with a reason, in docs/api/approved-breaks.json; that
file is reviewed in the PR like any other change (see docs/adr/0006-api-contract.md).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = "docs/api/openapi.json"
DEFAULT_APPROVED = ROOT / "docs" / "api" / "approved-breaks.json"
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_MAX_DEPTH = 40


class _Doc:
    """One OpenAPI document, for resolving local $refs."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec

    def resolve(self, node: object) -> tuple[dict, str | None]:
        """(schema, ref) with local $refs followed; ref is the last one followed."""
        ref = None
        seen: set[str] = set()
        while isinstance(node, dict) and isinstance(node.get("$ref"), str):
            ref = node["$ref"]
            if ref in seen or not ref.startswith("#/"):
                break
            seen.add(ref)
            target: object = self.spec
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                target = target.get(part, {}) if isinstance(target, dict) else {}
            node = target
        return (node if isinstance(node, dict) else {}), ref


def _non_null_members(schema: dict) -> list[dict] | None:
    for key in ("anyOf", "oneOf"):
        if isinstance(schema.get(key), list):
            return [m for m in schema[key] if not (isinstance(m, dict) and m.get("type") == "null")]
    return None


def _types(doc: _Doc, schema: dict, depth: int = 0) -> frozenset[str] | None:
    """The JSON types a schema allows, or None when it allows anything."""
    schema, _ = doc.resolve(schema)
    if depth > _MAX_DEPTH:
        return None
    out: set[str] = set()
    t = schema.get("type")
    if isinstance(t, str):
        out.add(t)
    elif isinstance(t, list):
        out.update(x for x in t if isinstance(x, str))
    if schema.get("nullable") is True:
        out.add("null")
    for key in ("anyOf", "oneOf"):
        members = schema.get(key)
        if isinstance(members, list):
            for m in members:
                mt = _types(doc, m, depth + 1)
                if mt is None:
                    return None
                out |= mt
    if not out:
        if "enum" in schema or "const" in schema:
            return None
        if "properties" in schema:
            return frozenset({"object"})
        if "items" in schema:
            return frozenset({"array"})
        return None
    return frozenset(out)


def _covers(wide: frozenset[str], narrow: frozenset[str]) -> bool:
    """Every type in ``narrow`` is allowed by ``wide`` (integer counts as a number)."""
    return all(t in wide or (t == "integer" and "number" in wide) for t in narrow)


def _fmt(types: frozenset[str] | None) -> str:
    return "any" if types is None else "|".join(sorted(types))


class Checker:
    def __init__(self, base: dict, head: dict) -> None:
        self.base = _Doc(base)
        self.head = _Doc(head)
        self.breaks: list[str] = []

    def _add(self, where: str, what: str) -> None:
        self.breaks.append(f"{where}: {what}")

    # --- schemas ---------------------------------------------------------------

    def schema(self, b: object, h: object, direction: str, where: str, at: str,
               seen: frozenset[tuple[str | None, str | None]] = frozenset(),
               depth: int = 0) -> None:
        """Compare one schema. direction is 'request' (client writes it) or 'response'
        (client reads it). ``at`` is the field path shown in the message."""
        bs, bref = self.base.resolve(b)
        hs, href = self.head.resolve(h)
        if depth > _MAX_DEPTH or (bref is not None and (bref, href) in seen):
            return
        if bref is not None:
            seen = seen | {(bref, href)}
        label = at or "body"

        bt, ht = _types(self.base, bs), _types(self.head, hs)
        if direction == "response":
            if bt is not None and (ht is None or not _covers(bt, ht)):
                self._add(where, f"{label} type changed from {_fmt(bt)} to {_fmt(ht)}")
                return
        elif ht is not None and (bt is None or not _covers(ht, bt)):
            self._add(where, f"{label} type changed from {_fmt(bt)} to {_fmt(ht)}")
            return

        if direction == "request":
            benum, henum = bs.get("enum"), hs.get("enum")
            if isinstance(henum, list):
                if not isinstance(benum, list):
                    self._add(where, f"{label} now limited to the values {henum}")
                else:
                    gone = [v for v in benum if v not in henum]
                    if gone:
                        self._add(where, f"{label} no longer accepts {gone}")

        # Optional[X] is anyOf [X, null]: compare the X on each side.
        bm, hm = _non_null_members(bs), _non_null_members(hs)
        if bm is not None and len(bm) == 1:
            bs, _ = self.base.resolve(bm[0])
        if hm is not None and len(hm) == 1:
            hs, _ = self.head.resolve(hm[0])

        bprops, hprops = bs.get("properties"), hs.get("properties")
        if isinstance(bprops, dict) and isinstance(hprops, dict):
            breq = set(bs.get("required") or [])
            hreq = set(hs.get("required") or [])
            for name in sorted(bprops):
                sub = f"{at}.{name}" if at else name
                if name not in hprops:
                    what = "removed" if direction == "response" else "no longer accepted"
                    self._add(where, f"{direction} property '{sub}' {what}")
                    continue
                if direction == "response" and name in breq and name not in hreq:
                    self._add(where, f"response property '{sub}' no longer always present")
                self.schema(bprops[name], hprops[name], direction, where, sub, seen, depth + 1)
            if direction == "request":
                for name in sorted(hreq - breq):
                    sub = f"{at}.{name}" if at else name
                    self._add(where, f"request property '{sub}' is newly required")
        elif isinstance(bprops, dict) and bprops and direction == "response":
            # The base promised named fields; the head promises none.
            for name in sorted(bprops):
                sub = f"{at}.{name}" if at else name
                self._add(where, f"response property '{sub}' removed")
        elif isinstance(hprops, dict) and direction == "request":
            for name in sorted(set(hs.get("required") or [])):
                sub = f"{at}.{name}" if at else name
                self._add(where, f"request property '{sub}' is newly required")

        if "items" in bs and "items" in hs:
            self.schema(bs["items"], hs["items"], direction, where, f"{at}[]", seen, depth + 1)

    # --- operations ------------------------------------------------------------

    @staticmethod
    def _params(path_item: dict, op: dict, doc: _Doc) -> dict[tuple[str, str], dict]:
        out: dict[tuple[str, str], dict] = {}
        for p in list(path_item.get("parameters") or []) + list(op.get("parameters") or []):
            p, _ = doc.resolve(p)
            if "name" in p and "in" in p:
                out[(p["in"], p["name"])] = p
        return out

    def _content(self, bc: dict, hc: dict, direction: str, where: str, label: str) -> None:
        for media in sorted(bc):
            if media not in hc:
                self._add(where, f"{label} media type {media} removed")
                continue
            bschema = (bc[media] or {}).get("schema")
            hschema = (hc[media] or {}).get("schema")
            if bschema is not None:
                self.schema(bschema, hschema if hschema is not None else {}, direction,
                            f"{where} {label} {media}", "")

    def operation(self, where: str, bitem: dict, bop: dict, hitem: dict, hop: dict) -> None:
        bparams = self._params(bitem, bop, self.base)
        hparams = self._params(hitem, hop, self.head)
        for key in sorted(bparams):
            loc, name = key
            if key not in hparams:
                self._add(where, f"{loc} parameter '{name}' removed")
                continue
            if hparams[key].get("required") and not bparams[key].get("required"):
                self._add(where, f"{loc} parameter '{name}' became required")
            self.schema(bparams[key].get("schema") or {}, hparams[key].get("schema") or {},
                        "request", where, f"{loc} parameter '{name}'")
        for key in sorted(set(hparams) - set(bparams)):
            if hparams[key].get("required"):
                self._add(where, f"new required {key[0]} parameter '{key[1]}'")

        bbody, _ = self.base.resolve(bop.get("requestBody")) if bop.get("requestBody") else ({}, None)
        hbody, _ = self.head.resolve(hop.get("requestBody")) if hop.get("requestBody") else ({}, None)
        if hbody.get("required") and not bbody.get("required"):
            self._add(where, "request body became required")
        if bbody:
            self._content(bbody.get("content") or {}, hbody.get("content") or {},
                          "request", where, "request body")

        bresp, hresp = bop.get("responses") or {}, hop.get("responses") or {}
        for status in sorted(bresp):
            if status not in hresp:
                self._add(where, f"response {status} removed")
                continue
            br, _ = self.base.resolve(bresp[status])
            hr, _ = self.head.resolve(hresp[status])
            self._content(br.get("content") or {}, hr.get("content") or {},
                          "response", where, f"response {status}")

    def run(self) -> list[str]:
        bpaths = self.base.spec.get("paths") or {}
        hpaths = self.head.spec.get("paths") or {}
        for path in sorted(bpaths):
            bitem = bpaths[path] or {}
            hitem = hpaths.get(path) or {}
            for method in METHODS:
                if method not in bitem:
                    continue
                where = f"{method.upper()} {path}"
                if method not in hitem:
                    self._add(where, "operation removed")
                    continue
                self.operation(where, bitem, bitem[method], hitem, hitem[method])
        return sorted(set(self.breaks))


def find_breaks(base: dict, head: dict) -> list[str]:
    """Every break from ``base`` to ``head``, one line each, sorted."""
    return Checker(base, head).run()


# --- approvals -----------------------------------------------------------------


def load_approved(path: Path) -> list[dict]:
    """The approved-breaks entries. Each needs a ``break`` pattern and a ``reason``."""
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("approved") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected an object with an 'approved' list")
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not str(e.get("break") or "").strip():
            raise ValueError(f"{path}: entry {i} needs a 'break' line")
        if not str(e.get("reason") or "").strip():
            raise ValueError(f"{path}: entry {i} ({e['break']!r}) needs a 'reason'")
    return entries


def _pattern(text: str) -> re.Pattern[str]:
    """An approved line matches exactly, except that * matches any run of characters."""
    return re.compile("".join(".*" if c == "*" else re.escape(c) for c in text) + r"\Z")


def split_approved(breaks: list[str], approved: list[dict]) -> tuple[list[str], list[str], list[dict]]:
    """(unapproved breaks, approved breaks, approval entries that matched nothing)."""
    patterns = [(e, _pattern(e["break"])) for e in approved]
    used: set[int] = set()
    left, ok = [], []
    for b in breaks:
        hit = next((i for i, (_, p) in enumerate(patterns) if p.match(b)), None)
        if hit is None:
            left.append(b)
        else:
            used.add(hit)
            ok.append(b)
    unused = [e for i, (e, _) in enumerate(patterns) if i not in used]
    return left, ok, unused


def _git_show(ref: str) -> dict | None:
    proc = subprocess.run(
        ["git", "show", f"{ref}:{DOC_PATH}"], cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        return None
    return json.loads(proc.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--base-ref", help=f"git ref whose {DOC_PATH} is the baseline")
    src.add_argument("--base", type=Path, help="baseline document file")
    parser.add_argument("--head", type=Path, default=ROOT / DOC_PATH)
    parser.add_argument("--approved", type=Path, default=DEFAULT_APPROVED)
    args = parser.parse_args(argv)

    if args.base_ref:
        base = _git_show(args.base_ref)
        if base is None:
            print(f"{args.base_ref} has no {DOC_PATH}; nothing to compare against.")
            return 0
        base_name = args.base_ref
    else:
        base = json.loads(args.base.read_text(encoding="utf-8"))
        base_name = str(args.base)
    head = json.loads(args.head.read_text(encoding="utf-8"))

    breaks = find_breaks(base, head)
    left, ok, unused = split_approved(breaks, load_approved(args.approved))
    for b in ok:
        print(f"approved break: {b}")
    for e in unused:
        print(f"note: approval no longer matches anything (safe to delete): {e['break']}")
    if left:
        print(
            f"\n{len(left)} breaking change(s) in {DOC_PATH} compared with {base_name}:\n",
            file=sys.stderr,
        )
        for b in left:
            print(f"  {b}", file=sys.stderr)
        print(
            "\nClients written against the base document would break. Make the change "
            "additive (keep the old field, parameter or route next to the new one), or, "
            "if the owner approves the break, add each line above to "
            "docs/api/approved-breaks.json with a reason. See docs/adr/0006-api-contract.md.",
            file=sys.stderr,
        )
        return 1
    print(f"No breaking changes in {DOC_PATH} compared with {base_name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
