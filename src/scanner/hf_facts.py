"""Hugging Face model facts: license, gating, and which weight files are really pickle.

The weight-format census used to judge a model by file EXTENSION. ``.bin`` is
ambiguous: PyTorch's ``pytorch_model.bin`` is a pickle (or a zip holding one), but an
OpenVINO IR ``openvino_model.bin`` is raw tensor bytes with no code path. Flagging the
second as "arbitrary code executes on load" was a false positive. Here an ambiguous
file is classified by its first bytes (an HTTP Range read of 16 bytes, no full
download), with a sibling-``.xml`` OpenVINO fallback when the read fails.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

HF_RESOLVE = "https://huggingface.co/{name}/resolve/main/{path}"
# Extensions whose format can't be told from the name alone; sniffed.
AMBIGUOUS_EXT = (".bin",)
MAX_SNIFFS = 8
_SNIFF_TIMEOUT = 6.0
_REDIRECTS = {301, 302, 303, 307, 308}

PICKLE, ZIP_PICKLE, RAW = "pickle", "zip-pickle", "raw"


def _hf_host(host: str) -> bool:
    host = (host or "").lower()
    return (host == "huggingface.co" or host.endswith(".huggingface.co")
            or host == "hf.co" or host.endswith(".hf.co"))


def classify_magic(head: bytes) -> str:
    """``pickle`` (protocol 2+ opcode header), ``zip-pickle`` (a zip: PyTorch's
    torch.save format, which stores a pickle inside), else ``raw``."""
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return PICKLE
    if head.startswith(b"PK\x03\x04"):
        return ZIP_PICKLE
    return RAW


def is_openvino_pair(path: str, all_paths: set[str]) -> bool:
    """An OpenVINO IR is ``<stem>.xml`` + ``<stem>.bin`` side by side."""
    return path.lower().endswith(".bin") and (path[:-4] + ".xml") in all_paths


async def _head_bytes(url: str, client: httpx.AsyncClient) -> bytes | None:
    """First 16 bytes of an HF file, following redirects only to HF hosts (each hop
    re-validated, SSRF-guarded). None on any failure."""
    from src.ssrf import validate_url_https

    try:
        cur = url
        for _hop in range(4):
            validate_url_https(cur, field_name="hf_file_url")
            if not _hf_host(urlparse(cur).hostname or ""):
                return None
            resp = await client.get(cur, headers={"Range": "bytes=0-15"},
                                    timeout=_SNIFF_TIMEOUT, follow_redirects=False)
            if resp.status_code in _REDIRECTS:
                loc = resp.headers.get("location")
                if not loc:
                    return None
                cur = str(httpx.URL(cur).join(loc))
                continue
            if resp.status_code not in (200, 206):
                return None
            return resp.content[:16]
        return None
    except (httpx.HTTPError, ValueError):
        return None


async def classify_weights(
    name: str, weight_paths: list[str], all_paths: set[str], client: httpx.AsyncClient,
) -> dict[str, str]:
    """Format of each ambiguous weight file (``pickle`` / ``zip-pickle`` / ``raw``).
    Unsniffable files fall back to the OpenVINO pairing rule, else stay ``pickle``
    (fail closed: an unknown ``.bin`` keeps the old, cautious reading)."""
    targets = [p for p in weight_paths if p.lower().endswith(AMBIGUOUS_EXT)][:MAX_SNIFFS]
    heads = await asyncio.gather(*[
        _head_bytes(HF_RESOLVE.format(name=name, path=p), client) for p in targets])
    out: dict[str, str] = {}
    for p, head in zip(targets, heads):
        if head:
            out[p] = classify_magic(head)
        else:
            out[p] = RAW if is_openvino_pair(p, all_paths) else PICKLE
    for p in weight_paths:
        if p.lower().endswith(AMBIGUOUS_EXT) and p not in out:
            out[p] = RAW if is_openvino_pair(p, all_paths) else PICKLE
    return out


def license_from_meta(meta: dict) -> str | None:
    """The model's license from its card metadata, else its ``license:`` tag."""
    card = meta.get("cardData") if isinstance(meta.get("cardData"), dict) else {}
    lic = card.get("license")
    if isinstance(lic, list):
        lic = ", ".join(str(x) for x in lic if x)
    if isinstance(lic, str) and lic.strip():
        return lic.strip()[:64]
    for t in meta.get("tags") or []:
        if isinstance(t, str) and t.startswith("license:") and len(t) > 8:
            return t[8:][:64]
    return None


def model_card_facts(hf: dict) -> dict:
    """The facts a person deciding whether to load the model wants, from the
    ``packaged_manifest['hf']`` block."""
    unsafe = hf.get("unsafe_weights") or []
    safe = hf.get("safe_weights") or []
    gated = hf.get("gated")
    return {
        "license": hf.get("license"),
        "gated": bool(gated) if not isinstance(gated, str) else gated,
        "pipeline_tag": hf.get("pipeline_tag"),
        "library_name": hf.get("library_name"),
        "safetensors": any(p.lower().endswith(".safetensors") for p in safe),
        "pickle_weights": len(unsafe),
        "safe_weights": len(safe),
        "raw_weights": len(hf.get("raw_weights") or []),
        "custom_code": len(hf.get("custom_code") or []),
    }
