"""Container image checks that need the network, run after the layer walk.

``scan_package`` calls :func:`apply_docker_image_extras` for ``docker`` coordinates,
after the static engine has graded the image's own files and before scoring:

* **CVE check** — the installed-package inventory from
  :mod:`src.scanner.docker_layers` (dpkg / apk OS packages by their distro *source*
  package, plus Python and npm packages) goes to OSV ``querybatch``. Only advisories
  with a released fix are reported: "rebuild on an updated base image" is something
  the image author can act on, while a distro CVE with no fix anywhere is not. They are
  ``dependency`` findings, so like every dependency advisory they never decide the
  answer and their score cost is the bounded, saturating dependency penalty (OS
  packages weigh as transitive). A known-malicious (OpenSSF MAL) package is the
  exception, exactly as for repos.
* **Provenance** — cosign signatures (``sha256-<digest>.sig``, keyless Fulcio
  certificate), cosign attestations (``.att``, DSSE in-toto) and OCI referrers carrying
  a Sigstore bundle, all looked up by the image's digest and verified offline with the
  same gates as npm/PyPI provenance (trusted CI issuer, identity bound to the image's
  declared source repo, signed digest equals the image's digest). Unsigned images read
  "none published", which is N/A, never a penalty.
* **Image summary** — ``artifact_scan["image"]``: what was actually read (layers, app
  files, packages, distro) for the Check page's scan-depth line.

Fail-open throughout: any network or parse error leaves that part out and says so; an
image scan never fails because OSV or a registry hiccuped.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from datetime import datetime, timezone

import httpx

from src.scanner.docker_layers import ImagePackage, os_label, osv_ecosystem
from src.scanner.lockfiles import Dep
from src.scanner.supply_chain import OSV_BATCH_URL, OSV_VULN_URL, is_malicious, summarize_osv

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 12.0
_OSV_BATCH = 1000            # OSV querybatch limit per request
_MAX_HYDRATE = 600           # vuln records fetched for fix + severity
_HYDRATE_CONCURRENCY = 16
_VULN_TIME_BUDGET = 35.0     # seconds for the whole CVE check
_PROV_TIME_BUDGET = 20.0     # seconds for the signature lookups

_SIG_ANNOTATION = "dev.cosignproject.cosign/signature"
_CERT_ANNOTATION = "dev.sigstore.cosign/certificate"
_BUNDLE_ANNOTATION = "dev.sigstore.cosign/bundle"
_DSSE_MEDIA = "application/vnd.dsse.envelope.v1+json"
_SIMPLESIGN_MEDIA = "application/vnd.dev.cosign.simplesigning.v1+json"
# Fulcio certificate extensions (github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
_OID_SOURCE_REPO_URI = "1.3.6.1.4.1.57264.1.12"
_OID_SOURCE_REPO_DIGEST = "1.3.6.1.4.1.57264.1.13"
_OID_GITHUB_WORKFLOW_SHA = "1.3.6.1.4.1.57264.1.3"

COSIGN_VERIFY_METHOD = (
    "cosign keyless signature: ECDSA/RSA/Ed25519 over the signed payload against the "
    "Fulcio leaf certificate (cryptography, offline); trusted-CI issuer + source-repo "
    "identity gate; signed image digest must equal the scanned image's digest. "
    "NOT anchored to Fulcio TUF trust-root; Rekor inclusion NOT proven offline."
)


# ---------------------------------------------------------------------------------------
# CVE check
# ---------------------------------------------------------------------------------------
def image_deps(packages: list[ImagePackage], os_release: dict) -> tuple[list[Dep], str | None]:
    """OSV query entries for the inventory, deduplicated. OS packages are queried by
    their distro source package (one source builds many binary packages) and marked
    transitive; language packages keep full weight. Returns ``(deps, os_ecosystem)``;
    OS packages are left out when the distro isn't one OSV indexes."""
    os_eco = osv_ecosystem(os_release)
    deps: list[Dep] = []
    seen: set = set()
    for p in packages:
        if p.kind == "os":
            if not os_eco:
                continue
            key = (os_eco, p.source or p.name, p.source_version or p.version)
            dep = Dep(ecosystem=os_eco, name=key[1], version=key[2], direct=False)
        elif p.ecosystem in ("PyPI", "npm"):
            key = (p.ecosystem, p.name.lower() if p.ecosystem == "PyPI" else p.name,
                   p.version)
            dep = Dep(ecosystem=p.ecosystem, name=p.name, version=p.version)
        else:
            continue
        if key in seen:
            continue
        seen.add(key)
        deps.append(dep)
    return deps, os_eco


def has_released_fix(vuln: dict, dep: Dep) -> bool:
    """True when the advisory names a fixed version for this package in this ecosystem
    (a ``fixed`` event in one of its ranges). Known-malicious records always count."""
    if is_malicious(vuln):
        return True
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if str(pkg.get("ecosystem") or "") != dep.ecosystem:
            continue
        if str(pkg.get("name") or "").lower() != dep.name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in (rng or {}).get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    return True
    return False


def fixed_version(vuln: dict, dep: Dep) -> str | None:
    """The first fixed version listed for this package (for the remediation line)."""
    for aff in vuln.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        if str(pkg.get("ecosystem") or "") != dep.ecosystem \
                or str(pkg.get("name") or "").lower() != dep.name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in (rng or {}).get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    return str(ev["fixed"])
    return None


def reduce_image_vulns(
    deps: list[Dep], batch: list[dict], details: dict[str, dict], *, label: str,
) -> tuple[list[dict], dict]:
    """Pure: OSV batch results + hydrated records → (finding dicts, summary). Keeps only
    advisories with a released fix (and MAL records); an advisory whose record couldn't
    be fetched is counted as unchecked, never reported as a finding."""
    filtered: list[dict] = []
    total_ids: set = set()
    fixable_ids: set = set()
    unchecked: set = set()
    fixed_for: dict = {}
    for idx, res in enumerate(batch):
        if idx >= len(deps) or not isinstance(res, dict):
            filtered.append({})
            continue
        dep = deps[idx]
        keep = []
        for v in res.get("vulns") or []:
            vid = str(v.get("id", "")) if isinstance(v, dict) else str(v)
            if not vid:
                continue
            total_ids.add(vid)
            detail = details.get(vid)
            if detail is None:
                unchecked.add(vid)
                continue
            if has_released_fix(detail, dep):
                fixable_ids.add(vid)
                keep.append({"id": vid})
                fixed_for[(dep.name, dep.version, vid)] = fixed_version(detail, dep)
        filtered.append({"vulns": keep})
    findings, counts, malicious = summarize_osv(deps, filtered, details, lockfile_path=label)
    for f in findings:
        if f["name"].startswith("Known-malicious"):
            continue
        # "Vulnerable dependency: <name>@<version> (<id>)" → name the fixed release.
        try:
            coord, vid = f["name"].split(": ", 1)[1].rsplit(" (", 1)
            name, version = coord.rsplit("@", 1)
            fixed = fixed_for.get((name, version, vid.rstrip(")")))
        except ValueError:
            fixed = None
        if fixed:
            f["remediation"] = (
                f"Fixed in {name} {fixed}. Rebuild on an updated base image "
                "(or upgrade the package) to pick it up."
            )
    summary = {
        "ok": True,
        "vulns_total": len(total_ids),
        "fixable": len(fixable_ids),
        "unfixed": len(total_ids - fixable_ids - unchecked),
        "unchecked": len(unchecked),
        "counts": counts,
        "malicious": malicious,
    }
    return findings, summary


async def _hydrate(ids: list[str], client: httpx.AsyncClient, deadline: float) -> dict:
    sem = asyncio.Semaphore(_HYDRATE_CONCURRENCY)
    out: dict[str, dict] = {}

    async def one(vid: str) -> None:
        async with sem:
            if time.monotonic() > deadline:
                return
            try:
                r = await client.get(OSV_VULN_URL.format(vuln_id=vid), timeout=_HTTP_TIMEOUT)
                if r.status_code == 200:
                    out[vid] = r.json()
            except (httpx.HTTPError, ValueError):
                return

    await asyncio.gather(*(one(v) for v in ids[:_MAX_HYDRATE]))
    return out


async def check_image_vulnerabilities(
    packages: list[ImagePackage], os_release: dict, *, client: httpx.AsyncClient,
    time_budget: float = _VULN_TIME_BUDGET,
) -> tuple[list[dict], dict]:
    """OSV check of the image's packages. Fail-open: returns ``([], {"ok": False, …})``
    on any error."""
    deps, os_eco = image_deps(packages, os_release)
    by_eco = Counter(p.ecosystem for p in packages)
    base = {
        "os": os_label(os_release),
        "osv_ecosystem": os_eco,
        "packages_found": {k: v for k, v in sorted(by_eco.items())},
        "packages_checked": len(deps),
    }
    if any(p.kind == "os" for p in packages) and not os_eco:
        base["note"] = "this distro isn't in the vulnerability database; OS packages not checked"
    if not deps:
        return [], {**base, "ok": False, "error": "no checkable packages found"}
    deadline = time.monotonic() + time_budget
    try:
        batch: list[dict] = []
        for i in range(0, len(deps), _OSV_BATCH):
            chunk = deps[i:i + _OSV_BATCH]
            r = await client.post(
                OSV_BATCH_URL, json={"queries": [d.as_osv_query() for d in chunk]},
                timeout=_HTTP_TIMEOUT,
            )
            r.raise_for_status()
            res = r.json().get("results") or []
            batch.extend(res + [{}] * (len(chunk) - len(res)))
        ids: list[str] = []
        seen: set = set()
        for res in batch:
            for v in (res or {}).get("vulns") or []:
                vid = str(v.get("id", "")) if isinstance(v, dict) else str(v)
                if vid and vid not in seen:
                    seen.add(vid)
                    ids.append(vid)
        details = await _hydrate(ids, client, deadline) if ids else {}
        label = f"image packages ({base['os']})" if base["os"] else "image packages"
        findings, summary = reduce_image_vulns(deps, batch, details, label=label)
        summary.update(base)
        summary["db_snapshots"] = {"osv": datetime.now(timezone.utc).strftime("%Y-%m-%d")}
        return findings, summary
    except Exception as exc:  # noqa: BLE001 — fail-open
        logger.warning("image OSV check failed (fail-open): %s", exc)
        return [], {**base, "ok": False, "error": "vulnerability lookup failed"}


# ---------------------------------------------------------------------------------------
# Provenance (cosign signatures / attestations / OCI referrers)
# ---------------------------------------------------------------------------------------
def _pem_to_der(pem: str) -> bytes | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        return cert.public_bytes(Encoding.DER)
    except Exception:  # noqa: BLE001
        return None


def cert_source(cert_der: bytes) -> dict:
    """The source repo and commit a Fulcio certificate binds (GitHub Actions flow), or
    {} when the extensions are absent."""
    from src.scanner.provenance import _decode_der_string, normalize_repo

    out: dict = {}
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:  # noqa: BLE001
        return out
    for oid, key in ((_OID_SOURCE_REPO_URI, "repo"), (_OID_SOURCE_REPO_DIGEST, "commit"),
                     (_OID_GITHUB_WORKFLOW_SHA, "commit")):
        if key in out:
            continue
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
            raw = getattr(ext.value, "value", None)
            val = _decode_der_string(raw) if isinstance(raw, bytes) else None
        except Exception:  # noqa: BLE001
            val = None
        if val:
            out[key] = normalize_repo(val) if key == "repo" else val
    return out


def verify_raw_signature(cert_der: bytes, payload: bytes, signature: bytes) -> bool:
    """Verify a plain (non-DSSE) signature over ``payload`` — cosign's simple-signing
    format — against the leaf certificate's key. False on any mismatch or error."""
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding

        key = x509.load_der_x509_certificate(cert_der).public_key()
    except Exception:  # noqa: BLE001
        return False
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            algo = hashes.SHA384() if key.curve.key_size >= 384 else hashes.SHA256()
            key.verify(signature, payload, ec.ECDSA(algo))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, payload)
        else:
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001
        return False


def verify_simple_signing(
    payload: bytes, signature: bytes, cert_der: bytes, *, coordinate: str,
    image_digests: tuple[str, ...], claimed_repo: str | None,
):
    """Pure: verify one cosign simple-signing signature into a ``ProvenanceResult``.

    ``verified`` requires all of: the signature checks against the certificate, the
    issuer is a trusted CI, the certificate's identity binds to the claimed source repo
    (when the image declares one), and the payload's signed digest is this image's."""
    from src.scanner.provenance import (
        HOSTED_CI_ISSUERS,
        TRUSTED_CI_ISSUERS,
        ProvenanceResult,
        extract_cert_identity,
        normalize_repo,
    )

    res = ProvenanceResult(surface="docker", coordinate=coordinate,
                           claimed_repo=normalize_repo(claimed_repo),
                           method=COSIGN_VERIFY_METHOD)
    res.present = True
    res.predicate_type = "cosign container image signature"
    res.notes.append("trust-root NOT anchored to Fulcio TUF; Rekor inclusion NOT proven offline")
    try:
        doc = json.loads(payload.decode("utf-8"))
        signed = (((doc.get("critical") or {}).get("image") or {})
                  .get("docker-manifest-digest"))
    except Exception:  # noqa: BLE001
        signed = None
    res.subject_digest = signed
    res.subject_matches = bool(signed) and signed in image_digests
    res.verification_level = "structural"
    identity = extract_cert_identity(cert_der)
    res.identity = identity
    src = cert_source(cert_der)
    issuer, san = identity.get("issuer"), identity.get("san")
    res.binding = {k: v for k, v in {"repo": src.get("repo"), "commit": src.get("commit"),
                                     "builder": san}.items() if v}
    res.builder_hosted = issuer in HOSTED_CI_ISSUERS if issuer else None
    if res.claimed_repo and src.get("repo"):
        res.source_matches_claim = src["repo"] == res.claimed_repo
    res.signature_valid = verify_raw_signature(cert_der, payload, signature)
    if not res.signature_valid:
        res.notes.append("signature did NOT verify against the certificate")
        return res
    res.verification_level = "signature"
    if issuer not in TRUSTED_CI_ISSUERS:
        res.notes.append(f"OIDC issuer not in trusted-CI set ({issuer!r})")
        res.source_matches_claim = False
        return res
    if res.claimed_repo:
        bound = src.get("repo") == res.claimed_repo or (
            bool(san) and "/".join(res.claimed_repo.split("/")[-2:]) in san)
        if not bound:
            res.notes.append("certificate identity does not bind to the image's source repo")
            res.source_matches_claim = False
            return res
    if not res.subject_matches:
        res.notes.append("signed digest is not this image's digest")
        return res
    res.verified = True
    res.certified_eligible = bool(res.builder_hosted
                                  and res.source_matches_claim in (True, None))
    return res


async def _registry_json(url: str, client: httpx.AsyncClient, token: str | None,
                         accept: str, verify_digest: str | None = None) -> dict | None:
    from src.scanner.artifact_fetch import _docker_get

    raw = await _docker_get(url, client, token=token, accept=accept,
                            verify_digest=verify_digest, max_bytes=2 * 1024 * 1024)
    if raw is None:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


async def _blob(url: str, client: httpx.AsyncClient, token: str | None,
                digest: str) -> bytes | None:
    from src.scanner.artifact_fetch import _docker_get

    return await _docker_get(url, client, token=token, verify_digest=digest,
                             max_bytes=4 * 1024 * 1024)


_MANIFEST_ACCEPT = "application/vnd.oci.image.manifest.v1+json"


async def _attestation_material(reg: str, repo: str, digest: str, client, token) -> list:
    """DSSE in-toto envelopes from a cosign ``.att`` tag (cert in the layer annotation)
    and Sigstore bundles from OCI referrers, as provenance ``material`` items."""
    from src.scanner.provenance import INTOTO_PAYLOAD_TYPE, _b64d, parse_npm_attestations

    material: list = []
    hexd = digest.split(":", 1)[1]
    man = await _registry_json(f"{reg}/v2/{repo}/manifests/sha256-{hexd}.att", client, token,
                               _MANIFEST_ACCEPT)
    for layer in (man or {}).get("layers") or []:
        if not isinstance(layer, dict) or layer.get("mediaType") != _DSSE_MEDIA:
            continue
        ann = layer.get("annotations") or {}
        cert_der = _pem_to_der(ann.get(_CERT_ANNOTATION) or "")
        raw = await _blob(f"{reg}/v2/{repo}/blobs/{layer.get('digest')}", client, token,
                          str(layer.get("digest")))
        try:
            env = json.loads(raw or b"{}")
            payload = _b64d(env.get("payload", ""))
            sigs = env.get("signatures") or []
            sig = _b64d(sigs[0]["sig"]) if sigs and sigs[0].get("sig") else b""
            statement = json.loads(payload.decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        material.append({
            "predicate_type": statement.get("predicateType"),
            "payload_type": env.get("payloadType") or INTOTO_PAYLOAD_TYPE,
            "payload": payload, "statement": statement, "signature": sig,
            "cert_der": cert_der, "rekor_index": None,
        })
    idx = await _registry_json(f"{reg}/v2/{repo}/referrers/{digest}", client, token,
                               "application/vnd.oci.image.index.v1+json")
    for desc in ((idx or {}).get("manifests") or [])[:10]:
        if not isinstance(desc, dict) or "sigstore.bundle" not in str(
                desc.get("artifactType") or ""):
            continue
        m = await _registry_json(f"{reg}/v2/{repo}/manifests/{desc.get('digest')}", client,
                                 token, _MANIFEST_ACCEPT, verify_digest=desc.get("digest"))
        for layer in ((m or {}).get("layers") or [])[:2]:
            raw = await _blob(f"{reg}/v2/{repo}/blobs/{layer.get('digest')}", client, token,
                              str(layer.get("digest")))
            try:
                bundle = json.loads(raw or b"{}")
            except ValueError:
                continue
            material.extend(parse_npm_attestations({"attestations": [{"bundle": bundle}]}))
    return material


async def _simple_signature(reg: str, repo: str, digest: str, client, token):
    """(payload, signature, cert_der) from a cosign ``.sig`` tag, or None."""
    from src.scanner.provenance import _b64d

    hexd = digest.split(":", 1)[1]
    man = await _registry_json(f"{reg}/v2/{repo}/manifests/sha256-{hexd}.sig", client, token,
                               _MANIFEST_ACCEPT)
    for layer in (man or {}).get("layers") or []:
        if not isinstance(layer, dict) or layer.get("mediaType") != _SIMPLESIGN_MEDIA:
            continue
        ann = layer.get("annotations") or {}
        cert_der = _pem_to_der(ann.get(_CERT_ANNOTATION) or "")
        sig_b64 = ann.get(_SIG_ANNOTATION)
        if not cert_der or not sig_b64:
            continue  # key-based (non-keyless) signature: no identity to check
        payload = await _blob(f"{reg}/v2/{repo}/blobs/{layer.get('digest')}", client, token,
                              str(layer.get("digest")))
        if payload is None:
            continue
        try:
            return payload, _b64d(sig_b64), cert_der
        except Exception:  # noqa: BLE001
            continue
    return None


async def analyze_image_provenance(image: dict, *, display: str, client: httpx.AsyncClient):
    """Look up and verify the image's signatures/attestations. Fail-open: returns a
    "not present" result on any error."""
    from src.scanner.artifact_fetch import (
        DOCKER_AUTH,
        DOCKER_REGISTRY,
        GHCR_AUTH,
        GHCR_REGISTRY,
        _docker_token,
    )
    from src.scanner.provenance import ProvenanceResult, normalize_repo, verify_material

    index_digest = image.get("index_digest") or ""
    platform_digest = image.get("platform_digest") or index_digest
    claimed = image.get("source_label")
    coordinate = f"{display}@{index_digest}"
    fallback = ProvenanceResult(surface="docker", coordinate=coordinate,
                                claimed_repo=normalize_repo(claimed),
                                method=COSIGN_VERIFY_METHOD)
    if image.get("has_build_attestation"):
        fallback.notes.append(
            "unsigned BuildKit build attestation present; it isn't signed, so it can't be "
            "verified")
    if not index_digest.startswith("sha256:"):
        return fallback
    ghcr = image.get("registry") == "ghcr"
    reg = GHCR_REGISTRY if ghcr else DOCKER_REGISTRY
    repo = image.get("repo") or ""
    digests = tuple(dict.fromkeys([index_digest, platform_digest]))
    try:
        token = await _docker_token(GHCR_AUTH if ghcr else DOCKER_AUTH, repo, client)
        for dg in digests:
            material = await _attestation_material(reg, repo, dg, client, token)
            if material:
                res = verify_material(material, surface="docker", coordinate=coordinate,
                                      claimed_repo=claimed, artifact_digest=dg,
                                      scan_depth="artifact")
                res.method = res.method or COSIGN_VERIFY_METHOD
                return res
        for dg in digests:
            sig = await _simple_signature(reg, repo, dg, client, token)
            if sig:
                payload, signature, cert_der = sig
                return verify_simple_signing(payload, signature, cert_der,
                                             coordinate=coordinate, image_digests=digests,
                                             claimed_repo=claimed)
    except Exception as exc:  # noqa: BLE001 — fail-open
        fallback.error = str(exc)[:200]
        logger.warning("image provenance lookup failed for %s: %s", display, exc)
    return fallback


# ---------------------------------------------------------------------------------------
# Orchestration (called from scan_package)
# ---------------------------------------------------------------------------------------
def image_summary(image: dict, vulns: dict | None) -> dict:
    """The ``artifact_scan["image"]`` block the Check page reads."""
    layers = dict(image.get("layers") or {})
    return {
        "depth": layers.get("depth", "config"),
        "layers_total": layers.get("layers_total", 0),
        "layers_scanned": layers.get("layers_scanned", 0),
        "layers_skipped": layers.get("layers_skipped") or [],
        "app_files": layers.get("app_files", 0),
        "reason": layers.get("reason"),
        "os": os_label(image.get("os_release") or {}),
        "packages": layers.get("packages", 0),
        "index_digest": image.get("index_digest"),
        "source_label": image.get("source_label"),
        "vulnerabilities": {k: v for k, v in (vulns or {}).items() if k != "db_snapshots"},
    }


async def apply_docker_image_extras(result, fetched) -> None:
    """Fold the CVE check, provenance and image summary into ``result``. Never raises."""
    from src.config import settings
    from src.scanner.scan import Finding, _apply_provenance_result

    image = getattr(fetched, "image", None)
    if not isinstance(image, dict):
        return
    vulns: dict | None = None
    try:
        async with httpx.AsyncClient(headers={"User-Agent": "AgentAvow-Scanner"}) as client:
            if image.get("packages"):
                findings, vulns = await check_image_vulnerabilities(
                    image["packages"], image.get("os_release") or {}, client=client)
                if vulns.get("ok"):
                    result.findings = result.findings + [Finding(**f) for f in findings]
                    counts = vulns.get("counts") or {}
                    result.supply_chain = {
                        "ok": True, "advisory": False, "scored": True, "source": "image",
                        "deps_total": vulns.get("packages_checked", 0),
                        "unique_vulns": len(findings),
                        "ecosystems": sorted({vulns.get("osv_ecosystem") or "",
                                              *[k for k in (vulns.get("packages_found") or {})
                                                if k in ("PyPI", "npm")]} - {""}),
                        "counts": counts,
                        "malicious": vulns.get("malicious") or [],
                        "db_snapshots": vulns.get("db_snapshots") or {},
                    }
                    if isinstance(result.coverage, dict):
                        snaps = result.coverage.get("db_snapshots")
                        snaps = dict(snaps) if isinstance(snaps, dict) else {}
                        snaps.update(vulns.get("db_snapshots") or {})
                        result.coverage["db_snapshots"] = snaps
            if getattr(settings, "scanner_verify_provenance", False):
                res = await asyncio.wait_for(
                    analyze_image_provenance(image, display=fetched.name, client=client),
                    timeout=_PROV_TIME_BUDGET,
                )
                _apply_provenance_result(result, res, res.claimed_repo)
    except Exception:  # noqa: BLE001 — fail-open
        logger.warning("docker image extras failed for %s", getattr(fetched, "name", "?"),
                       exc_info=True)
    if isinstance(result.artifact_scan, dict):
        result.artifact_scan["image"] = image_summary(image, vulns)
