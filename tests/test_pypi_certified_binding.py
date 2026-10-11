"""PEP 740 (PyPI) provenance can earn Certified: the signed Trusted Publisher SAN binds
the repo, and it must equal the repo the project declares on PyPI."""
from __future__ import annotations

import json
from types import SimpleNamespace

from src.scanner.provenance import (
    declared_repo_from_pypi_meta,
    parse_pypi_provenance,
    verify_material,
)
from src.scanner.scan import _bind_pypi_declared_repo
from tests.test_scanner_provenance import (
    OWNER_REPO,
    _b64,
    _make_leaf_cert,
    _sign_dsse,
)

PUBLISH_PREDICATE = "https://docs.pypi.org/attestations/publish/v1"


def _pep740_doc(san_uri: str | None = None):
    """A PEP 740 publish attestation: no repo in the predicate, only the cert SAN."""
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_leaf_cert(key, san_uri=san_uri) if san_uri else _make_leaf_cert(key)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "foo-1.0.0.tar.gz", "digest": {"sha256": "ab" * 32}}],
        "predicateType": PUBLISH_PREDICATE,
        "predicate": None,
    }
    payload = json.dumps(statement).encode()
    sig = _sign_dsse(key, payload)
    return {
        "version": 1,
        "attestation_bundles": [{
            "publisher": {"kind": "GitHub", "repository": "someone/else"},
            "attestations": [{
                "version": 1,
                "verification_material": {"certificate": _b64(cert),
                                          "transparency_entries": [{"logIndex": "1"}]},
                "envelope": {"statement": _b64(payload), "signature": _b64(sig)},
            }],
        }],
    }


def _verify(doc):
    return verify_material(parse_pypi_provenance(doc), surface="pypi",
                           coordinate="foo@1.0.0/foo-1.0.0.tar.gz",
                           scan_depth="artifact")


def test_san_binds_repo_for_publish_attestation():
    res = _verify(_pep740_doc())
    assert res.verified is True
    # From the SIGNED SAN, not the unsigned publisher metadata ("someone/else").
    assert res.binding["repo"] == OWNER_REPO
    assert res.source_matches_claim is None  # nothing declared yet


def test_declared_repo_match_sets_source_matches():
    res = _verify(_pep740_doc())
    _bind_pypi_declared_repo(res, {"declared_repository": "https://github.com/Owner/Repo"})
    assert res.source_matches_claim is True
    assert res.summary()["source_matches_claim"] is True


def test_declared_repo_mismatch_is_not_a_penalty():
    res = _verify(_pep740_doc())
    _bind_pypi_declared_repo(res, {"declared_repository": "github.com/other/project"})
    assert res.source_matches_claim is None
    assert res.verified is True


def test_no_declaration_leaves_unset():
    res = _verify(_pep740_doc())
    _bind_pypi_declared_repo(res, None)
    assert res.source_matches_claim is None


def test_unverified_never_bound():
    res = SimpleNamespace(verified=False, binding={"repo": OWNER_REPO},
                          source_matches_claim=None, claimed_repo=None)
    _bind_pypi_declared_repo(res, {"declared_repository": OWNER_REPO})
    assert res.source_matches_claim is None


def test_declared_repo_from_meta_prefers_source_keys():
    meta = {"info": {
        "home_page": "https://requests.readthedocs.io",
        "project_urls": {"Documentation": "https://requests.readthedocs.io",
                         "Source": "https://github.com/psf/requests"},
    }}
    assert declared_repo_from_pypi_meta(meta) == "github.com/psf/requests"


def test_declared_repo_from_meta_falls_back_to_github_homepage():
    meta = {"info": {"home_page": "https://github.com/pallets/flask/", "project_urls": {}}}
    assert declared_repo_from_pypi_meta(meta) == "github.com/pallets/flask"


def test_declared_repo_from_meta_ignores_non_forge():
    meta = {"info": {"home_page": "https://example.com",
                     "project_urls": {"Homepage": "https://pypi.org/project/x"}}}
    assert declared_repo_from_pypi_meta(meta) is None
    assert declared_repo_from_pypi_meta({}) is None
