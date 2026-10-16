"""Cross-implementation regression test for APS rotation-attestation fixtures.

Binds ``src.signing.canonicalize_jcs_strict`` to the APS rotation-attestation
fixture set at ``https://aeoess.com/fixtures/rotation-attestation/``.

**Why this test exists.** CTEF v0.3.1 §6.3 declares the continuity-layer
composition rule as "rotation-attestation chain, content-addressed" and
co-normatively cites aeoess's rotation-attestation spec. The composition
only works if AgentGraph and APS produce byte-identical canonical output
for every fixture in the published set. A silent drift — on null handling,
unicode escaping, key ordering — breaks every rotation-attested receipt in
the wild without any visible API change.

**Why live-endpoint fetch, not a repo snapshot.** Per commitment on
A2A#1672 (issuecomment-4314555571): this test pulls canonical bytes from
``aeoess.com/fixtures/rotation-attestation/`` at test-collection time and
pins SHA-256 in code, rather than committing a repo-local snapshot. That
way the fixture version is always what APS is actually publishing — if
APS revs the set and our canonicalizer drifts, the test fails loudly; if
our pinned hash drifts from APS's published hash, same.

If this test fails, do not patch ``canonicalize_jcs_strict`` to match:
a silent canonical change invalidates every previously-signed CTEF
envelope that composed an APS rotation-attested continuity claim. Treat
the failure as a breaking interop event, coordinate with aeoess.

Sibling to ``tests/test_jcs_canonicalize_aps_interop.py`` (bilateral
delegation, snapshot-based) and ``tests/test_cte_test_vectors.py``
(self-published CTEF vectors). Together these three tests close the
canonicalization loop across APS bilateral delegation, APS continuity
rotation, and our own CTEF envelope/verdict shapes.

Spec reference: https://aeoess.com/fixtures/rotation-attestation/
Index:         https://aeoess.com/fixtures/rotation-attestation/test-vectors.json
"""
from __future__ import annotations

import hashlib

import httpx
import pytest

from src.signing import canonicalize_jcs_strict

_BASE_URL = "https://aeoess.com/fixtures/rotation-attestation"
_INDEX_URL = f"{_BASE_URL}/test-vectors.json"
_FETCH_TIMEOUT = 15.0
_USER_AGENT = "agentgraph-aps-rotation-interop-test/1.0"

# Code-pinned expected hashes for the five rotation-attestation fixtures.
# These MUST stay in sync with what aeoess publishes at
# ``/fixtures/rotation-attestation/test-vectors.json``. Drift in either
# direction is a breaking interop event — the test asserts both that
# (a) our canonicalizer reproduces the hash and (b) the pinned value
# matches what APS is currently publishing.
_EXPECTED_HASHES: dict[str, str] = {
    "happy-path": (
        "819f9e571e6d7c57852e17309f3d8166bbcb8fc04d2894dcb8c8357b66bfe3df"
    ),
    "cross-signed": (
        "b11a72b09b8184e3cc4620e0d5fe0926f6fecfb8cd35c2ef364c5761647c43b4"
    ),
    "migration-attested": (
        "5791fe9f9456f1d54b73401b42e3afff7a7e04e7a60f43537e99dd58301803a4"
    ),
    "happy-path-compound": (
        "acd624c98946e11d02dde01faa70386d0b19fc957a104311bf9d73817bfe7989"
    ),
    "negative-no-attestation": (
        "ae871beefeaf1847cd5c34927c42cf5bd92d44c8554cf5eff0641dae80452f24"
    ),
}


def _client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=_FETCH_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
        follow_redirects=True,
        transport=transport,
    )


# Any failure to obtain a partner document — transport error, timeout,
# non-2xx (a 503 from aeoess.com failed PR #108's CI on 2026-10-09), or a
# body that is not JSON — is a partner outage, not a regression on our
# side. Every fetch therefore skips rather than errors.
_FETCH_ERRORS = (httpx.HTTPError, httpx.TimeoutException, OSError, ValueError)


def _fetch_json(client: httpx.Client, url: str, what: str):
    try:
        r = client.get(url)
        r.raise_for_status()
        return r.json()
    except _FETCH_ERRORS as e:
        pytest.skip(f"APS rotation-attestation {what} unreachable: {e}")


@pytest.fixture(scope="module")
def live_index() -> dict:
    """Fetch the live test-vectors.json index from aeoess.com.

    Skips the whole module if the endpoint is unreachable — we do not
    want CI red-bars when aeoess is down; the test is an interop
    regression check, not a liveness probe. Drift detection still
    fires whenever the endpoint is reachable (which is the common case).
    """
    with _client() as c:
        return _fetch_json(c, _INDEX_URL, "index")


@pytest.fixture(scope="module")
def live_fixtures(live_index: dict) -> dict[str, dict]:
    """Fetch every fixture declared in the live index."""
    out: dict[str, dict] = {}
    with _client() as c:
        for name, entry in live_index["fixtures"].items():
            out[name] = _fetch_json(c, entry["url"], f"fixture {name!r}")
    return out


@pytest.mark.parametrize(
    "handler",
    [
        lambda req: httpx.Response(503, text="Service Unavailable"),
        lambda req: httpx.Response(500, text="boom"),
        lambda req: httpx.Response(200, text="<html>not json</html>"),
        lambda req: (_ for _ in ()).throw(httpx.ConnectError("down", request=req)),
        lambda req: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=req)),
    ],
    ids=["503", "500", "non-json", "connect-error", "timeout"],
)
def test_partner_fetch_failure_skips_not_errors(handler):
    """Regression (#31): one fixture fetch failing must skip, never error."""
    with _client(httpx.MockTransport(handler)) as c:
        with pytest.raises(pytest.skip.Exception):
            _fetch_json(c, f"{_BASE_URL}/positive-basic.json", "fixture")


def test_live_index_declares_all_five_fixtures(live_index: dict):
    """If APS changes the set (adds/removes fixtures), we learn immediately.

    Five is the v1 contract. A change in count means a coordinated
    interop event, not a silent extension.
    """
    declared = set(live_index["fixtures"].keys())
    assert declared == set(_EXPECTED_HASHES.keys()), (
        f"APS fixture set drifted: got {declared}, "
        f"expected {set(_EXPECTED_HASHES.keys())}. "
        "Coordinate with aeoess before updating pinned set."
    )


def test_spec_version_is_v1(live_index: dict):
    """Spec identity must not drift silently."""
    assert live_index["specVersion"] == "rotation-attestation-v1"


def test_canonicalization_rule_matches_ours(live_index: dict):
    """APS and AgentGraph must agree on which canonicalizer to apply."""
    rule = live_index["canonicalizationRule"]
    assert "RFC 8785" in rule and "JCS" in rule, (
        f"APS canonicalization rule changed: {rule}"
    )


@pytest.mark.parametrize(
    "fixture_name",
    [
        "happy-path",
        "cross-signed",
        "migration-attested",
        "happy-path-compound",
        "negative-no-attestation",
    ],
)
def test_live_hash_matches_code_pinned_hash(
    live_index: dict, fixture_name: str,
):
    """The hash aeoess publishes must match what we have pinned in code.

    This catches the case where APS revs a fixture (even subtly) without
    bumping the spec version, or where our code-pinned value goes stale
    because we updated one side and forgot the other.
    """
    published = live_index["fixtures"][fixture_name]["canonicalSha256"]
    # APS publishes as "sha256:<hex>"; strip the algorithm prefix.
    published_hex = published.split(":", 1)[1] if ":" in published else published
    assert published_hex == _EXPECTED_HASHES[fixture_name], (
        f"{fixture_name}: APS published hash does not match our pinned "
        f"expected value. Either APS revved the fixture (coordinate) or "
        f"our pin is stale. Published: {published_hex}, pinned: "
        f"{_EXPECTED_HASHES[fixture_name]}"
    )


@pytest.mark.parametrize(
    "fixture_name",
    [
        "happy-path",
        "cross-signed",
        "migration-attested",
        "happy-path-compound",
        "negative-no-attestation",
    ],
)
def test_canonical_bytes_reproduce_byte_exact(
    live_fixtures: dict[str, dict], fixture_name: str,
):
    """Our canonicalizer must produce byte-identical canonical output.

    This is the load-bearing interop check. If this fails, CTEF envelopes
    composing an APS continuity claim will not verify byte-for-byte
    against APS's own verifier — the composition break is silent at the
    API level, loud at the signature level.
    """
    fixture = live_fixtures[fixture_name]
    canonical = canonicalize_jcs_strict(fixture)
    got_hash = hashlib.sha256(canonical).hexdigest()

    assert got_hash == _EXPECTED_HASHES[fixture_name], (
        f"{fixture_name}: our canonicalizer diverged from APS. "
        f"Got {got_hash}, expected {_EXPECTED_HASHES[fixture_name]}. "
        "DO NOT patch canonicalize_jcs_strict to match — this is a "
        "breaking interop event. Coordinate with aeoess."
    )


def test_negative_fixture_has_empty_rotation_signature(
    live_fixtures: dict[str, dict], live_index: dict,
):
    """The negative fixture's structural condition must match the spec.

    Per the published error-code contract, this fixture is the canonical
    INVALID_CLAIM_SCOPE trigger: a rotationLog entry exists (continuity
    claim present) but the rotationSignature is empty (no evidence). A
    conformant verifier MUST fail closed on this structural condition
    before evaluating any other layer.

    This test does not implement the verifier — it asserts the fixture
    actually carries the structural condition the spec names. If APS
    changes the fixture shape without updating the error-code contract,
    this test fires to surface the divergence.
    """
    fixture = live_fixtures["negative-no-attestation"]
    rotation_log = fixture.get("rotationLog", [])
    assert rotation_log, (
        "negative-no-attestation fixture lost its rotationLog entry — "
        "the INVALID_CLAIM_SCOPE trigger no longer structurally present"
    )
    empty_sig_entries = [
        e for e in rotation_log if e.get("rotationSignature") == ""
    ]
    assert empty_sig_entries, (
        "negative-no-attestation fixture no longer contains a rotationLog "
        "entry with empty rotationSignature — the structural condition "
        "the spec names as INVALID_CLAIM_SCOPE trigger has changed"
    )

    # And the published error-code contract must still name this.
    err = live_index.get("errorCodes", {}).get("negative-no-attestation", {})
    assert err.get("code") == "INVALID_CLAIM_SCOPE", (
        f"APS error-code contract drifted for negative-no-attestation: "
        f"got {err.get('code')}, expected INVALID_CLAIM_SCOPE"
    )
