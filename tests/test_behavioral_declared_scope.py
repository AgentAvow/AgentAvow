"""The behavioral tier must judge a tool against its OWN declared scope (.agentavow.yml).

Regression for a gap where the public scan endpoint called the sandbox runner without
the declared egress hosts, so the "sandbox holds it to its own declaration" promise in
the docs was never actually exercised in production.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

import src.api.public_scan_router as router
from src.scanner.behavioral import runner as behavioral_runner
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.scan import _declared_scope_from_artifact

MANIFEST = "version: agentavow-manifest-v0\negress:\n  - api.example.com\ncapabilities:\n  - network:egress\n"


@dataclass
class _File:
    path: str
    text: str | None = None


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    return r


@pytest.fixture
def captured_runs(monkeypatch):
    calls: list[dict] = []

    async def fake_run(surface, coordinate, *, expected_hosts=None, manifest=None, timeout=45):
        calls.append({"surface": surface, "coordinate": coordinate,
                      "expected_hosts": set(expected_hosts or [])})
        return BehavioralResult(ran=True, surface=surface, coordinate=coordinate,
                                egress_hosts=["api.example.com"], unexpected_egress=[])

    monkeypatch.setattr(behavioral_runner, "run_behavioral", fake_run)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    return calls


def test_declared_scope_is_read_from_the_artifact_root():
    files = {"package.json": _File("package.json", "{}"),
             ".agentavow.yml": _File(".agentavow.yml", MANIFEST)}
    scope = _declared_scope_from_artifact(files)
    assert scope["present"] is True
    assert scope["egress"] == ["api.example.com"]


def test_declared_scope_tolerates_one_wrapper_dir_but_not_nested_copies():
    wrapped = {"pkg-1.0/.agentavow.yml": _File("pkg-1.0/.agentavow.yml", MANIFEST)}
    assert _declared_scope_from_artifact(wrapped)["egress"] == ["api.example.com"]
    nested = {"vendor/other/.agentavow.yml": _File("vendor/other/.agentavow.yml", MANIFEST)}
    assert _declared_scope_from_artifact(nested) == {}


@pytest.mark.parametrize("files", [
    {},
    {".agentavow.yml": _File(".agentavow.yml", None)},            # binary
    {".agentavow.yml": _File(".agentavow.yml", "::: not yaml [")},  # malformed
    {".agentavow.yml": _File(".agentavow.yml", "version: 99\negress: [x]\n")},
])
def test_absent_or_bad_manifest_is_no_declaration(files):
    assert _declared_scope_from_artifact(files) == {}


def test_declared_egress_normalizes_hosts():
    data = {"declared_scope": {"present": True, "egress": [" API.Example.com ", "", "cdn.x.io"]}}
    assert router._declared_egress(data) == {"api.example.com", "cdn.x.io"}
    assert router._declared_egress({}) == set()
    assert router._declared_egress({"declared_scope": "garbage"}) == set()


def test_forced_run_passes_declared_hosts_to_the_sandbox(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "npm", "name": "left-pad"},
            "declared_scope": {"present": True, "egress": ["api.example.com"]}}
    block = asyncio.run(router._behavioral_block(data, force=True))
    assert captured_runs == [{"surface": "npm", "coordinate": "left-pad",
                              "expected_hosts": {"api.example.com"}}]
    assert block["ran"] is True
    assert block["declared_egress"] == ["api.example.com"]
    assert block["findings"] == []


def test_run_without_a_declaration_still_works(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "pypi", "name": "requests"}}
    block = asyncio.run(router._behavioral_block(data, force=True))
    assert captured_runs[0]["expected_hosts"] == set()
    assert block["declared_egress"] == []


def test_cache_entry_is_keyed_by_the_declaration(fake_redis, captured_runs):
    base = {"package_coordinate": {"surface": "npm", "name": "left-pad"}}
    declared = dict(base, declared_scope={"present": True, "egress": ["api.example.com"]})
    asyncio.run(router._behavioral_block(base, force=True))
    asyncio.run(router._behavioral_block(declared, force=True))
    assert len(captured_runs) == 2, "a declaration must not reuse the undeclared verdict"
    assert len(fake_redis.store) == 2
    # And the declared run is served from cache afterwards, without a third sandbox run.
    cached = asyncio.run(router._behavioral_block(declared, force=False))
    assert cached["declared_egress"] == ["api.example.com"]
    assert len(captured_runs) == 2


def test_cache_key_is_stable_across_host_order():
    a = router._behavioral_cache_key("npm", "X", {"b.com", "a.com"})
    b = router._behavioral_cache_key("npm", "x", {"a.com", "b.com"})
    assert a == b
    assert router._behavioral_cache_key("npm", "x") == "behavioral:npm:x"
    assert a != router._behavioral_cache_key("npm", "x")
    json.dumps(a)  # plain string, safe as a redis key


def test_bot_copy_does_not_claim_sandboxing_we_do_not_do():
    from src.bots import definitions
    text = json.dumps(definitions.__dict__.get("SCHEDULED_POSTS")
                      or {k: v for k, v in vars(definitions).items() if isinstance(v, dict)},
                      default=str).lower()
    assert "sandboxes every" not in text
    assert "sandbox interactions" not in text


def test_background_run_starts_once_per_coordinate_while_in_flight(fake_redis, captured_runs,
                                                                     monkeypatch):
    started = []
    monkeypatch.setattr(router.asyncio, "create_task", lambda coro: (started.append(coro),
                                                                      coro.close()))
    data = {"package_coordinate": {"surface": "npm", "name": "left-pad"}}

    async def twice():
        a = await router._behavioral_block(data, force=False)
        b = await router._behavioral_block(data, force=False)
        return a, b

    a, b = asyncio.run(twice())
    assert a["pending"] and b["pending"]
    assert len(started) == 1, "the second request must not detonate the same coordinate again"
    assert any(k.endswith(":lock") for k in fake_redis.store)


def test_lock_fails_open_without_redis(monkeypatch):
    def boom():
        raise RuntimeError("redis down")
    monkeypatch.setattr("src.redis_client.get_redis", boom)
    assert asyncio.run(router._acquire_behavioral_lock("npm", "x", set())) is True


def test_a_ran_block_carries_a_verifiable_signed_observation(fake_redis, captured_runs):
    import base64

    from src.signing import get_public_key
    data = {"package_coordinate": {"surface": "npm", "name": "left-pad"},
            "declared_scope": {"present": True, "egress": ["api.example.com"]}}
    block = asyncio.run(router._behavioral_block(data, force=True))
    att = block["attestation"]
    assert att and att["kid"] == "agentgraph-security-v1"
    h, p, sig = att["jws"].split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    get_public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{h}.{p}".encode())
    payload = json.loads(base64.urlsafe_b64decode(pad(p)))
    assert payload["type"] == "BehavioralObservation"
    assert payload["@context"] == router.BEHAVIORAL_OBSERVATION_CONTEXT
    assert payload["subject"] == {"id": "pkg:npm/left-pad", "surface": "npm", "name": "left-pad"}
    assert payload["observation"]["declaredEgress"] == ["api.example.com"]
    assert payload["observation"]["egressHosts"] == ["api.example.com"]
    assert "trust_score" not in json.dumps(payload)  # an observation, never a score
    assert payload["observedAt"] == att["observed_at"]


def test_no_signed_observation_when_the_sandbox_did_not_run(fake_redis, monkeypatch):
    async def fake_run(surface, coordinate, *, expected_hosts=None, manifest=None, timeout=45):
        return BehavioralResult(ran=False, surface=surface, coordinate=coordinate,
                                error="unsupported_surface")
    monkeypatch.setattr(behavioral_runner, "run_behavioral", fake_run)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    block = asyncio.run(router._behavioral_block(
        {"package_coordinate": {"surface": "npm", "name": "x"}}, force=True))
    assert block["ran"] is False and block["attestation"] is None
