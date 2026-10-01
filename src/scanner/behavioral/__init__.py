"""Behavioral (sandbox) scan tier — run a tool in isolation and observe what it DOES.

Static analysis reads the code; the behavioral tier runs it in a gVisor-isolated sandbox
behind a transparent egress logger and records the hosts it phones home to, the files it
writes, and (Phase 1.5) the processes it spawns — catching runtime malice static analysis
can't see (obfuscated loaders, install-time exfiltration, an MCP server that only calls out
on first invocation).

The product logic here (orchestration + mapping observations to findings) is host-agnostic
and unit-tested. The actual sandbox execution (`scripts/sandbox/behavioral_run.sh`) needs a
dedicated Linux host with Docker + gVisor — never the prod box. See
`docs/internal/sandbox-behavioral-tier-plan.md`.
"""
from __future__ import annotations

from src.scanner.behavioral.env_reads import env_names_from_files
from src.scanner.behavioral.graders import grade, grade_summary
from src.scanner.behavioral.manifest import DeclaredScope, parse_manifest
from src.scanner.behavioral.runner import (
    BehavioralResult,
    behavioral_findings,
    run_behavioral,
)
from src.scanner.behavioral.transcript import ExerciseTranscript, parse_transcript

__all__ = [
    "BehavioralResult", "DeclaredScope", "ExerciseTranscript", "behavioral_findings",
    "env_names_from_files", "grade", "grade_summary", "parse_manifest",
    "parse_transcript", "run_behavioral",
]
