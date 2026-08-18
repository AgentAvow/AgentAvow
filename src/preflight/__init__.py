"""Connector Preflight — a pre-submission readiness linter for AI-agent tools.

Given a scan of an MCP server (or its repo), evaluate it against the *published*
submission-rejection gates of the Anthropic Claude connectors directory and the
OpenAI apps directory, and emit a pass/fail "Directory-Ready" report. The signed
AgentAvow score + badge ride along as the byproduct.

The gate evaluator (``gates.evaluate_gates``) is PURE and deterministic — it reads
the normalized scan dict a submitter can reproduce, so the verdict is recomputable.
"""
