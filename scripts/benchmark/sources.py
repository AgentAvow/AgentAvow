"""Pinned answer-key sources for the Q4 accuracy benchmark.

Every dataset is pinned to a commit (or dataset revision), so a re-run reads the same
bytes. The samples are real malware: they are downloaded into a data directory OUTSIDE
the repo (default ``~/benchmark-data/<set>/``), read only as data, and never installed,
imported, built or run. Nothing from them goes into git; the report links the sources.

License notes (checked 2026-11-16):

* A, MaliciousSkillBench: code Apache-2.0, metadata / labels / splits CC BY 4.0. The
  skill artifacts themselves keep their upstream terms (THIRD_PARTY_NOTICE.md), so we
  cite and link, and never republish items.
* B, Cisco skill-scanner evals: GitHub reports NOASSERTION (the LICENSE file is the
  Apache-2.0 text with a Cisco copyright line, and each ``_expected.json`` says
  Apache-2.0). Per the design we treat it as cite-and-link only: no redistribution,
  and check again before publishing per-item results.
* C, DataDog malicious-software-packages-dataset: Apache-2.0 (attribution).
* D, benign packages: ranking lists only (hugovk/top-pypi-packages has no license
  file; wooorm/npm-high-impact is MIT). We use them to pick names, and fetch the
  packages themselves from the public registries, as a package scan does.
"""
from __future__ import annotations

import os
from pathlib import Path

DATA_ROOT_ENV = "AGENTAVOW_BENCHMARK_DATA"


def data_root() -> Path:
    env = os.environ.get(DATA_ROOT_ENV)
    return Path(env) if env else Path.home() / "benchmark-data"


SOURCES: dict[str, dict] = {
    "A": {
        "name": "MaliciousSkillBench",
        "repo": "protectskills/MaliciousSkillBench",
        "url": "https://github.com/protectskills/MaliciousSkillBench",
        "commit": "893afd609be22a2dfac5a2b94bbebb4eeb99515e",
        "tarball_sha256": "826c025cd6b37bc8b8a487f2dba89cc41a5a7061f6b133fd7bf8b83e03eaa6cf",
        # Benign skill text lives only in the Hugging Face dataset.
        "hf_dataset": "ProtectSkills/MaliciousSkillBench",
        "hf_revision": "d4b42ce5766a6e0359c987cf59c1007cb3795a90",
        "license": "Apache-2.0 (code), CC-BY-4.0 (metadata); artifacts keep upstream terms",
        "redistribute": False,
        "surface": "skill",
    },
    "B": {
        "name": "Cisco skill-scanner evals (evals/skills)",
        "repo": "cisco-ai-defense/skill-scanner",
        "url": "https://github.com/cisco-ai-defense/skill-scanner/tree/main/evals/skills",
        "commit": "c558c421157c546ec417cf23778ce81a3a8f35fd",
        "tarball_sha256": "3cfee4083439c1c4f5de5a7d1b8d0802d4c88309c2012789ffd07b9ebf66ee01",
        "license": "NOASSERTION on GitHub; cite and link only, never redistribute",
        "redistribute": False,
        "surface": "skill",
    },
    "C": {
        "name": "DataDog malicious-software-packages-dataset",
        "repo": "DataDog/malicious-software-packages-dataset",
        "url": "https://github.com/DataDog/malicious-software-packages-dataset",
        "commit": "72c723be547033c558244520524b117c8d71663b",
        "zip_password": "infected",  # published in the dataset README
        "license": "Apache-2.0",
        "redistribute": False,  # malware: link, never republish
        "surface": "package",
    },
    "D": {
        "name": "Benign sample (top-downloaded npm / PyPI packages)",
        "pypi_ranking": {
            "repo": "hugovk/top-pypi-packages",
            "commit": "29c0d4c38c28c0e6b99e73fa09cb91a2323ca51b",
            "path": "top-pypi-packages-30-days.min.json",
        },
        "npm_ranking": {
            "repo": "wooorm/npm-high-impact",
            "commit": "9e29478332833af97b0e96801a5187cfd3c28382",
            "path": "lib/top-download.js",
        },
        "license": "ranking lists only; packages fetched from the public registries",
        "redistribute": False,
        "surface": "package",
    },
}


def set_dir(set_id: str) -> Path:
    return data_root() / set_id
