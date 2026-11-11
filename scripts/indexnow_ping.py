"""Tell IndexNow search engines (Bing, Yandex, Seznam, Naver) which pages changed.

Run at the end of scripts/deploy-prod.sh, from the machine that ran the deploy. It
reads the sitemap URLs from web/public/sitemap.xml and POSTs them to
https://api.indexnow.org/indexnow, which shares them with every IndexNow engine.

The key is public by design: search engines confirm it by fetching
https://agentavow.com/<key>.txt, served from web/public/<key>.txt.

--changed-only  ping only URLs whose <lastmod> differs from the last successful ping
                (kept in --state). With no state yet, every URL is sent.

This never fails a deploy: every outcome, including errors, is one line of output and
exit status 0.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "web" / "public"
SITEMAP = PUBLIC / "sitemap.xml"
HOST = "agentavow.com"
ENDPOINT = "https://api.indexnow.org/indexnow"
TIMEOUT_SECONDS = 10
DEFAULT_STATE = Path.home() / ".cache" / "agentavow" / "indexnow-lastmod.json"
SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
KEY_FILE = re.compile(r"^[0-9a-f]{32}\.txt$")


def find_key(public: Path = PUBLIC) -> str:
    """The key from the one <32 hex>.txt file in web/public; its content must match."""
    files = sorted(p for p in public.iterdir() if KEY_FILE.match(p.name))
    if len(files) != 1:
        raise ValueError(f"expected one IndexNow key file in {public}, found {len(files)}")
    key = files[0].stem
    if files[0].read_text().strip() != key:
        raise ValueError(f"{files[0].name} does not contain its own key")
    return key


def read_sitemap(text: str) -> dict[str, str]:
    """URL -> lastmod ("" when absent), in sitemap order, for this host only."""
    urls: dict[str, str] = {}
    for url in ET.fromstring(text).iter(f"{SITEMAP_NS}url"):
        loc = (url.findtext(f"{SITEMAP_NS}loc") or "").strip()
        if loc.startswith(f"https://{HOST}/"):
            urls[loc] = (url.findtext(f"{SITEMAP_NS}lastmod") or "").strip()
    return urls


def changed(current: dict[str, str], previous: dict[str, str]) -> list[str]:
    """URLs that are new or whose lastmod moved since the previous ping."""
    return [url for url, lastmod in current.items() if previous.get(url) != lastmod]


def build_payload(key: str, urls: list[str], host: str = HOST) -> dict:
    """The JSON body IndexNow expects."""
    return {
        "host": host,
        "key": key,
        "keyLocation": f"https://{host}/{key}.txt",
        "urlList": list(urls),
    }


def post(payload: dict) -> int:
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        return response.status


def run(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--changed-only", action="store_true")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--dry-run", action="store_true", help="print the payload, send nothing")
    args = parser.parse_args(argv)

    key = find_key()
    current = read_sitemap(SITEMAP.read_text())
    previous: dict[str, str] = {}
    if args.changed_only and args.state.exists():
        previous = json.loads(args.state.read_text())
    urls = changed(current, previous) if args.changed_only else list(current)
    if not urls:
        return "indexnow: no changed URLs, nothing sent"
    payload = build_payload(key, urls)
    if args.dry_run:
        return f"indexnow: dry run, would send {json.dumps(payload)}"

    status = post(payload)
    # 200 OK and 202 Accepted (key not yet verified) both mean the URLs were taken.
    if status in (200, 202):
        args.state.parent.mkdir(parents=True, exist_ok=True)
        args.state.write_text(json.dumps(current, indent=1))
        return f"indexnow: sent {len(urls)} URL(s), HTTP {status}"
    return f"indexnow: HTTP {status}, {len(urls)} URL(s) not confirmed"


def main(argv: list[str] | None = None) -> int:
    try:
        line = run(argv)
    except urllib.error.HTTPError as err:
        line = f"indexnow: HTTP {err.code} ({err.reason}), skipped"
    except Exception as err:  # noqa: BLE001 - a ping must never fail the deploy
        line = f"indexnow: skipped ({type(err).__name__}: {err})"
    print(" ".join(line.split()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
