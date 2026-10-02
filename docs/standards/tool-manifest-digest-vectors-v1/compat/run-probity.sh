#!/usr/bin/env bash
# Run the v1 vectors through our native verifier and through Probity's independent
# reader, pinned by commit, and fail if either disagrees with the vector file.
#
#   compat/run-probity.sh [--probity DIR] [--out DIR] [--python BIN]
#
#   --probity DIR   a checkout of probityai/agent-evidence-vectors at the pinned commit
#                   (compat/probity-pin.json). Omitted: cloned into OUT/probity.
#   --out DIR       where reports go (default: ${TMPDIR:-/tmp}/probity-v1-compat).
#   --python BIN    interpreter for the reader (default: python3; needs 3.13+ and
#                   the pins in Probity's requirements file, see README).
#
# Writes to OUT: native-report.txt, probity-stock-report.json (only when the vector
# file is byte-identical to the one Probity locked), probity-report.json, summary.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V1_DIR="$(cd "$HERE/.." && pwd)"
VECTORS="$V1_DIR/tool-manifest-digest-v1-vectors.json"
PIN="$HERE/probity-pin.json"

PROBITY=""
OUT="${TMPDIR:-/tmp}/probity-v1-compat"
PYTHON="python3"
while [ $# -gt 0 ]; do
  case "$1" in
    --probity) PROBITY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"

pin() { "$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$PIN" "$1"; }
REPO="$(pin repository)"
COMMIT="$(pin commit)"
READER_DIR="$(pin reader_dir)"
REQS="$(pin requirements)"

if [ -z "$PROBITY" ]; then
  PROBITY="$OUT/probity"
  if [ ! -d "$PROBITY/.git" ]; then
    git clone -q "https://github.com/$REPO" "$PROBITY"
  fi
  git -C "$PROBITY" fetch -q origin "$COMMIT" 2>/dev/null || true
  git -C "$PROBITY" checkout -q "$COMMIT"
fi

HEAD="$(git -C "$PROBITY" rev-parse HEAD)"
if [ "$HEAD" != "$COMMIT" ]; then
  echo "Probity checkout is at $HEAD, pinned commit is $COMMIT" >&2
  exit 1
fi
if ! "$PYTHON" -c "import rfc8785, cryptography" 2>/dev/null; then
  echo "reader dependencies missing; run: $PYTHON -m pip install -r $PROBITY/$REQS" >&2
  exit 1
fi

status=0
echo "== native: node verify.mjs"
if node "$V1_DIR/verify.mjs" "$VECTORS" > "$OUT/native-report.txt" 2>&1; then
  NATIVE="pass"
else
  NATIVE="FAIL"; status=1
fi
tail -n 1 "$OUT/native-report.txt"

LOCKED_SHA="$("$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))['fixture']['sha256'])" "$PROBITY/$READER_DIR/source-lock.json")"
FIXTURE_SHA="$(shasum -a 256 "$VECTORS" | cut -d' ' -f1)"
echo "== probity stock driver: run_agentavow.py"
if [ "$FIXTURE_SHA" = "$LOCKED_SHA" ]; then
  if (cd "$PROBITY/$READER_DIR" && "$PYTHON" run_agentavow.py --fixture "$VECTORS" > "$OUT/probity-stock-report.json" 2> "$OUT/probity-stock-stderr.txt"); then
    STOCK="pass (vector file is byte-identical to Probity's locked fixture)"
  else
    STOCK="FAIL"; status=1
    cat "$OUT/probity-stock-stderr.txt" >&2
  fi
  [ -s "$OUT/probity-stock-stderr.txt" ] || rm -f "$OUT/probity-stock-stderr.txt"
else
  STOCK="skipped (vector file sha256 $FIXTURE_SHA differs from Probity's locked $LOCKED_SHA; their driver refuses by design)"
  rm -f "$OUT/probity-stock-report.json"
fi
echo "$STOCK"

echo "== probity reader against the current vector file: compat/probity_compat.py"
if "$PYTHON" "$HERE/probity_compat.py" --probity "$PROBITY" --vectors "$VECTORS" --out "$OUT/probity-report.json" > "$OUT/probity-stdout.txt" 2>&1; then
  READER="pass"
else
  READER="FAIL"; status=1
fi
cat "$OUT/probity-stdout.txt"
READER_LINE="$(tail -n 1 "$OUT/probity-stdout.txt")"

{
  echo "## Probity v1 compat"
  echo
  echo "| check | result |"
  echo "|---|---|"
  echo "| native \`node verify.mjs\` | $NATIVE |"
  echo "| Probity stock driver (\`run_agentavow.py\`) | $STOCK |"
  echo "| Probity reader on current vectors | $READER: $READER_LINE |"
  echo
  echo "Vector file sha256 \`$FIXTURE_SHA\`."
  echo
  echo "Probity reader pinned at [\`$REPO@${COMMIT:0:12}\`](https://github.com/$REPO/tree/$COMMIT/$READER_DIR)."
} > "$OUT/summary.md"

echo
echo "reports in $OUT"
exit $status
