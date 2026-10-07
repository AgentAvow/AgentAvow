"""SYNTHETIC recall fixture (same family as loader.py): decode and exec on different
lines, which the one-line pattern cannot see."""
import base64

_blob = "cHJpbnQoImZpeHR1cmUiKQ=="
_payload = base64.b64decode(_blob)
_x = 1
exec(_payload)
