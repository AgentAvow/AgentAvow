"""SYNTHETIC recall fixture (mirrors OSV MAL-2024-5748, pyobfgood): a base64-encoded
payload is decoded and exec'd. The payload below decodes to `print("fixture")`."""
import base64

exec(base64.b64decode("cHJpbnQoImZpeHR1cmUiKQ=="))
