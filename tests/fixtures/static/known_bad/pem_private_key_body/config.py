"""SYNTHETIC recall fixture (leaked-credential class; no OSV MAL id - secret-scanning
GHSA family): a PEM private-key BODY committed in source. The base64 below is random
filler, NOT a real key."""

SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsynthetic0fixture1not2a3real4key5body6line7aaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc==
-----END RSA PRIVATE KEY-----"""
