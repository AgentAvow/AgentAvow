"""RFC 8785 anchors for ``src.signing.canonicalize_jcs_strict``.

Regression for the divergence found 2026-09-21: the hand-rolled serializer
expanded large floats to integer digits and sorted object keys by code point
instead of UTF-16 code unit. Expected bytes below come from RFC 8785 itself
(§3.2.3 sorting example, Appendix B number samples), not from our output.
"""
from __future__ import annotations

import pytest

from src.signing import canonicalize_jcs_strict


def test_keys_sort_by_utf16_code_unit_not_code_point():
    # RFC 8785 §3.2.3. U+1F600 (surrogates D83D DE00) sorts BEFORE U+FB33 by
    # UTF-16 code unit, but after it by code point.
    payload = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face",'
        '"דּ":"Hebrew Letter Dalet With Dagesh"}'
    ).encode()
    assert canonicalize_jcs_strict(payload) == expected


@pytest.mark.parametrize("value,expected", [
    (1e30, b"1e+30"),
    (1e21, b"1e+21"),
    (1e-7, b"1e-7"),
    (1e-27, b"1e-27"),
    (0.000001, b"0.000001"),
    (0.002, b"0.002"),
    (4.5, b"4.5"),
    (333333333.33333329, b"333333333.3333333"),
    (1.0, b"1"),
    (-0.0, b"0"),
    (9007199254740991, b"9007199254740991"),
])
def test_numbers_serialize_per_ecma262(value, expected):
    assert canonicalize_jcs_strict(value) == expected


def test_rfc8785_structure_example():
    # RFC 8785 §3.2.2: literals, nesting, and string escapes.
    payload = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "€$\u000f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    ).encode()
    assert canonicalize_jcs_strict(payload) == expected


@pytest.mark.parametrize("bad", [
    float("nan"),
    float("inf"),
    2**53,            # outside the IEEE 754 exact-integer range
    {1: "int key"},
])
def test_unrepresentable_input_is_refused(bad):
    with pytest.raises(ValueError):
        canonicalize_jcs_strict(bad)
