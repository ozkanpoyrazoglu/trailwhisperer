"""Unit tests for `_parse_summary_json` / `_salvage_summary_json`.

Pure-parse tests — no AWS. A summarization reply that hit the model's max-tokens
ceiling used to leak into the UI as raw unrendered JSON; these lock in the
salvage path (complete flags kept, the partial one dropped) plus the happy paths.
"""

import os

os.environ.setdefault("AWS_REGION", "us-east-1")

import main  # noqa: E402

# Real-world shape: the reply was cut off mid-way through the third flag.
TRUNCATED = (
    '{\n  "summary": "06:31:13 - 07:33:45 window: 100 ACCEPTed flows to '
    '172.31.13.128. Top source 98.87.175.76 hit dstport 40742 repeatedly.",\n'
    '  "flags": [\n'
    '    "98.87.175.76 -> 172.31.13.128:40742 (TCP/443) repeats every minute; '
    'possible keepalive/beacon.",\n'
    '    "66.132.186.62 -> 172.31.13.128:1194 (UDP) single packet at 07:09:33; '
    'port 1194 is OpenVPN.",\n'
    '    "44.213.'
)

_CUT_NOTE = "cut short"


def test_truncated_reply_is_salvaged_not_dumped_raw():
    data = main._parse_summary_json(TRUNCATED)
    assert isinstance(data, dict)
    assert data["summary"].startswith("06:31:13")
    assert data["summary"].endswith("repeatedly.")
    # Two complete flags survive, the partial "44.213. is dropped.
    assert len(data["flags"]) == 3
    assert "98.87.175.76" in data["flags"][0]
    assert "OpenVPN" in data["flags"][1]
    assert _CUT_NOTE in data["flags"][2]
    assert not any("44.213." in f for f in data["flags"])


def test_truncated_mid_summary_keeps_readable_prefix():
    data = main._parse_summary_json('{"summary": "This narrative was cut in ha')
    assert data["summary"].startswith("This narrative was cut in ha")
    assert data["summary"].endswith("[…]")
    assert _CUT_NOTE in data["flags"][0]


def test_clean_json_unchanged():
    assert main._parse_summary_json('{"summary": "ok", "flags": ["a", "b"]}') == {
        "summary": "ok", "flags": ["a", "b"]
    }


def test_markdown_fenced_json():
    assert main._parse_summary_json('```json\n{"summary": "ok", "flags": []}\n```') == {
        "summary": "ok", "flags": []
    }


def test_escapes_and_braces_inside_strings():
    data = main._parse_summary_json(
        '{"summary": "a quote \\" and a brace } inside", "flags": ["esc \\" ok"]}'
    )
    assert data["flags"] == ['esc " ok']


def test_truncated_json_with_escaped_quote_in_flag():
    # Salvage must use the JSON string scanner, not a naive quote search.
    data = main._parse_summary_json(
        '{"summary": "s", "flags": ["role \\"admin\\" assumed", "partial'
    )
    assert data["flags"][0] == 'role "admin" assumed'
    assert _CUT_NOTE in data["flags"][1]


def test_plain_prose_returns_none_so_caller_falls_back_to_raw_text():
    assert main._parse_summary_json("Just a plain-text answer, no JSON.") is None
