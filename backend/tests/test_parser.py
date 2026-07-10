from app.parsers.zscaler_nss import parse_zscaler_file, parse_zscaler_line

VALID_LINE = (
    "Fri Jul 10 09:15:00 2026|192.168.1.100|alice@company.com|"
    "https://github.com/torvalds/linux|200|Allowed|General Surfing|CLEAN|GET|512|20480|None|10"
)


def test_valid_line_parses_all_fields():
    entry = parse_zscaler_line(VALID_LINE)

    assert entry is not None
    assert entry["timestamp"].isoformat() == "2026-07-10T09:15:00"
    assert entry["cip"] == "192.168.1.100"
    assert entry["login"] == "alice@company.com"
    assert entry["url"] == "https://github.com/torvalds/linux"
    assert entry["respcode"] == "200"
    assert entry["action"] == "Allowed"
    assert entry["urlcat"] == "General Surfing"
    assert entry["threatname"] == "CLEAN"
    assert entry["reqmethod"] == "GET"
    assert entry["reqsize"] == 512
    assert entry["respsize"] == 20480
    assert entry["malwarecat"] == "None"
    assert entry["riskscore"] == 10
    assert entry["raw_line"] == VALID_LINE


def test_malformed_timestamp_does_not_raise():
    line = "not-a-real-timestamp|10.0.0.1|bob|http://example.com|200|Allowed|General Surfing|CLEAN|GET|1|1|None|1"

    entry = parse_zscaler_line(line)

    assert entry is not None
    assert entry["timestamp"] is None
    # Every other field still parses positionally even though the timestamp failed.
    assert entry["cip"] == "10.0.0.1"
    assert entry["url"] == "http://example.com"


def test_missing_trailing_fields_default_to_none():
    # Only the first 5 fields present (timestamp, cip, login, url, respcode) —
    # everything after that is missing from the line entirely.
    line = "Fri Jul 10 09:15:00 2026|192.168.1.100|alice@company.com|https://example.com|200"

    entry = parse_zscaler_line(line)

    assert entry is not None
    assert entry["respcode"] == "200"
    assert entry["action"] is None
    assert entry["urlcat"] is None
    assert entry["threatname"] is None
    assert entry["reqmethod"] is None
    assert entry["reqsize"] is None
    assert entry["respsize"] is None
    assert entry["malwarecat"] is None
    assert entry["riskscore"] is None


def test_blank_and_comment_lines_are_skipped():
    assert parse_zscaler_line("") is None
    assert parse_zscaler_line("   ") is None
    assert parse_zscaler_line("# this is a comment") is None


def test_untrusted_content_is_html_escaped():
    line = (
        'Fri Jul 10 09:15:00 2026|10.0.0.1|<script>alert(1)</script>|'
        'http://example.com/?q=<img src=x onerror=alert(1)>|200|Allowed|General Surfing|CLEAN|GET|1|1|None|1'
    )

    entry = parse_zscaler_line(line)

    assert "<script>" not in entry["login"]
    assert "&lt;script&gt;" in entry["login"]
    assert "<img" not in entry["url"]


def test_parse_file_skips_blank_lines_and_counts_entries():
    content = f"{VALID_LINE}\n\n{VALID_LINE}\n# comment\n{VALID_LINE}\n"

    entries = parse_zscaler_file(content)

    assert len(entries) == 3
