from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from app.detection import chains as chains_module
from app.detection.chains import build_attack_chains


def make_row(id, rule_name, mitre_tag, severity, cip, login, ts):
    anomaly = SimpleNamespace(
        id=id,
        rule_name=rule_name,
        mitre_tag=mitre_tag,
        confidence_score=0.9,
        severity=severity,
        explanation=f"{rule_name} description",
    )
    entry = SimpleNamespace(cip=cip, login=login, timestamp=ts)
    return anomaly, entry


def t(minute):
    return datetime(2026, 7, 10, 9, minute, 0)


def test_ip_with_two_plus_anomalies_forms_a_chain():
    rows = [
        make_row(1, "high_request_volume", "T1110", "high", "10.1.1.50", "-", t(0)),
        make_row(2, "large_data_transfer", "T1041", "high", "10.1.1.50", "-", t(5)),
    ]

    with patch.object(chains_module, "synthesize_chain", return_value="fake synthesis"):
        result = build_attack_chains(rows)

    assert len(result) == 1
    chain = result[0]
    assert chain["entity_type"] == "ip"
    assert chain["entity_value"] == "10.1.1.50"
    assert chain["anomalies_count"] == 2
    assert chain["chain_synthesis"] == "fake synthesis"
    assert chain["highest_severity"] == "high"
    # chronological order preserved
    assert [a["rule"] for a in chain["anomalies"]] == ["high_request_volume", "large_data_transfer"]


def test_single_anomaly_ip_does_not_form_a_chain():
    rows = [make_row(1, "threat_detected", "T1189", "critical", "10.1.1.9", "bob@company.com", t(0))]

    with patch.object(chains_module, "synthesize_chain", return_value="fake"):
        result = build_attack_chains(rows)

    assert result == []


def test_falls_back_to_user_grouping_when_ip_alone_is_a_singleton():
    # Same user hitting from 3 different IPs -- IP grouping alone would never
    # catch this (each IP only appears once), but user grouping should.
    rows = [
        make_row(1, "off_hours_risky_access", "T1133", "medium", "10.1.1.1", "admin@company.com", t(0)),
        make_row(2, "off_hours_risky_access", "T1133", "medium", "10.1.1.2", "admin@company.com", t(5)),
        make_row(3, "off_hours_risky_access", "T1133", "medium", "10.1.1.3", "admin@company.com", t(10)),
    ]

    with patch.object(chains_module, "synthesize_chain", return_value="fake"):
        result = build_attack_chains(rows)

    assert len(result) == 1
    assert result[0]["entity_type"] == "user"
    assert result[0]["entity_value"] == "admin@company.com"
    assert result[0]["anomalies_count"] == 3


def test_placeholder_logins_are_excluded_from_user_grouping():
    # Two different IPs, both hit once, both with a placeholder login -- should
    # NOT be merged into a fake "chain" for login "-".
    rows = [
        make_row(1, "threat_detected", "T1189", "critical", "10.1.1.1", "-", t(0)),
        make_row(2, "threat_detected", "T1189", "critical", "10.1.1.2", "-", t(5)),
    ]

    with patch.object(chains_module, "synthesize_chain", return_value="fake"):
        result = build_attack_chains(rows)

    assert result == []


def test_multiple_chains_sorted_by_anomaly_count_descending():
    rows = [
        make_row(1, "large_data_transfer", "T1041", "high", "10.1.1.65", "carol@company.com", t(0)),
        make_row(2, "large_data_transfer", "T1041", "high", "10.1.1.65", "carol@company.com", t(1)),
        make_row(3, "high_request_volume", "T1110", "high", "10.1.1.50", "-", t(0)),
        make_row(4, "high_request_volume", "T1110", "high", "10.1.1.50", "-", t(1)),
        make_row(5, "high_request_volume", "T1110", "high", "10.1.1.50", "-", t(2)),
    ]

    with patch.object(chains_module, "synthesize_chain", return_value="fake"):
        result = build_attack_chains(rows)

    assert [c["anomalies_count"] for c in result] == [3, 2]
    assert result[0]["entity_value"] == "10.1.1.50"
