import statistics
from pathlib import Path
from typing import Iterable

import yaml

from app.models.anomaly import Anomaly
from app.models.log_entry import LogEntry

RULES_PATH = Path(__file__).resolve().parents[2] / "rules.yaml"


def _load_rules() -> dict:
    with open(RULES_PATH, "r") as f:
        config = yaml.safe_load(f) or {}
    return {rule["name"]: rule for rule in config.get("rules", [])}


def _detect_high_request_volume(entries, rule):
    threshold = rule.get("zscore_threshold", 2.5)
    counts: dict[str, int] = {}
    for e in entries:
        if e.cip:
            counts[e.cip] = counts.get(e.cip, 0) + 1

    if len(counts) < 2:
        return []

    values = list(counts.values())
    mean = statistics.mean(values)
    stdev = statistics.pstdev(values) or 1e-9

    flagged_ips = {}
    for ip, count in counts.items():
        z = (count - mean) / stdev
        if z > threshold:
            flagged_ips[ip] = round(min(z / (threshold * 2), 1.0), 2)

    return [(e, flagged_ips[e.cip]) for e in entries if e.cip in flagged_ips]


def _detect_off_hours_risky_access(entries, rule):
    start = rule.get("business_hours_start", 8)
    end = rule.get("business_hours_end", 18)
    risky = {c.lower() for c in rule.get("risky_categories", [])}

    results = []
    for e in entries:
        if not e.timestamp or not e.urlcat:
            continue
        if e.urlcat.lower() not in risky:
            continue
        if e.timestamp.hour < start or e.timestamp.hour >= end:
            results.append((e, 0.7))
    return results


def _detect_threat_detected(entries, rule):
    results = []
    for e in entries:
        if e.threatname and e.threatname.strip().upper() not in ("CLEAN", "NONE", ""):
            results.append((e, 0.95))
    return results


def _detect_large_data_transfer(entries, rule):
    max_bytes = rule.get("max_response_bytes", 100 * 1024 * 1024)
    results = []
    for e in entries:
        if e.respsize and e.respsize > max_bytes:
            overflow_ratio = min(e.respsize / max_bytes, 5.0)
            results.append((e, round(min(0.5 + overflow_ratio / 10, 1.0), 2)))
    return results


RULE_DETECTORS = {
    "high_request_volume": _detect_high_request_volume,
    "off_hours_risky_access": _detect_off_hours_risky_access,
    "threat_detected": _detect_threat_detected,
    "large_data_transfer": _detect_large_data_transfer,
}


def detect_anomalies(session, entries: Iterable[LogEntry]) -> int:
    """Run all rules from rules.yaml against a batch of parsed LogEntry rows.

    Creates an Anomaly row (with MITRE ATT&CK tag, severity, and a confidence
    score) for every entry that trips a rule, commits them, and returns the
    number created. The LLM explainer is optional and not called here — see
    app.detection.llm_explainer.explain_anomaly for on-demand enrichment.
    """
    entries = list(entries)
    rules = _load_rules()
    created = 0

    for rule_name, detector in RULE_DETECTORS.items():
        rule = rules.get(rule_name)
        if not rule:
            continue

        for entry, confidence in detector(entries, rule):
            session.add(
                Anomaly(
                    log_entry_id=entry.id,
                    rule_name=rule_name,
                    mitre_tag=rule.get("mitre_tag"),
                    confidence_score=confidence,
                    explanation=rule.get("description", "").strip(),
                    severity=rule.get("severity", "medium"),
                    status="new",
                )
            )
            created += 1

    session.commit()
    return created
