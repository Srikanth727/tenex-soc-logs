from collections import defaultdict
from typing import Iterable, Optional

from app.detection.llm_explainer import synthesize_chain
from app.models.anomaly import Anomaly
from app.models.log_entry import LogEntry

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
PLACEHOLDER_LOGINS = {None, "", "-"}

AnomalyRow = tuple[Anomaly, LogEntry]


def _anomaly_payload(anomaly: Anomaly, entry: LogEntry) -> dict:
    return {
        "rule": anomaly.rule_name,
        "mitre_tag": anomaly.mitre_tag,
        "confidence": anomaly.confidence_score,
        "severity": anomaly.severity,
        # when the attacker was active (LogEntry.timestamp), not when detection ran
        "occurred_at": entry.timestamp.isoformat() if entry.timestamp else None,
        "explanation": anomaly.explanation,
    }


def _highest_severity(anomalies: list[Anomaly]) -> Optional[str]:
    ranked = [a.severity for a in anomalies if a.severity in SEVERITY_RANK]
    if not ranked:
        return None
    return max(ranked, key=lambda s: SEVERITY_RANK[s])


def _build_chain(entity_type: str, entity_value: str, rows: list[AnomalyRow]) -> dict:
    rows = sorted(rows, key=lambda row: (row[1].timestamp is None, row[1].timestamp, row[0].id))
    anomalies = [a for a, _ in rows]

    synthesis = synthesize_chain(
        entity_type=entity_type,
        entity_value=entity_value,
        events=[
            {
                "rule": a.rule_name,
                "mitre_tag": a.mitre_tag,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for a, e in rows
        ],
    )

    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "anomalies_count": len(anomalies),
        "anomalies": [_anomaly_payload(a, e) for a, e in rows],
        "highest_severity": _highest_severity(anomalies),
        "chain_synthesis": synthesis,
    }


def build_attack_chains(rows: Iterable[AnomalyRow]) -> list[dict]:
    """Group a log file's anomalies into attack chains that tell a story a SOC
    analyst would recognize, instead of a flat list of isolated rows.

    Grouping is source IP first (primary): any IP with 2+ anomalies becomes an
    "ip" chain. Anomalies left over from IPs that only had a single hit are
    then grouped by user login (secondary, excluding placeholder/unauthenticated
    logins) — this catches an attacker who rotates IPs but reuses the same
    compromised account, which IP-only grouping would miss. A group of fewer
    than 2 anomalies isn't a "chain" — it stays out of this response and is
    still visible in the flat anomalies list.
    """
    rows = list(rows)

    by_ip: dict[str, list[AnomalyRow]] = defaultdict(list)
    for row in rows:
        _, entry = row
        if entry.cip:
            by_ip[entry.cip].append(row)

    chains = []
    leftover: list[AnomalyRow] = []

    for ip, ip_rows in by_ip.items():
        if len(ip_rows) >= 2:
            chains.append(_build_chain("ip", ip, ip_rows))
        else:
            leftover.extend(ip_rows)

    by_user: dict[str, list[AnomalyRow]] = defaultdict(list)
    for row in leftover:
        _, entry = row
        if entry.login and entry.login not in PLACEHOLDER_LOGINS:
            by_user[entry.login].append(row)

    for user, user_rows in by_user.items():
        if len(user_rows) >= 2:
            chains.append(_build_chain("user", user, user_rows))

    chains.sort(key=lambda c: c["anomalies_count"], reverse=True)
    return chains
