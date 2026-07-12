# Log file lifecycle: upload a Zscaler NSS log, parse + persist its entries,
# run anomaly detection, and expose the results (paginated entries, hourly
# timeline, flat anomaly list, and IP/login-grouped attack chains).

from flask import Blueprint, g, jsonify, request
from sqlalchemy import func

from app.auth import require_role
from app.database import SessionLocal
from app.detection.chains import build_attack_chains
from app.detection.rules import detect_anomalies
from app.models.anomaly import Anomaly
from app.models.log_entry import LogEntry
from app.models.log_file import LogFile
from app.parsers.zscaler_nss import parse_zscaler_file

documents_bp = Blueprint("documents", __name__)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
VALID_ANOMALY_STATUSES = {"new", "reviewed", "dismissed"}


# Shape a LogFile row into the JSON returned by the upload/list-logs endpoints.
def _serialize_log_file(lf: LogFile) -> dict:
    return {
        "id": lf.id,
        "filename": lf.filename,
        "status": lf.status,
        "uploaded_at": lf.uploaded_at.isoformat() if lf.uploaded_at else None,
        "line_count": lf.line_count,
    }


# Shape a LogEntry row into the JSON returned by the entries/anomalies/chains endpoints.
def _serialize_entry(e: LogEntry) -> dict:
    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "cip": e.cip,
        "login": e.login,
        "url": e.url,
        "action": e.action,
        "urlcat": e.urlcat,
        "threatname": e.threatname,
        "respcode": e.respcode,
        "reqmethod": e.reqmethod,
        "reqsize": e.reqsize,
        "respsize": e.respsize,
        "malwarecat": e.malwarecat,
        "riskscore": e.riskscore,
    }


# Shape an (Anomaly, LogEntry) pair into the JSON used by the anomalies list and the status-update endpoint.
def _serialize_anomaly(a: Anomaly, e: LogEntry) -> dict:
    return {
        "id": a.id,
        "rule_name": a.rule_name,
        "mitre_tag": a.mitre_tag,
        "confidence_score": a.confidence_score,
        "explanation": a.explanation,
        "severity": a.severity,
        "status": a.status,
        "occurred_at": e.timestamp.isoformat() if e.timestamp else None,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        "log_entry": _serialize_entry(e),
    }


# Parse an optional comma-separated query param into a list of trimmed values,
# or None if absent/blank (meaning "no filter" to the caller).
def _parse_csv_param(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    values = [v.strip() for v in raw.split(",") if v.strip()]
    return values or None


# Fetch a log file by id, scoped to the requesting user unless they're an admin.
def _get_owned_log_file(db, log_id: int):
    # Enforced here (not just at upload time) so analysts can't read another
    # user's log file by guessing/incrementing the id; admins bypass the check.
    log_file = db.query(LogFile).filter(LogFile.id == log_id).first()
    if not log_file:
        return None
    if g.user_role != "admin" and log_file.user_id != g.user_id:
        return None
    return log_file


# Accept a multipart log file upload, parse it, store the entries, and run
# anomaly detection against them.
@documents_bp.post("/logs")
@require_role()
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "no file provided (expected multipart field 'file')"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "empty filename"}), 400

    # Read one byte past the cap so an oversized file can be rejected without
    # buffering an unbounded upload fully into memory first.
    raw_bytes = file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "file too large (max 50MB)"}), 413

    # Zscaler feeds occasionally contain stray non-UTF-8 bytes; replace rather
    # than reject so one bad byte doesn't fail an otherwise-valid upload.
    text = raw_bytes.decode("utf-8", errors="replace")
    parsed_entries = parse_zscaler_file(text)
    if not parsed_entries:
        return jsonify({"error": "no valid log lines found"}), 400

    db = SessionLocal()
    log_file = LogFile(
        user_id=g.user_id,
        filename=file.filename,
        status="processing",
        line_count=len(parsed_entries),
    )
    db.add(log_file)
    db.flush()

    entries = [LogEntry(log_file_id=log_file.id, **fields) for fields in parsed_entries]
    db.add_all(entries)
    db.flush()  # assigns entry ids so detect_anomalies can attach anomalies via log_entry_id

    anomaly_count = detect_anomalies(db, entries)

    log_file.status = "complete"
    db.commit()

    return (
        jsonify(
            {
                **_serialize_log_file(log_file),
                "anomaly_count": anomaly_count,
            }
        ),
        201,
    )


# List uploaded log files: own uploads for analysts, all uploads for admins.
@documents_bp.get("/logs")
@require_role()
def list_logs():
    db = SessionLocal()
    query = db.query(LogFile)
    if g.user_role != "admin":
        query = query.filter(LogFile.user_id == g.user_id)
    log_files = query.order_by(LogFile.uploaded_at.desc()).all()
    return jsonify([_serialize_log_file(lf) for lf in log_files])


# Return a paginated page of parsed log entries for one log file.
@documents_bp.get("/logs/<int:log_id>/entries")
@require_role()
def get_entries(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 100)), 1), 1000)

    entries = (
        db.query(LogEntry)
        .filter(LogEntry.log_file_id == log_id)
        .order_by(LogEntry.timestamp.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return jsonify(
        {
            "page": page,
            "per_page": per_page,
            "entries": [_serialize_entry(e) for e in entries],
        }
    )


# Return entry counts bucketed by hour, for the dashboard's timeline chart.
@documents_bp.get("/logs/<int:log_id>/timeline")
@require_role()
def get_timeline(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    bucket = func.date_trunc("hour", LogEntry.timestamp)  # hourly granularity for the dashboard timeline chart
    rows = (
        db.query(bucket.label("bucket"), func.count(LogEntry.id))  # pylint: disable=not-callable
        .filter(LogEntry.log_file_id == log_id)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )

    return jsonify([{"timestamp": b.isoformat() if b else None, "count": c} for b, c in rows])


# Return the flat list of detected anomalies for a log file, newest activity
# first by default. Optional ?severity=critical,high and ?status=new,reviewed
# query params (comma-separated) narrow the results.
@documents_bp.get("/logs/<int:log_id>/anomalies")
@require_role()
def get_anomalies(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    severity_filter = _parse_csv_param(request.args.get("severity"))
    status_filter = _parse_csv_param(request.args.get("status"))

    query = (
        db.query(Anomaly, LogEntry)
        .join(LogEntry, Anomaly.log_entry_id == LogEntry.id)
        .filter(LogEntry.log_file_id == log_id)
    )
    if severity_filter:
        query = query.filter(Anomaly.severity.in_(severity_filter))
    if status_filter:
        query = query.filter(Anomaly.status.in_(status_filter))

    # occurred_at (when the attacker was active) desc by default; confidence as
    # a tie-breaker for anomalies that occurred at the same moment.
    rows = query.order_by(LogEntry.timestamp.desc(), Anomaly.confidence_score.desc()).all()

    return jsonify([_serialize_anomaly(a, e) for a, e in rows])


# Group this log file's anomalies into attack chains (by source IP, then by
# user login for leftovers) and synthesize a narrative per chain.
@documents_bp.get("/logs/<int:log_id>/chains")
@require_role()
def get_chains(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    # Unordered here deliberately: build_attack_chains groups by IP/login and
    # sorts each resulting chain chronologically itself.
    rows = (
        db.query(Anomaly, LogEntry)
        .join(LogEntry, Anomaly.log_entry_id == LogEntry.id)
        .filter(LogEntry.log_file_id == log_id)
        .all()
    )

    return jsonify(build_attack_chains(rows))


# Update an anomaly's triage status (new -> reviewed/dismissed) after analyst review.
@documents_bp.patch("/anomalies/<int:anomaly_id>")
@require_role()
def update_anomaly_status(anomaly_id):
    db = SessionLocal()
    row = (
        db.query(Anomaly, LogEntry, LogFile)
        .join(LogEntry, Anomaly.log_entry_id == LogEntry.id)
        .join(LogFile, LogEntry.log_file_id == LogFile.id)
        .filter(Anomaly.id == anomaly_id)
        .first()
    )
    if not row:
        return jsonify({"error": "anomaly not found"}), 404

    anomaly, entry, log_file = row
    # Same ownership rule as _get_owned_log_file: 404 rather than 403 so a
    # guessed id doesn't confirm the anomaly exists for another user.
    if g.user_role != "admin" and log_file.user_id != g.user_id:
        return jsonify({"error": "anomaly not found"}), 404

    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in VALID_ANOMALY_STATUSES:
        return jsonify({"error": f"status must be one of {sorted(VALID_ANOMALY_STATUSES)}"}), 400

    anomaly.status = status
    db.commit()

    return jsonify(_serialize_anomaly(anomaly, entry))
