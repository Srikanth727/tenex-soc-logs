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


def _serialize_log_file(lf: LogFile) -> dict:
    return {
        "id": lf.id,
        "filename": lf.filename,
        "status": lf.status,
        "uploaded_at": lf.uploaded_at.isoformat() if lf.uploaded_at else None,
        "line_count": lf.line_count,
    }


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


def _get_owned_log_file(db, log_id: int):
    log_file = db.query(LogFile).filter(LogFile.id == log_id).first()
    if not log_file:
        return None
    if g.user_role != "admin" and log_file.user_id != g.user_id:
        return None
    return log_file


@documents_bp.post("/logs")
@require_role()
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "no file provided (expected multipart field 'file')"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "empty filename"}), 400

    raw_bytes = file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "file too large (max 50MB)"}), 413

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
    db.flush()

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


@documents_bp.get("/logs")
@require_role()
def list_logs():
    db = SessionLocal()
    query = db.query(LogFile)
    if g.user_role != "admin":
        query = query.filter(LogFile.user_id == g.user_id)
    log_files = query.order_by(LogFile.uploaded_at.desc()).all()
    return jsonify([_serialize_log_file(lf) for lf in log_files])


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


@documents_bp.get("/logs/<int:log_id>/timeline")
@require_role()
def get_timeline(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    bucket = func.date_trunc("hour", LogEntry.timestamp)
    rows = (
        db.query(bucket.label("bucket"), func.count(LogEntry.id))
        .filter(LogEntry.log_file_id == log_id)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )

    return jsonify([{"timestamp": b.isoformat() if b else None, "count": c} for b, c in rows])


@documents_bp.get("/logs/<int:log_id>/anomalies")
@require_role()
def get_anomalies(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    rows = (
        db.query(Anomaly, LogEntry)
        .join(LogEntry, Anomaly.log_entry_id == LogEntry.id)
        .filter(LogEntry.log_file_id == log_id)
        .order_by(Anomaly.confidence_score.desc())
        .all()
    )

    return jsonify(
        [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "mitre_tag": a.mitre_tag,
                "confidence_score": a.confidence_score,
                "explanation": a.explanation,
                "severity": a.severity,
                "status": a.status,
                "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                "log_entry": _serialize_entry(e),
            }
            for a, e in rows
        ]
    )


@documents_bp.get("/logs/<int:log_id>/chains")
@require_role()
def get_chains(log_id):
    db = SessionLocal()
    log_file = _get_owned_log_file(db, log_id)
    if not log_file:
        return jsonify({"error": "log file not found"}), 404

    rows = (
        db.query(Anomaly, LogEntry)
        .join(LogEntry, Anomaly.log_entry_id == LogEntry.id)
        .filter(LogEntry.log_file_id == log_id)
        .all()
    )

    return jsonify(build_attack_chains(rows))
