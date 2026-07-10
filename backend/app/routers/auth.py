from flask import Blueprint, jsonify, request

from app.auth import create_token, hash_password, verify_password
from app.database import SessionLocal
from app.models.user import User

auth_bp = Blueprint("auth", __name__)

VALID_ROLES = {"analyst", "admin"}


def _user_payload(user: User) -> dict:
    return {"id": user.id, "username": user.username, "email": user.email, "role": user.role}


@auth_bp.post("/signup")
def signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role", "analyst")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {sorted(VALID_ROLES)}"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    db = SessionLocal()
    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        return jsonify({"error": "username or email already registered"}), 409

    user = User(username=username, email=email, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()

    token = create_token(user.id, user.role)
    return jsonify({"token": token, "user": _user_payload(user)}), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return jsonify({"error": "invalid username or password"}), 401

    token = create_token(user.id, user.role)
    return jsonify({"token": token, "user": _user_payload(user)}), 200
