from flask import Flask, jsonify
from flask_cors import CORS

from app.config import Config
from app.database import SessionLocal, init_db
from app.routers.auth import auth_bp
from app.routers.documents import documents_bp


def create_app():
    app = Flask(__name__)
    CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

    init_db()

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(documents_bp, url_prefix="/api")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.teardown_appcontext
    def remove_session(exception=None):
        SessionLocal.remove()

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
