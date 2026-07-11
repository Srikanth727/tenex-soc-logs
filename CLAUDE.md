# Tenex SOC Log Analysis Platform

## Project Context
Full-stack cybersecurity app for SOC analysts. Upload Zscaler NSS Web Proxy logs → parse → detect anomalies → display SOC dashboard.

## Environment
- Python: Conda env `tenex-soc` (Python 3.11)
- Node: System Node (frontend)
- Database: PostgreSQL 16 in Docker only
- Local dev: Flask + Next.js run directly
- Full stack: docker-compose up --build

## Stack
- Frontend: Next.js 16 (App Router) + TypeScript + Tailwind CSS → port 3000. This
  version has breaking changes vs. typical training data — read `frontend/AGENTS.md`
  and the relevant guide under `frontend/node_modules/next/dist/docs/` before
  assuming a "normal" Next.js pattern applies (e.g. `src/` layout is required,
  `params`/`searchParams` are Promises, stricter React Compiler ESLint rules).
- Backend: Python Flask + SQLAlchemy → port 8080
- Database: PostgreSQL 16 → port 5432
- Auth: JWT + bcrypt, RBAC (analyst/admin)
- Log format: Zscaler NSS Web Proxy logs (pipe-delimited), field order fixed in
  `backend/app/parsers/zscaler_nss.py`'s `FIELD_ORDER` — Zscaler's real NSS feeds
  are admin-configurable, so match samples/tests to that constant, not the other
  way around.

## Database Tables
- users: id, username, email, password_hash, role, created_at
- log_files: id, user_id, filename, status, uploaded_at, line_count
- log_entries: id, log_file_id, timestamp, cip, login, url, action, urlcat, threatname, respcode, reqmethod, reqsize, respsize, malwarecat, riskscore, raw_line
- anomalies: id, log_entry_id, rule_name, mitre_tag, confidence_score, explanation, severity, detected_at

## Anomaly Detection Rules
1. high_request_volume — z-score > 2.5 per IP → T1110 Brute Force. Needs a wide
   enough population of distinct IPs in the file to be mathematically achievable —
   with only ~3-5 distinct IPs the max possible z-score is capped around 2.0,
   regardless of the outlier's count.
2. off_hours_risky_access — risky urlcat outside 8am-6pm → T1133 External Remote Services
3. threat_detected — threatname != CLEAN → T1189 Drive-by Compromise
4. large_data_transfer — respsize > 100MB → T1041 Exfiltration

Config lives in `backend/rules.yaml`; logic in `backend/app/detection/rules.py`.
Attack-chain correlation (`GET /api/logs/:id/chains`, `backend/app/detection/chains.py`)
groups anomalies from these rules by source IP first, then user login for leftovers —
see PLAN.md Phase 5 for the design rationale.

## Dev Commands
```bash
docker-compose up postgres -d
conda activate tenex-soc
cd backend && flask run --port 8080
cd frontend && npm run dev
docker-compose up --build
```

## Code Rules
- Use psycopg2-binary (not psycopg2)
- LLM explainer is optional — `explain_anomaly()`/`synthesize_chain()` in
  `backend/app/detection/llm_explainer.py` must never leave the app unusable if
  the LLM is off/unreachable (return `None` or a templated fallback, not an error)
- JWT in localStorage under "token"
- CORS: localhost:3000, localhost:5173
- All models in separate files
- Use Flask Blueprints for routes
- Hash passwords with `bcrypt` directly, not `passlib` — `passlib==1.7.4` probes
  `bcrypt.__about__.__version__`, an attribute removed in `bcrypt>=4.1`

## Known Gotchas
- **Postgres must run in Docker only.** A native Homebrew (or other) Postgres on
  port 5432 will silently steal connections meant for the Docker container. Symptom:
  `flask run` fails with a generic Flask-CLI "can't locate app" error whose *real*
  cause is buried further down the traceback (`create_app()` calls `init_db()`,
  which connects to Postgres immediately). Fix: `brew services stop postgresql@16`
  (or whichever service), then `docker-compose up postgres -d`.
- **Frontend Docker container needs `--build` after any frontend code change.**
  `docker-compose.yml`'s frontend service has no bind mount (removed — it was
  shadowing the production `.next` build and crash-looping the container) and runs
  a static build baked in at `docker build` time, not a live dev server.
- **Backend Docker container needs a restart (not necessarily rebuild) after code
  or `.env` changes.** It bind-mounts source, so new files are already there, but
  `flask run` has no reloader enabled, and a running container keeps the env vars
  it was created with — `docker-compose up -d backend` to recreate/pick up changes.
- **`LLM_MODE=hosted` needs a genuinely valid `LLM_API_KEY`.** A bad/expired key
  fails as a silent `None`/fallback in the app (by design — the LLM is optional),
  not a visible error. If chain syntheses or explanations look templated/generic,
  check `Config.LLM_API_KEY` actually authenticates before assuming a code bug.
- Sample/test data must be validated against the *running* parser and detection
  code, not just written against the spec — every real bug found in this project
  (field-order mismatches, the z-score population-size issue, duplicate React keys)
  was caught this way, not by reading the code.
