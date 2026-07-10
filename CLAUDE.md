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
- Frontend: Next.js 14 + TypeScript + Tailwind CSS → port 3000
- Backend: Python Flask + SQLAlchemy → port 8080
- Database: PostgreSQL 16 → port 5432
- Auth: JWT + bcrypt, RBAC (analyst/admin)
- Log format: Zscaler NSS Web Proxy logs (pipe-delimited)

## Database Tables
- users: id, username, email, password_hash, role, created_at
- log_files: id, user_id, filename, status, uploaded_at, line_count
- log_entries: id, log_file_id, timestamp, cip, login, url, action, urlcat, threatname, respcode, reqmethod, reqsize, respsize, malwarecat, riskscore, raw_line
- anomalies: id, log_entry_id, rule_name, mitre_tag, confidence_score, explanation, severity, detected_at

## Anomaly Detection Rules
1. high_request_volume — z-score > 2.5 per IP → T1110 Brute Force
2. off_hours_risky_access — risky urlcat outside 8am-6pm → T1133 External Remote Services
3. threat_detected — threatname != CLEAN → T1566 Phishing
4. large_data_transfer — respsize > 100MB → T1041 Exfiltration

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
- LLM explainer is optional
- JWT in localStorage under "token"
- CORS: localhost:3000, localhost:5173
- All models in separate files
- Use Flask Blueprints for routes
