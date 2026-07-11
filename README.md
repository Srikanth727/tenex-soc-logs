# Tenex SOC Log Analysis Platform

A full-stack tool for SOC analysts: upload Zscaler NSS Web Proxy logs, parse them into
structured records, run rule-based anomaly detection tagged with MITRE ATT&CK
techniques, and review the results on a dashboard.

## Overview

1. An analyst uploads a pipe-delimited Zscaler NSS Web Proxy log file through the
   dashboard.
2. The Flask backend parses each line, sanitizes untrusted fields (URLs, usernames,
   etc.) against stored XSS, and stores structured `log_entries` rows in Postgres.
3. Four YAML-configured detection rules run over the parsed entries and create
   `anomalies` rows, each tagged with a MITRE ATT&CK technique, a severity, and a
   confidence score.
4. The dashboard shows an hourly request-volume timeline and a table of detected
   anomalies for the selected log file.

## Architecture

```
frontend (Next.js 16 App Router, TypeScript, Tailwind) :3000
   │  fetch() with "Authorization: Bearer <token>"
   ▼
backend (Flask + SQLAlchemy, Blueprints)               :8080
   │  psycopg2
   ▼
PostgreSQL 16 (Docker only)                             :5432
```

- **Auth**: JWT (`PyJWT`) + `bcrypt` password hashing. No server-side sessions — the
  token is a Bearer header on every request. RBAC has two roles: `analyst` and
  `admin` (admins see every analyst's uploaded logs; analysts see only their own).
- **Parsing**: `backend/app/parsers/zscaler_nss.py` splits each line on `|` using a
  fixed field order (see below) and HTML-escapes every string field before it's
  stored, since log content (URLs, usernames, user agents) is untrusted input that
  gets rendered back in the dashboard.
- **Detection**: `backend/app/detection/rules.py` loads `backend/rules.yaml` and runs
  one Python function per rule over a batch of parsed entries after upload.
- **AI usage**: detection itself is deterministic rule logic, not an LLM — the model
  is only used, optionally, to turn a rule's static description into a plain-English
  explanation. See [AI usage](#ai-usage).

### Log field order

Zscaler NSS feeds use an admin-configurable custom format string, so there's no
single canonical field order — this project fixes one for its parser and sample
data:

```
timestamp|cip|login|url|respcode|action|urlcat|threatname|reqmethod|reqsize|respsize|malwarecat|riskscore
```

All files in `sample_logs/` and the parser in `backend/app/parsers/zscaler_nss.py`
use this exact order. If you generate your own Zscaler NSS feed, configure its custom
format string to match, or adjust `FIELD_ORDER` in the parser.

## Setup

### Prerequisites

- Conda (env name `tenex-soc`, Python 3.11 — see `environment.yml`)
- Node.js (system install) for the frontend
- Docker Desktop (Postgres runs in Docker only — never install Postgres natively
  alongside this project; see [Troubleshooting](#troubleshooting))

### Environment variables

Copy `.env.example` to `.env` and fill in real values (`.env` is gitignored):

| Variable | Used by | Purpose |
|---|---|---|
| `DB_USER`, `DB_PASSWORD`, `DB_NAME` | postgres, backend | Database credentials |
| `JWT_SECRET_KEY` | backend | Signs auth tokens — set a real secret outside dev |
| `LLM_MODE` | backend | `hosted` (Claude API) or `ollama` (local model) |
| `LLM_API_KEY` | backend | Anthropic API key, only used when `LLM_MODE=hosted` |
| `OLLAMA_BASE_URL` | backend | Only used when `LLM_MODE=ollama` |

### Option A — full stack via Docker Compose

```bash
docker-compose up --build
```

Frontend on `http://localhost:3000`, backend on `http://localhost:8080`, Postgres on
`5432`.

### Option B — local dev (recommended while iterating)

```bash
docker-compose up postgres -d          # Postgres 16 only

conda activate tenex-soc
cd backend && pip install -r requirements.txt   # first time / after dependency changes
flask run --port 8080                  # backend/.flaskenv sets FLASK_APP for you

cd frontend && npm install             # first time
npm run dev                            # frontend
```

Sanity check the backend: `curl http://localhost:8080/health` → `{"status":"ok"}`.

### Tests

```bash
cd backend
python -m pytest tests/ -v
```

## API Reference

All routes except `/health`, `/api/auth/signup`, and `/api/auth/login` require
`Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check, `{"status": "ok"}` |
| POST | `/api/auth/signup` | `{username, email, password, role?}` → `{token, user}` |
| POST | `/api/auth/login` | `{username, password}` → `{token, user}` |
| POST | `/api/logs` | Multipart `file` upload — parses, stores, and runs detection. Returns the `LogFile` summary plus `anomaly_count` |
| GET | `/api/logs` | List log files (own uploads for `analyst`, all uploads for `admin`) |
| GET | `/api/logs/:id/entries` | Paginated parsed entries (`?page=&per_page=`, max 1000/page) |
| GET | `/api/logs/:id/timeline` | Hourly request counts, `[{timestamp, count}, ...]` |
| GET | `/api/logs/:id/anomalies` | Detected anomalies for the log, joined with their source entry |
| GET | `/api/logs/:id/chains` | Anomalies correlated into attack chains by shared source IP/user (see [Attack chain reconstruction](#attack-chain-reconstruction)) |

Example:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","email":"a1@company.com","password":"testpass123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:8080/api/logs \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample_logs/suspicious.log"
```

## Anomaly Detection Rules

Configured in `backend/rules.yaml`, implemented in `backend/app/detection/rules.py`.
Each rule produces a confidence score (0–1) per flagged entry; the MITRE tag and
severity are fixed per rule.

### 1. High Request Volume — `T1110` Brute Force (severity: high)

Groups entries by source IP (`cip`) and flags any IP whose request count is a
statistical outlier (z-score > 2.5) relative to the other IPs in the same upload.
Needs a reasonably sized population of distinct IPs to be meaningful — with only a
handful of source IPs in a file, no single IP can mathematically clear the z-score
threshold regardless of its count. `sample_logs/suspicious.log` and `mixed.log`
include a wide pool of low-volume background IPs specifically so the brute-force
outlier (`10.1.1.50`) stands out.

### 2. Off-Hours Risky Access — `T1133` External Remote Services (severity: medium)

Flags requests to a risky `urlcat` (`Proxy/Anonymizer`, `Malicious Sites`,
`Peer to Peer`, `Hacking`, `Unknown`, `Remote Access Tools`, `Spyware Callback`)
outside business hours (before 8am or after 6pm, configurable in `rules.yaml`).
Example in `sample_logs/suspicious.log`: `admin@company.com` reaching
`Spyware Callback`-categorized `malware.com` at 3am.

### 3. Threat Detected — `T1189` Drive-by Compromise (severity: critical)

Flags any entry where `threatname` is present and isn't `CLEAN`/`NONE` — i.e.
Zscaler's own threat engine already flagged the request, regardless of whether the
proxy action was `Allowed` or `Blocked`. Example: `threatname=Trojan.Generic`,
`action=Blocked`, `malwarecat=Trojan`.

### 4. Large Data Transfer — `T1041` Exfiltration Over C2 Channel (severity: high)

Flags any entry with `respsize` over the configured threshold (100MB by default).

## Attack chain reconstruction

A flat table of dozens of anomalies hides the story a SOC analyst actually wants:
which events are part of the *same* incident. `GET /api/logs/:id/chains`
(`backend/app/detection/chains.py`) correlates a log file's anomalies into chains:

- **Grouped by source IP first (primary)** — any IP with 2+ anomalies becomes a chain.
- **Anomalies left over** from IPs that only had a single hit are then **grouped by
  user login (secondary)**, excluding placeholder/unauthenticated logins (`-`,
  empty) — this catches an attacker who rotates IPs but reuses the same compromised
  account, which IP-only grouping would miss. A given anomaly is never double-counted
  across both groupings.
- A group needs **2+ anomalies to count as a chain**; singletons stay out of this
  endpoint's response (they're still visible in the flat `/anomalies` list).
- For each chain, `chain_synthesis` is a 1-2 sentence narrative connecting the events
  into an attack-chain story, generated the same optional way as
  [anomaly explanations](#ai-usage) — Claude/Ollama per `LLM_MODE`, falling back to a
  templated summary (never blank) if the LLM is unavailable or misconfigured.
- The frontend's `ChainList` component renders chains above the flat `AnomalyTable`,
  color-coded by the chain's highest-severity anomaly, and hides itself entirely if
  the log has no 2+-anomaly groups.
- **Not cached or persisted** — chains (and their LLM synthesis) are recomputed on
  every request. Repeatedly viewing the same log re-invokes the LLM per chain; if
  that cost/latency matters for your use case, this is the first thing to add
  caching around.

## AI usage

- **Detection is deterministic, not AI.** All four rules above are plain Python/YAML
  logic — no model is in the loop for flagging anomalies. This keeps detection fast,
  free, reproducible, and auditable.
- **Explanations and chain narratives are optional and LLM-generated.**
  `backend/app/detection/llm_explainer.py` has two entry points, both toggled by the
  same `LLM_MODE`:
  - `explain_anomaly()` can turn a single anomaly's structured context into a 2–3
    sentence plain-English explanation (not currently wired into any route — see
    its docstring).
  - `synthesize_chain()` turns an ordered list of correlated anomalies (see
    [Attack chain reconstruction](#attack-chain-reconstruction)) into a 1-2 sentence
    attack-chain narrative — this one *is* wired in, via `GET /api/logs/:id/chains`.
  - `LLM_MODE=hosted` calls the Claude API (`anthropic` library) with `LLM_API_KEY`.
  - `LLM_MODE=ollama` calls a local Ollama server (`llama3.2` by default) at
    `OLLAMA_BASE_URL` — no API key or external network call required.
  - On any failure (missing/invalid key, network error, Ollama not running),
    `explain_anomaly` returns `None` (caller falls back to the rule's static YAML
    description) and `synthesize_chain` returns a templated summary instead (never
    blank) — the app is fully usable with the LLM turned off or misconfigured.

## RBAC

Two roles, enforced server-side via the `require_role()` decorator in
`backend/app/auth.py`:

- **analyst** (default on signup): can upload logs and see only their own uploads.
- **admin**: sees every analyst's uploaded logs (`GET /api/logs` returns all files,
  not just the caller's). There's no separate admin-only UI surface yet — the
  frontend Navbar and LogList just reflect the role and widen what's visible.

Role is chosen at signup (`role` field, defaults to `analyst`) — there's currently no
promotion flow; change a user's role directly in the `users` table if needed.

## Threat model & limitations

- **Trusted input boundary**: log file *content* (URLs, usernames, user agents) is
  treated as untrusted and HTML-escaped before storage, since it's rendered back into
  the dashboard — this prevents stored XSS from a malicious log line. The log
  *upload endpoint itself* is only reachable by an authenticated user, but any
  authenticated analyst can currently upload arbitrarily large files up to the 50MB
  cap; there's no per-user rate limiting or virus scanning of uploads.
- **Detection is rule-based, not ML-based.** It will not catch anomalies outside the
  four configured patterns, and thresholds (z-score 2.5, 100MB, business hours) are
  static and shared across all uploads — a real deployment should make these
  per-tenant configurable and probably add more rules over time.
- **The `high_request_volume` rule is population-sensitive.** Because it's a z-score
  across IPs *within a single uploaded file*, a small file with few distinct IPs can
  never trigger it, and the same absolute request count could flag or not flag
  depending on what else is in that file. It does not compare against historical
  baselines across uploads.
- **JWT has no revocation.** Tokens are valid until they expire (`JWT_EXP_MINUTES`,
  default 8 hours); logging out only clears the client's local copy. There's no
  server-side blocklist, so a stolen token remains valid until it naturally expires.
- **LLM explanations are best-effort and unverified.** If enabled, the explanation
  text is model output describing a rule's own structured findings — it should be
  read as a summary aid, not as an independent detection or a source of truth for
  the underlying facts.
- **No multi-tenancy isolation beyond role.** Any `admin` account can read every
  analyst's uploaded log content; there's no per-team or per-org scoping.

## Troubleshooting

### Postgres port 5432 conflict (Homebrew Postgres already running)

Symptom: `flask run` fails to boot, and the traceback (buried under Flask CLI's
generic "can't locate app" wrapper) ends in
`psycopg2.OperationalError: ... role "tenex_user" does not exist` even though the
Docker Postgres container is configured correctly.

Cause: a native Homebrew `postgresql@16` (or similar) service is already bound to
`localhost:5432`, so the backend's connection silently hits that instance instead of
the Docker container. This project runs Postgres **in Docker only** — do not run a
native Postgres alongside it.

Fix:

```bash
brew services stop postgresql@16
docker-compose up postgres -d
```

Verify only the Docker container owns the port:

```bash
lsof -nP -iTCP:5432 -sTCP:LISTEN   # should show `com.docke` / the Docker proxy, not `postgres`
```

### `flask run` says it can't find the app

`backend/.flaskenv` sets `FLASK_APP=app.main:create_app`, which Flask's CLI only
picks up automatically when your working directory is `backend/` (or when running
inside the Docker container, where the whole `backend/` tree is mounted at `/app`).
If you see a "can't locate a Flask application" error, first check the *actual* root
cause further down the traceback — `create_app()` calls `init_db()`, which connects
to Postgres immediately, so any DB connectivity problem (Postgres not running, wrong
credentials, the port conflict above) surfaces through this same generic error.

### `bcrypt`/`passlib` warnings

This project hashes passwords with the `bcrypt` package directly (not `passlib`),
specifically to avoid a known compatibility issue where `passlib==1.7.4` probes
`bcrypt.__about__.__version__`, an attribute removed in `bcrypt>=4.1`.

### Frontend build/lint errors after pulling changes

This repo is scaffolded on **Next.js 16**, not 14 — see `frontend/AGENTS.md`. App
Router conventions, and this project's ESLint config (`react-hooks/set-state-in-effect`
from the React Compiler lint rules), are stricter than in most Next.js tutorials.
Read `frontend/AGENTS.md` and the relevant guide under
`frontend/node_modules/next/dist/docs/` before assuming a "normal" Next.js fix
applies.

## Sample data

`sample_logs/` has three files for exercising the pipeline, in the exact field order
the parser expects:

| File | Lines | Contents |
|---|---|---|
| `normal.log` | 100 | Clean traffic only — `action=Allowed`, `threatname=CLEAN`, business hours Mon–Fri, 3 users/IPs. Uploading it should produce **zero** anomalies. |
| `suspicious.log` | 50 | One instance of each of the 4 anomaly types, plus filler traffic. |
| `mixed.log` | 200 | ~80% normal / ~20% anomalous, blended across a realistic 8-hour spread, all 4 anomaly types represented. |

Upload any of them from the dashboard's Upload widget, or via `curl` as shown in the
[API reference](#api-reference).
